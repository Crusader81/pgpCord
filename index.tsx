/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { ChatBarButton, ChatBarButtonFactory } from "@api/ChatButtons";
import { ApplicationCommandInputType } from "@api/Commands";
import * as DataStore from "@api/DataStore";
import { MessageEditListener, MessageSendListener } from "@api/MessageEvents";
import { updateMessage } from "@api/MessageUpdater";
import { definePluginSettings, Settings } from "@api/Settings";
import ErrorBoundary from "@components/ErrorBoundary";
import { Button, Paragraph } from "@components/index";
import { fetchUserProfile, sendMessage } from "@utils/discord";
import { useAwaiter, useForceUpdater } from "@utils/react";
import definePlugin, { IconComponent, OptionType } from "@utils/types";
import { filters, waitFor } from "@webpack";
import { Alerts, ChannelStore, FluxDispatcher, MessageStore, SelectedChannelStore, showToast, TextArea, useEffect, UserStore, useState } from "@webpack/common";
import * as openpgp from "openpgp";

import { createDispatchGate, decryptArmoredContent, decryptReplyPreviews, isArmoredMessage, selectRecipients } from "./core";

// If someone has this in their bio, we assume they run this plugin too.
const MAGIC_BIO_STRING = "I use PGPcord BTW";

// Sent along with our public key to ask the other side to (re)send theirs
const KEY_REQUEST_STRING = "[PGPcord key request]";

const PUBLIC_KEY_REGEX = /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]+?-----END PGP PUBLIC KEY BLOCK-----/;
const PGP_MESSAGE_REGEX = /-----BEGIN PGP MESSAGE-----[\s\S]+?-----END PGP MESSAGE-----/;

// Persisted with Vencord's DataStore (IndexedDB inside the Discord/Vesktop profile folder).
const KEYS_STORE = "PGPcordFork_keys"; // userId -> their armored public key
const SENT_STORE = "PGPcordFork_sentKeyTo"; // userId -> true once we've sent them our public key
const GROUP_MODES_STORE = "PGPcordFork_groupModes";

const settings = definePluginSettings({
    // Custom components instead of STRING settings so the generate button can fill them in live
    generateKeys: {
        type: OptionType.COMPONENT,
        component: ErrorBoundary.wrap(GenerateKeysSetting, { noop: false })
    },
    publicKey: {
        type: OptionType.COMPONENT,
        component: ErrorBoundary.wrap(() => <KeyTextSetting
            id="publicKey"
            title="Public key"
            description={"Your armored PGP public key. Sent automatically to people with \"" + MAGIC_BIO_STRING + "\" in their bio."} />, { noop: false })
    },
    privateKey: {
        type: OptionType.COMPONENT,
        component: ErrorBoundary.wrap(() => <KeyTextSetting
            id="privateKey"
            title="Private key"
            description="Your armored PGP private key. Needed to read encrypted messages. Stored locally in Vencord settings; encrypted only if the key itself has a passphrase. Use a dedicated key and keep a backup to read your history." />, { noop: false })
    },
    passphrase: {
        type: OptionType.STRING,
        description: "Passphrase for your private key (leave empty if it has none)",
        default: "",
        onChange: () => replyPreviews?.retry()
    },
    encryptionEnabled: {
        type: OptionType.BOOLEAN,
        description: "Encrypt outgoing DM/group DM text (also toggled by the lock button). Attachments are not encrypted.",
        default: true
    },
    groupMode: {
        type: OptionType.SELECT,
        description: "Default group DM recipients. Others still see ciphertext. Override with /pgp-self or /pgp-group.",
        options: [
            { label: "People with saved public keys (plus me)", value: "known", default: true },
            { label: "Only me", value: "self" }
        ]
    },
    allowPlainAttachments: {
        type: OptionType.BOOLEAN,
        description: "Send images and other uploads unchanged alongside encrypted text. Attachments are unencrypted and visible to everyone in the chat.",
        default: true
    },
    selfOnlyDM: {
        type: OptionType.BOOLEAN,
        description: "Without a saved DM recipient key, encrypt only to yourself instead of waiting. The other person cannot read it yet.",
        default: true
    },
    plaintextNotifications: {
        type: OptionType.BOOLEAN,
        description: "Show decrypted text in this client's notifications (may appear on your lock screen)",
        default: true
    },
    savedKeys: {
        type: OptionType.COMPONENT,
        component: ErrorBoundary.wrap(SavedKeysSetting, { noop: false })
    }
});

function KeyTextSetting({ id, title, description }: { id: "publicKey" | "privateKey"; title: string; description: string; }) {
    const value = settings.use([id])[id] ?? "";

    return (
        <div>
            <Paragraph><b>{title}</b></Paragraph>
            <Paragraph>{description}</Paragraph>
            <TextArea
                value={value}
                onChange={(v: string) => { settings.store[id] = v; replyPreviews?.retry(); }}
                placeholder="-----BEGIN PGP ..."
                rows={6}
            />
        </div>
    );
}

function GenerateKeysSetting() {
    const [generating, setGenerating] = useState(false);

    async function generate() {
        setGenerating(true);
        try {
            const me = UserStore.getCurrentUser();
            const passphrase = settings.store.passphrase ?? "";
            const { publicKey, privateKey } = await openpgp.generateKey({
                userIDs: [{ name: me?.username ?? "PGPcord user" }],
                passphrase: passphrase || undefined,
                format: "armored"
            });
            settings.store.publicKey = publicKey;
            settings.store.privateKey = privateKey;
            privateKeyCache = null;
            showToast({ text: "Generated a new PGP key pair.", variant: "success" });
        } catch (e) {
            console.error("[PGPcord] Failed to generate keys", e);
            showToast({ text: "PGPcord: failed to generate keys. See console.", variant: "critical" });
        } finally {
            setGenerating(false);
        }
    }

    function onClick() {
        if (!settings.store.publicKey?.trim() && !settings.store.privateKey?.trim()) return void generate();

        Alerts.show({
            title: "Replace your PGP keys?",
            body: "This overwrites your current key pair. You won't be able to read old messages encrypted to it, and people who have your old public key will need your new one (use /pgp-request-keys).",
            confirmText: "Generate",
            cancelText: "Cancel",
            onConfirm: generate
        });
    }

    return (
        <div>
            <Paragraph>Generate a new key pair and fill in the boxes below. If a passphrase is set, the private key is protected with it.</Paragraph>
            <Button size="small" disabled={generating} onClick={onClick}>
                {generating ? "Generating..." : "Generate key pair"}
            </Button>
        </div>
    );
}

function SavedKeysSetting() {
    const forceUpdate = useForceUpdater();
    const userIds = Object.keys(theirKeys);

    const [fingerprints] = useAwaiter(
        () => Promise.all(userIds.map(async id => {
            try {
                return (await openpgp.readKey({ armoredKey: theirKeys[id] })).getFingerprint().toUpperCase();
            } catch {
                return "invalid key";
            }
        })),
        { fallbackValue: [], deps: [userIds.join()] }
    );

    async function clearKeys() {
        // Also forget who we sent our key to, so the exchange starts over next time
        theirKeys = {};
        sentKeyTo = {};
        await DataStore.set(KEYS_STORE, theirKeys);
        await DataStore.set(SENT_STORE, sentKeyTo);
        showToast({ text: "Cleared all saved PGP keys.", variant: "success" });
        forceUpdate();
    }

    return (
        <div>
            <Paragraph>Saved public keys</Paragraph>
            {userIds.length === 0
                ? <Paragraph>No keys saved yet.</Paragraph>
                : (
                    <ul style={{ margin: "8px 0" }}>
                        {userIds.map((id, i) => {
                            const user = UserStore.getUser(id);
                            return (
                                <li key={id} style={{ marginBottom: 4 }}>
                                    <Paragraph>
                                        <b>{user ? user.username : "Unknown user"}</b> ({id})
                                        <br />
                                        <code>{fingerprints[i] ?? "..."}</code>
                                    </Paragraph>
                                </li>
                            );
                        })}
                    </ul>
                )}
            <Button variant="dangerPrimary" size="small" disabled={userIds.length === 0} onClick={clearKeys}>
                Clear keys
            </Button>
        </div>
    );
}

let theirKeys: Record<string, string> = {};
let sentKeyTo: Record<string, boolean> = {};
let pendingMessages: Record<string, string[]> = {};
let groupModes: Record<string, "known" | "self"> = {};
let running = false;
let lifecycle = 0;
let stopDispatchGate: (() => void) | undefined;
let replyPreviews: ReturnType<typeof decryptReplyPreviews> | undefined;
const badgeSubscriptions = new Set<() => void>();

function cachePlaintext(ciphertext: string, plaintext: string) {
    if (plaintextCache.size >= 500) plaintextCache.delete(plaintextCache.keys().next().value!);
    plaintextCache.set(ciphertext, plaintext);
}

function recipientsFor(channelId: string): string[] | null {
    const ids = getRecipientIds(channelId);
    if (!ids) return null;
    const group = !!ChannelStore.getChannel(channelId)?.isGroupDM();
    return selectRecipients(ids, theirKeys, (group || settings.store.selfOnlyDM), group ? groupModes[channelId] ?? settings.store.groupMode : "known");
}

async function setGroupMode(channelId: string, mode: "known" | "self") {
    if (!ChannelStore.getChannel(channelId)?.isGroupDM()) {
        showToast({ text: "This command is for group DMs.", variant: "critical" });
        return;
    }
    groupModes[channelId] = mode;
    await DataStore.set(GROUP_MODES_STORE, groupModes);
    showToast({ text: mode === "self" ? "Group encryption: only you can decrypt new messages." : "Group encryption: people with saved keys, plus you.", variant: "success" });
    badgeSubscriptions.forEach(update => update());
}

// ciphertext -> plaintext. Lets us show our own sent messages and already-decrypted
// messages instantly instead of decrypting them again.
const plaintextCache = new Map<string, string>();
const decrypting = new Set<string>();
const decryptionErrors = new Map<string, { ciphertext: string; message: string; }>();
// IDs of messages we've shown decrypted, so they get the lock badge next to the author name
const encryptedMessageIds = new Set<string>();
// The author line doesn't re-render when a message finishes decrypting, so badges subscribe to their message
const badgeListeners = new Map<string, Set<() => void>>();

function setEncrypted(messageId: string, encrypted: boolean) {
    if (encryptedMessageIds.has(messageId) === encrypted) return;
    if (encrypted) encryptedMessageIds.add(messageId);
    else encryptedMessageIds.delete(messageId);
    badgeListeners.get(messageId)?.forEach(update => update());
    badgeSubscriptions.forEach(update => update());
}

// Everyone else in a DM or group DM, or null if this isn't one
function getRecipientIds(channelId: string | undefined): string[] | null {
    if (!channelId) return null;
    const channel = ChannelStore.getChannel(channelId);
    if (!channel?.isDM() && !channel?.isGroupDM()) return null;
    return channel.recipients ?? [];
}

const usernameOf = (id: string) => UserStore.getUser(id)?.username ?? id;

async function hasPlugin(userId: string) {
    const profile: any = await fetchUserProfile(userId);
    return !!profile?.bio?.includes(MAGIC_BIO_STRING);
}

let checkedOwnBio = false;

async function checkOwnBio() {
    const me = UserStore.getCurrentUser();
    if (!me || checkedOwnBio) return;
    checkedOwnBio = true;

    try {
        if (!await hasPlugin(me.id))
            showToast({ text: `Your bio doesn't contain "${MAGIC_BIO_STRING}", so other PGPcord users won't start key exchanges with you.`, variant: "critical" });
    } catch (e) {
        console.warn("[PGPcord] Could not check your bio", e);
    }
}

function getDmRecipientId(channelId: string | undefined): string | null {
    if (!channelId) return null;
    const channel = ChannelStore.getChannel(channelId);
    if (!channel?.isDM()) return null;
    return channel.recipients?.[0] ?? null;
}

// Returns the DM recipient's pronouns from their profile, or null if this
// isn't a 1-on-1 DM or they haven't set any pronouns.
export async function getDmRecipientPronouns(channelId: string): Promise<string | null> {
    const recipientId = getDmRecipientId(channelId);
    if (!recipientId) return null;

    const profile: any = await fetchUserProfile(recipientId);
    const pronouns: string = profile?.pronouns?.trim() ?? "";
    return pronouns || null;
}

async function saveTheirKey(userId: string, armoredKey: string) {
    theirKeys[userId] = armoredKey;
    await DataStore.set(KEYS_STORE, theirKeys);
}

async function markKeySent(userIds: string[]) {
    for (const id of userIds) sentKeyTo[id] = true;
    await DataStore.set(SENT_STORE, sentKeyTo);
}

async function queuePending(channelId: string, text: string) {
    (pendingMessages[channelId] ??= []).push(text);

}

// Sends the messages that were swapped out for our public key, now that we can encrypt them
async function flushPending(channelId: string, recipientIds: string[]) {
    recipientIds = recipientsFor(channelId) ?? recipientIds;
    const queued = pendingMessages[channelId];
    if (!queued?.length) return;

    delete pendingMessages[channelId];


    for (const content of queued) {
        if (!running) break;
        try {
            const msg = { content };
            if (await encryptInPlace(recipientIds, msg)) await sendMessage(channelId, msg);
        } catch (e) {
            console.error("[PGPcord] Failed to resend queued message", e);
            showToast({ text: "PGPcord: failed to resend your queued message. See console.", variant: "critical" });
        }
    }
}

let privateKeyCache: { source: string; key: openpgp.PrivateKey; } | null = null;

async function getPrivateKey() {
    const privateKey: string = settings.store.privateKey ?? "", passphrase: string = settings.store.passphrase ?? "";
    if (!privateKey.trim()) throw new Error("No private key set in PGPcord settings");

    const source = privateKey + "\0" + passphrase;
    if (privateKeyCache?.source === source) return privateKeyCache.key;

    let key = await openpgp.readPrivateKey({ armoredKey: privateKey.trim() });
    if (!key.isDecrypted()) key = await openpgp.decryptKey({ privateKey: key, passphrase });

    privateKeyCache = { source, key };
    return key;
}

async function encryptFor(userIds: string[], text: string) {
    const encryptionKeys = await Promise.all(userIds.map(id => openpgp.readKey({ armoredKey: theirKeys[id] })));
    // Also encrypt to ourselves so we can read our own messages later
    encryptionKeys.push((await getPrivateKey()).toPublic());

    return await openpgp.encrypt({
        message: await openpgp.createMessage({ text }),
        encryptionKeys
    }) as string;
}

const maxMessageLength = () => (UserStore.getCurrentUser() as any)?.premiumType === 2 ? 4000 : 2000;

// Encrypts msg.content in place. Returns false if the result is too long to send.
async function encryptInPlace(userIds: string[], msg: { content: string; }) {
    const plaintext = msg.content;
    const ciphertext = await encryptFor(userIds, plaintext);

    if (ciphertext.length > maxMessageLength()) {
        showToast({ text: `Encrypted message is too long (${ciphertext.length} characters). Try a shorter message.`, variant: "critical" });
        return false;
    }

    cachePlaintext(ciphertext, plaintext);
    msg.content = ciphertext;
    return true;
}

const offeredDmKeys = new Set<string>();

async function offerDmKey(channelId: string, userId: string) {
    if (offeredDmKeys.has(userId) || sentKeyTo[userId]) return;
    offeredDmKeys.add(userId);
    try {
        if (!await hasPlugin(userId) || !running) return;
        const ownKey = (await getPrivateKey()).toPublic().armor();
        await markKeySent([userId]);
        if (running) await sendMessage(channelId, { content: KEY_REQUEST_STRING + "\n" + ownKey });
    } catch {
        offeredDmKeys.delete(userId);
    }
}

const prepareSend: MessageSendListener = async (channelId, msg, options, props) => {
    if (!settings.store.encryptionEnabled) return;

    const recipientIds = recipientsFor(channelId);
    if (!recipientIds) return;
    if (!running) return { cancel: true };
    if (props?.hasAttachments && !settings.store.allowPlainAttachments) {
        showToast({ text: "Attachments are unencrypted. Enable allowPlainAttachments in the fork settings to send them.", variant: "critical" });
        return { cancel: true };
    }
    if (props?.hasStickers || options?.stickerIds?.length || options?.alsoForwardToChannelId || options?.scheduledTimestamp) {
        showToast({ text: "Stickers, forwarding and scheduled sends are not supported while PGP encryption is enabled.", variant: "critical" });
        return { cancel: true };
    }

    if (!msg.content) return;

    // Never encrypt a key-exchange message
    const publicKeyMessage = msg.content.match(PUBLIC_KEY_REGEX)?.[0];
    if (publicKeyMessage && (msg.content.trim() === publicKeyMessage || msg.content.trim() === KEY_REQUEST_STRING + "\n" + publicKeyMessage)) return;

    try {
        // We have everyone's key: encrypt
        const missing = recipientIds.filter(id => !theirKeys[id]);
        if (!missing.length) {
            if (!await encryptInPlace(recipientIds, msg)) return { cancel: true };
            if (!recipientIds.length) {
                showToast({ text: "Encrypted only to your own key. Other people in this chat cannot decrypt this message.", variant: "success" });
                const channel = ChannelStore.getChannel(channelId);
                if (channel?.isDM() && !channel?.isGroupDM() && channel.recipients?.[0])
                    void offerDmKey(channelId, channel.recipients[0]);
            }
            msg.tts = false;
            // Mentions inside ciphertext can't resolve anyway; keep the reply ping toggle as the user set it
            if (options) options.allowedMentions = { parse: [], repliedUser: options.allowedMentions?.repliedUser ?? true };
            return;
        }

        // Only start an exchange if everyone we're missing a key for has the plugin
        if (!(await Promise.all(missing.map(hasPlugin))).every(Boolean)) {
            showToast({ text: "No saved key for this recipient. Use /pgp-request-keys, or explicitly turn encryption off to send plaintext.", variant: "critical" });
            return { cancel: true };
        }

        if (missing.every(id => sentKeyTo[id])) {
            showToast({ text: `Still waiting for public keys from ${missing.map(usernameOf).join(", ")}. Use the lock button to send unencrypted.`, variant: "critical" });
            return { cancel: true };
        }

        const ownKey = (settings.store.publicKey ?? "").trim();
        if (!ownKey) {
            showToast({ text: "Set your PGP public key in the PGPcord settings first.", variant: "critical" });
            return { cancel: true };
        }
        await openpgp.readKey({ armoredKey: ownKey }); // throws if the key is invalid

        // Send our public key instead of what was typed, and resend that once we have everyone's key
        await queuePending(channelId, msg.content);
        msg.content = ownKey;
        await markKeySent(recipientIds);
        showToast({ text: `Sent your public key. Your message will be sent encrypted once ${recipientIds.length > 1 ? "everyone has" : "they"} sent theirs.`, variant: "success" });
    } catch (e) {
        console.error("[PGPcord] Failed to prepare message, cancelling send", e);
        showToast({ text: "PGPcord: encryption failed, message not sent. See console.", variant: "critical" });
        return { cancel: true };
    }
};

const onBeforeMessageSend: MessageSendListener = async (...args) => {
    try {
        return await prepareSend(...args);
    } catch (error) {
        console.error("[PGPcord Fork] Send preparation failed", error);
        showToast({ text: "PGP encryption failed; your message was not sent.", variant: "critical" });
        return { cancel: true };
    }
};

// Keep edits encrypted too, otherwise editing an encrypted message would resend it in plaintext
const prepareEdit: MessageEditListener = async (channelId, _messageId, msg) => {
    if (!settings.store.encryptionEnabled || !msg.content) return;

    const recipientIds = recipientsFor(channelId);
    if (!recipientIds) return;
    if (!running || !recipientIds.every(id => theirKeys[id])) {
        showToast({ text: "Missing recipient keys; encrypted edit cancelled.", variant: "critical" });
        return { cancel: true };
    }

    try {
        if (!await encryptInPlace(recipientIds, msg)) return { cancel: true };
    } catch (e) {
        console.error("[PGPcord] Failed to encrypt edit, cancelling", e);
        showToast({ text: "PGPcord: encryption failed, edit not saved. See console.", variant: "critical" });
        return { cancel: true };
    }
};

const onBeforeMessageEdit: MessageEditListener = async (...args) => {
    try {
        return await prepareEdit(...args);
    } catch (error) {
        console.error("[PGPcord Fork] Edit preparation failed", error);
        showToast({ text: "PGP encryption failed; your edit was not saved.", variant: "critical" });
        return { cancel: true };
    }
};

async function handleIncomingKey(channelId: string, userId: string, armoredKey: string, isNew: boolean, requested: boolean) {
    if (!running) return;
    // Old key messages loaded from history shouldn't overwrite a key we already have
    const isNewKey = theirKeys[userId] !== armoredKey && (isNew || !theirKeys[userId]);

    if (isNewKey) {
        try {
            await openpgp.readKey({ armoredKey });
        } catch (e) {
            console.warn("[PGPcord] Received an invalid public key from", userId, e);
            return;
        }

        await saveTheirKey(userId, armoredKey);
    }

    const recipientIds = getRecipientIds(channelId) ?? [userId];
    const selectedRecipients = recipientsFor(channelId) ?? recipientIds;
    const everyoneHasKeys = selectedRecipients.every(id => theirKeys[id]);

    if (isNewKey) {
        const text = recipientIds.length === 1
            ? "Saved their PGP public key. Messages in this DM will now be encrypted."
            : `Saved ${usernameOf(userId)}'s PGP public key.` + (everyoneHasKeys ? " Messages in this group will now be encrypted." : "");
        showToast({ text, variant: "success" });
    }

    // Reply with our key if they started the exchange, or if they explicitly asked for it.
    // Only answer requests as they arrive, not ones loaded from history.
    if (running && isNew && ((isNewKey && !sentKeyTo[userId]) || requested)) {
        const ownKey = (settings.store.publicKey ?? "").trim();
        if (ownKey) {
            await markKeySent(recipientIds);
            // Sent this way, it skips onBeforeMessageSend (that only hooks the chat box)
            await sendMessage(channelId, { content: ownKey });
        } else if (requested) {
            showToast({ text: "They requested your PGP public key, but you haven't set one in the PGPcord settings.", variant: "critical" });
        }
    }

    if (isNewKey && everyoneHasKeys) await flushPending(channelId, selectedRecipients);
}

async function requestKeys(channelId: string) {
    if (!running) return;
    const recipientIds = getRecipientIds(channelId);
    if (!recipientIds?.length) {
        showToast({ text: "Keys can only be requested in a DM or group DM.", variant: "critical" });
        return;
    }

    const ownKey = (settings.store.publicKey ?? "").trim();
    if (!ownKey) {
        showToast({ text: "Set your PGP public key in the PGPcord settings first.", variant: "critical" });
        return;
    }

    try {
        await openpgp.readKey({ armoredKey: ownKey }); // throws if the key is invalid
        await markKeySent(recipientIds);
        await sendMessage(channelId, { content: KEY_REQUEST_STRING + "\n" + ownKey });
        showToast({ text: `Sent your public key and requested ${recipientIds.length > 1 ? "everyone else's" : "theirs"}.`, variant: "success" });

        const withoutPlugin = (await Promise.all(recipientIds.map(async id => await hasPlugin(id) ? null : id))).filter(Boolean) as string[];
        if (withoutPlugin.length)
            showToast({ text: `${withoutPlugin.map(usernameOf).join(", ")} ${withoutPlugin.length > 1 ? "don't" : "doesn't"} have "${MAGIC_BIO_STRING}" in their bio, so they may not have PGPcord.`, variant: "critical" });
    } catch (e) {
        console.error("[PGPcord] Failed to request keys", e);
        showToast({ text: "PGPcord: failed to request keys. See console.", variant: "critical" });
    }
}

async function decryptCiphertext(ciphertext: string) {
    const cached = plaintextCache.get(ciphertext);
    if (cached != null && !isArmoredMessage(cached)) return cached;
    const key = await getPrivateKey();
    const plaintext = await decryptArmoredContent(ciphertext, async armoredMessage => {
        const { data } = await openpgp.decrypt({
            message: await openpgp.readMessage({ armoredMessage }),
            decryptionKeys: key
        });
        return data as string;
    });
    cachePlaintext(ciphertext, plaintext);
    return plaintext;
}

function notifyBadge(messageId: string) {
    badgeListeners.get(messageId)?.forEach(update => update());
}

async function decryptLater(channelId: string, messageId: string, ciphertext: string, retry = false) {
    const jobId = messageId + ciphertext;
    if (decrypting.has(jobId) || (!retry && decryptionErrors.get(messageId)?.ciphertext === ciphertext)) return;
    const generation = lifecycle;
    decrypting.add(jobId);
    decryptionErrors.delete(messageId);
    notifyBadge(messageId);
    try {
        const plaintext = await decryptCiphertext(ciphertext);
        if (!running || generation !== lifecycle) return;
        const current = MessageStore.getMessage(channelId, messageId);
        if (current?.content?.match(PGP_MESSAGE_REGEX)?.[0] === ciphertext) {
            setEncrypted(messageId, true);
            updateMessage(channelId, messageId, { content: plaintext, pgpCordEncrypted: true });
        }
    } catch {
        const current = MessageStore.getMessage(channelId, messageId);
        if (running && generation === lifecycle && (!current || current.content?.match(PGP_MESSAGE_REGEX)?.[0] === ciphertext)) {
            setEncrypted(messageId, false);
            decryptionErrors.set(messageId, { ciphertext, message: "Could not decrypt with your configured private key. Check the key and passphrase, then click to retry." });
        }
    } finally {
        decrypting.delete(jobId);
        notifyBadge(messageId);
    }
}

function repairHistory(channelId: string | undefined, messages: any[]) {
    if (!channelId) return;
    // History interceptors run before MessageStore. Wait until the batch has been committed.
    setTimeout(() => {
        if (!running) return;
        for (const message of messages) {
            const current = MessageStore.getMessage(channelId, message.id);
            const ciphertext = current?.content?.match(PGP_MESSAGE_REGEX)?.[0];
            if (ciphertext) void decryptLater(channelId, message.id, ciphertext);
        }
    }, 0);
}

// Swaps ciphertext for plaintext. Cached messages are swapped right away,
// anything else is decrypted in the background and re-rendered when done.
function decryptMessage(message: any) {
    if (typeof message?.content !== "string" || !getRecipientIds(message.channel_id)) return;

    const ciphertext = message.content.match(PGP_MESSAGE_REGEX)?.[0];
    if (!ciphertext) {
        if (message.pgpCordEncrypted) { setEncrypted(message.id, true); return; }
        // Edited to plaintext
        setEncrypted(message.id, false);
        return;
    }

    const cached = plaintextCache.get(ciphertext);
    if (cached != null && !isArmoredMessage(cached)) {
        message.content = cached;
        message.pgpCordEncrypted = true;
        setEncrypted(message.id, true);
    } else {
        setEncrypted(message.id, false);
        void decryptLater(message.channel_id, message.id, ciphertext);
    }
}

function findIncomingKey(message: any, recipientIds: string[]): string | null {
    if (!recipientIds.includes(message?.author?.id) || typeof message.content !== "string") return null;
    return message.content.match(PUBLIC_KEY_REGEX)?.[0] ?? null;
}

// Runs on Discord's events before its stores see them
const interceptAction = (action: any) => {
    switch (action.type) {
        case "MESSAGE_CREATE":
        case "MESSAGE_UPDATE": {
            const { message } = action;
            decryptMessage(message);
            if (message?.pgpCordCiphertext && !settings.store.plaintextNotifications) {
                const text = plaintextCache.get(message.pgpCordCiphertext);
                if (text != null) setTimeout(() => {
                    if (running && MessageStore.getMessage(message.channel_id, message.id)?.content === "Encrypted PGP message")
                        updateMessage(message.channel_id, message.id, { content: text });
                }, 0);
            }

            const recipientIds = getRecipientIds(message?.channel_id);
            const key = recipientIds && findIncomingKey(message, recipientIds);
            if (key) void handleIncomingKey(message.channel_id, message.author.id, key, action.type === "MESSAGE_CREATE", message.content.includes(KEY_REQUEST_STRING));
            break;
        }
        case "LOAD_MESSAGES_SUCCESS":
        case "LOAD_MESSAGES_AROUND_SUCCESS":
        case "LOAD_PINNED_MESSAGES_SUCCESS": {
            const historyChannel = action.channelId ?? action.channel_id ?? action.messages?.[0]?.channel_id;
            action.messages?.forEach((message: any) => {
                if (!message.channel_id && historyChannel) message.channel_id = historyChannel;
                decryptMessage(message);
            });
            repairHistory(historyChannel, action.messages ?? []);

            // Pick up keys sent while we were offline (messages are newest first, so take each author's latest)
            const channelId = action.channelId ?? action.messages?.[0]?.channel_id;
            const recipientIds = getRecipientIds(channelId);
            if (!recipientIds) break;

            const latestKeys = new Map<string, string>();
            for (const m of action.messages ?? []) {
                const key = findIncomingKey(m, recipientIds);
                if (key && !latestKeys.has(m.author.id)) latestKeys.set(m.author.id, key);
            }

            // One at a time, so we don't reply with our key more than once
            void (async () => {
                for (const [userId, key] of latestKeys)
                    await handleIncomingKey(channelId, userId, key, false, false);
            })();
            break;
        }
    }
};

const interceptor = (action: any) => {
    try {
        interceptAction(action);
    } catch (error) {
        console.warn("[PGPcord Fork] Could not process message event", error);
    }
};

const LockIcon: IconComponent = ({ height = 20, width = 20, className }) => (
    <svg width={width} height={height} className={className} viewBox="0 0 24 24">
        <path fill="currentColor" d="M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Zm-3 8V7a3 3 0 1 1 6 0v3H9Z" />
    </svg>
);

const UnlockIcon: IconComponent = ({ height = 20, width = 20, className }) => (
    <svg width={width} height={height} className={className} viewBox="0 0 24 24">
        <path fill="currentColor" d="M12 2a5 5 0 0 0-5 5h2a3 3 0 1 1 6 0v3H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Z" />
    </svg>
);

function EncryptedBadge({ message }: { message: any; }) {
    const forceUpdate = useForceUpdater();
    useEffect(() => {
        const id = message?.id;
        if (!id) return;
        const listeners = badgeListeners.get(id) ?? new Set();
        listeners.add(forceUpdate);
        badgeListeners.set(id, listeners);
        return () => {
            listeners.delete(forceUpdate);
            if (!listeners.size) badgeListeners.delete(id);
        };
    }, [message?.id]);

    const ciphertext = message?.content?.match(PGP_MESSAGE_REGEX)?.[0];
    useEffect(() => {
        if (ciphertext && message?.channel_id && getRecipientIds(message.channel_id))
            void decryptLater(message.channel_id, message.id, ciphertext);
    }, [message?.id, message?.channel_id, message?.content]);

    if (ciphertext) {
        const error = decryptionErrors.get(message.id);
        return <button
            title={error?.message ?? "Encrypted text has not been displayed as plaintext yet. Click to retry decryption."}
            onClick={() => { void decryptLater(message.channel_id, message.id, ciphertext, true); }}
            style={{ display: "inline-flex", marginLeft: 4, color: "var(--text-warning, #faa61a)", background: "none", border: 0, cursor: "pointer" }}
        ><LockIcon width={12} height={12} /></button>;
    }

    if (!message?.pgpCordEncrypted && !encryptedMessageIds.has(message?.id)) return null;

    return (
        <span title="Encrypted" style={{ display: "inline-flex", alignItems: "center", marginLeft: 4, color: "var(--status-positive, #23a55a)", verticalAlign: "middle" }}>
            <LockIcon width={12} height={12} />
        </span>
    );
}

const EncryptionToggle: ChatBarButtonFactory = ({ channel, isMainChat }) => {
    const { encryptionEnabled } = settings.use(["encryptionEnabled", "groupMode"]);
    const forceUpdate = useForceUpdater();
    useEffect(() => {
        badgeSubscriptions.add(forceUpdate);
        return () => { badgeSubscriptions.delete(forceUpdate); };
    }, []);
    if (!isMainChat || (!channel?.isDM() && !channel?.isGroupDM())) return null;

    return (
        <ChatBarButton
            tooltip={encryptionEnabled ? `PGP encryption on (group recipients: ${groupModes[channel.id] ?? settings.store.groupMode}; click to disable)` : "PGP encryption off (click to enable)"}
            onClick={() => settings.store.encryptionEnabled = !encryptionEnabled}
        >
            {encryptionEnabled
                ? <LockIcon />
                : <span style={{ display: "contents", color: "var(--status-danger, #f23f43)" }}><UnlockIcon /></span>}
        </ChatBarButton>
    );
};

const SafeEncryptedBadge = ErrorBoundary.wrap(EncryptedBadge, { noop: true });
const SafeEncryptionToggle = ErrorBoundary.wrap(EncryptionToggle, { noop: true });

export default definePlugin({
    name: "PGPcord: Discord E2EE",
    description: "A discord Encryption layer that automatically encrypts messages between other users with the plugin installed.",
    authors: [{ name: "Raudy6", id: 680537383543898175n }, { name: "1TRF", id: 240274815842385922n}],
    settings,

    onBeforeMessageSend,
    onBeforeMessageEdit,

    commands: [
        {
            name: "pgp-self",
            description: "Encrypt new text in this group DM only to your own key",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: (_, ctx) => setGroupMode(ctx.channel.id, "self")
        },
        {
            name: "pgp-group",
            description: "Encrypt new text to group members with saved keys, plus yourself",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: (_, ctx) => setGroupMode(ctx.channel.id, "known")
        },
        {
            name: "pgp-request-keys",
            description: "Send your PGP public key in this DM or group DM and ask everyone to send theirs back",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: (_, ctx) => requestKeys(ctx.channel.id)
        }
    ],

    flux: {
        CONNECTION_OPEN: checkOwnBio
    },

    renderMessageDecoration: props => <SafeEncryptedBadge message={props.message} />,

    chatBarButton: {
        icon: LockIcon,
        render: props => <SafeEncryptionToggle {...props} />
    },

    async start() {
        const generation = ++lifecycle;
        const original = Settings.plugins["PGPcord: Discord E2EE"];

        if (!settings.store.publicKey && !settings.store.privateKey && original) {
            settings.store.publicKey = original.publicKey;
            settings.store.privateKey = original.privateKey;
            settings.store.passphrase = original.passphrase ?? "";
        }
        theirKeys = await DataStore.get(KEYS_STORE) ?? await DataStore.get("PGPcord_keys") ?? {};
        sentKeyTo = await DataStore.get(SENT_STORE) ?? await DataStore.get("PGPcord_sentKeyTo") ?? {};
        groupModes = await DataStore.get(GROUP_MODES_STORE) ?? {};
        if (generation !== lifecycle) return;
        await DataStore.set(KEYS_STORE, theirKeys);
        await DataStore.set(SENT_STORE, sentKeyTo);
        if (generation !== lifecycle) return;
        // Pending plaintext from the old plugin is never automatically resent.
        pendingMessages = {};
        running = true;
        waitFor(filters.byStoreName("ReferencedMessageStore"), store => {
            if (running && generation === lifecycle)
                replyPreviews = decryptReplyPreviews(store, decryptCiphertext, channelId => !!getRecipientIds(channelId));
        });
        stopDispatchGate = createDispatchGate(FluxDispatcher, {
            applies: message => !!getRecipientIds(message?.channel_id),
            async prepare(message, live) {
                // Decrypt the quoted message shown above replies
                const reference = message?.referenced_message;
                const referenceCiphertext = typeof reference?.content === "string" ? reference.content.match(PGP_MESSAGE_REGEX)?.[0] : null;
                if (referenceCiphertext) {
                    try {
                        const plaintext = await decryptCiphertext(referenceCiphertext);
                        if (running) message = { ...message, referenced_message: { ...reference, content: plaintext, pgpCordEncrypted: true, pgpCordCiphertext: referenceCiphertext } };
                    } catch { }
                }
                const ciphertext = typeof message?.content === "string" ? message.content.match(PGP_MESSAGE_REGEX)?.[0] : null;
                if (!ciphertext) return message;
                try {
                    const plaintext = await decryptCiphertext(ciphertext);
                    if (!running) return message;
                    setEncrypted(message.id, true);
                    return {
                        ...message,
                        content: live && !settings.store.plaintextNotifications ? "Encrypted PGP message" : plaintext,
                        pgpCordEncrypted: true,
                        pgpCordCiphertext: ciphertext
                    };
                } catch {
                    return message;
                }
            }
        });
        FluxDispatcher.addInterceptor(interceptor);
        const channelId = SelectedChannelStore.getChannelId();
        if (channelId) MessageStore.getMessages(channelId)?._array?.forEach(message => {
            const ciphertext = message.content?.match(PGP_MESSAGE_REGEX)?.[0];
            if (ciphertext) void decryptLater(channelId, message.id, ciphertext);
        });
        void checkOwnBio();
    },

    stop() {
        running = false;
        lifecycle++;
        replyPreviews?.stop();
        replyPreviews = undefined;
        stopDispatchGate?.();
        stopDispatchGate = undefined;
        checkedOwnBio = false;
        const interceptors: any[] = FluxDispatcher._interceptors;
        const i = interceptors.indexOf(interceptor);
        if (i !== -1) interceptors.splice(i, 1);
        privateKeyCache = null;
        plaintextCache.clear();
        decryptionErrors.clear();
        offeredDmKeys.clear();
        encryptedMessageIds.clear();
        badgeListeners.clear();
        badgeSubscriptions.clear();
        pendingMessages = {};
    }
});
