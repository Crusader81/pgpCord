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
import { definePluginSettings } from "@api/Settings";
import ErrorBoundary from "@components/ErrorBoundary";
import { Button, Paragraph } from "@components/index";
import { fetchUserProfile, sendMessage } from "@utils/discord";
import { useAwaiter, useForceUpdater } from "@utils/react";
import definePlugin, { IconComponent, OptionType } from "@utils/types";
import { filters, waitFor } from "@webpack";
import { Alerts, ChannelStore, FluxDispatcher, MessageStore, SelectedChannelStore, showToast, TextArea, useEffect, UserStore, useState } from "@webpack/common";
import * as openpgp from "openpgp";

import { createDispatchGate, decryptArmoredContent, decryptReplyPreviews, extractWhitelistedLinks, isArmoredMessage, parseLinkWhitelist, selectRecipients } from "./core";

// If someone has this in their bio, we assume they run this plugin too.
const MAGIC_BIO_STRING = "I use PGPcord BTW";
// Sent along with our public key to ask the other side to (re)send theirs
const KEY_REQUEST_STRING = "[PGPcord key request]";
// Shown in this client's notifications instead of the plaintext when plaintextNotifications is off
const HIDDEN_NOTIFICATION_TEXT = "Encrypted PGP message";

const PUBLIC_KEY_REGEX = /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]+?-----END PGP PUBLIC KEY BLOCK-----/;
const PGP_MESSAGE_REGEX = /-----BEGIN PGP MESSAGE-----[\s\S]+?-----END PGP MESSAGE-----/;

// Persisted with Vencord's DataStore (IndexedDB inside the Discord/Vesktop profile folder).
const KEYS_STORE = "PGPcordFork_keys"; // userId -> their armored public key
const SENT_STORE = "PGPcordFork_sentKeyTo"; // userId -> true once we've sent them our public key
const GROUP_MODES_STORE = "PGPcordFork_groupModes"; // channelId -> GroupMode

type GroupMode = "known" | "self";

// ============================== State ==============================

let theirKeys: Record<string, string> = {};
let sentKeyTo: Record<string, boolean> = {};
let groupModes: Record<string, GroupMode> = {};
// channelId -> plaintext we swapped out for our public key, resent once we have everyone's key
let pendingMessages: Record<string, string[]> = {};

let running = false;
let lifecycle = 0; // bumped on every start/stop so stale async work can bail out
let checkedOwnBio = false;
let stopDispatchGate: (() => void) | undefined;
let replyPreviews: ReturnType<typeof decryptReplyPreviews> | undefined;
let privateKeyCache: { source: string; key: openpgp.PrivateKey; } | null = null;

// ciphertext -> plaintext. Lets us show our own sent messages and already-decrypted
// messages instantly instead of decrypting them again.
const plaintextCache = new Map<string, string>();
const decrypting = new Set<string>();
const decryptionErrors = new Map<string, { ciphertext: string; message: string; }>();
// IDs of messages we've shown decrypted, so they get the lock badge next to the author name
const encryptedMessageIds = new Set<string>();
// The author line doesn't re-render when a message finishes decrypting, so badges subscribe to their message
const badgeListeners = new Map<string, Set<() => void>>();
const badgeSubscriptions = new Set<() => void>(); // chat bar lock buttons
const offeredDmKeys = new Set<string>();
const autoRequestedKeys = new Set<string>();

// ============================== Settings ==============================

const settings = definePluginSettings({
    // Custom components instead of STRING settings so the generate button can fill them in live
    generateKeys: { type: OptionType.COMPONENT, component: ErrorBoundary.wrap(GenerateKeysSetting, { noop: false }) },
    publicKey: keySetting("publicKey", "Public key",
        "Your armored PGP public key. Sent automatically to people with \"" + MAGIC_BIO_STRING + "\" in their bio."),
    privateKey: keySetting("privateKey", "Private key",
        "Your armored PGP private key. Needed to read encrypted messages. Stored locally in Vencord settings; encrypted only if the key itself has a passphrase. Use a dedicated key and keep a backup to read your history."),
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
    whitelistedLinks: {
        type: OptionType.STRING,
        description: "Whitelisted links: domains (comma separated) whose links are also sent unencrypted next to the encrypted message, so Discord can embed them. Anyone in the chat, and Discord, can see these links.",
        default: "youtube.com, youtu.be, klipy.com, giphy.com, tenor.com"
    },
    plaintextNotifications: {
        type: OptionType.BOOLEAN,
        description: "Show decrypted text in this client's notifications (may appear on your lock screen)",
        default: true
    },
    savedKeys: { type: OptionType.COMPONENT, component: ErrorBoundary.wrap(SavedKeysSetting, { noop: false }) }
});

function keySetting(id: "publicKey" | "privateKey", title: string, description: string) {
    return {
        type: OptionType.COMPONENT as const,
        component: ErrorBoundary.wrap(() => <KeyTextSetting id={id} title={title} description={description} />, { noop: false })
    };
}

function KeyTextSetting({ id, title, description }: { id: "publicKey" | "privateKey"; title: string; description: string; }) {
    const value = settings.use([id])[id] ?? "";
    return (
        <div>
            <Paragraph><b>{title}</b></Paragraph>
            <Paragraph>{description}</Paragraph>
            <TextArea value={value} onChange={(v: string) => { settings.store[id] = v; replyPreviews?.retry(); }} placeholder="-----BEGIN PGP-----" rows={6} />
        </div>
    );
}

function GenerateKeysSetting() {
    const [generating, setGenerating] = useState(false);

    async function generate() {
        setGenerating(true);
        try {
            const passphrase = settings.store.passphrase ?? "";
            const { publicKey, privateKey } = await openpgp.generateKey({
                userIDs: [{ name: UserStore.getCurrentUser()?.username ?? "PGPcord user" }],
                passphrase: passphrase || undefined,
                format: "armored"
            });
            settings.store.publicKey = publicKey;
            settings.store.privateKey = privateKey;
            privateKeyCache = null;
            toast.success("Generated a new PGP key pair.");
        } catch (e) {
            console.error("[PGPcord] Failed to generate keys", e);
            toast.error("PGPcord: failed to generate keys. See console.");
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
            <Button size="small" disabled={generating} onClick={onClick}>{generating ? "Generating..." : "Generate key pair"}</Button>
        </div>
    );
}

function SavedKeysSetting() {
    const forceUpdate = useForceUpdater();
    const userIds = Object.keys(theirKeys);
    const [fingerprints] = useAwaiter(() => Promise.all(userIds.map(id =>
        openpgp.readKey({ armoredKey: theirKeys[id] }).then(key => key.getFingerprint().toUpperCase()).catch(() => "invalid key")
    )), { fallbackValue: [], deps: [userIds.join()] });

    async function clearKeys() {
        // Also forget who we sent our key to, so the exchange starts over next time
        theirKeys = {};
        sentKeyTo = {};
        await persistKeys();
        await persistSentKeys();
        toast.success("Cleared all saved PGP keys.");
        forceUpdate();
    }

    return (
        <div>
            <Paragraph>Saved public keys</Paragraph>
            {userIds.length === 0
                ? <Paragraph>No keys saved yet.</Paragraph>
                : <ul style={{ margin: "8px 0" }}>
                    {userIds.map((id, i) => (
                        <li key={id} style={{ marginBottom: 4 }}>
                            <Paragraph>
                                <b>{UserStore.getUser(id)?.username ?? "Unknown user"}</b> ({id})
                                <br />
                                <code>{fingerprints[i] ?? "..."}</code>
                            </Paragraph>
                        </li>
                    ))}
                </ul>}
            <Button variant="dangerPrimary" size="small" disabled={userIds.length === 0} onClick={clearKeys}>Clear keys</Button>
        </div>
    );
}

// ============================== Helpers ==============================

const toast = {
    success: (text: string) => { showToast({ text, variant: "success" }); },
    error: (text: string) => { showToast({ text, variant: "critical" }); }
};
// For send/edit listeners: show the error and block the message
const cancel = (text: string) => { toast.error(text); return { cancel: true }; };

const firstMatch = (regex: RegExp, content: unknown) => typeof content === "string" ? content.match(regex)?.[0] : undefined;
const ciphertextOf = (content: unknown) => firstMatch(PGP_MESSAGE_REGEX, content);
const publicKeyOf = (content: unknown) => firstMatch(PUBLIC_KEY_REGEX, content);

const ownPublicKey = () => (settings.store.publicKey ?? "").trim();
const usernameOf = (id: string) => UserStore.getUser(id)?.username ?? id;
const maxMessageLength = () => (UserStore.getCurrentUser() as any)?.premiumType === 2 ? 4000 : 2000;
const hasPlugin = async (userId: string) => !!(await fetchUserProfile(userId) as any)?.bio?.includes(MAGIC_BIO_STRING);

const persistKeys = () => DataStore.set(KEYS_STORE, theirKeys);
const persistSentKeys = () => DataStore.set(SENT_STORE, sentKeyTo);

async function markKeySent(userIds: string[]) {
    for (const id of userIds) sentKeyTo[id] = true;
    await persistSentKeys();
}

// Everyone else in a DM or group DM, or null if this isn't one
function getRecipientIds(channelId: string | undefined): string[] | null {
    const channel = channelId ? ChannelStore.getChannel(channelId) : null;
    return channel?.isDM() || channel?.isGroupDM() ? channel.recipients ?? [] : null;
}

// Who new text in this channel is encrypted to (besides us), or null outside DMs
function recipientsFor(channelId: string): string[] | null {
    const ids = getRecipientIds(channelId);
    if (!ids) return null;
    const group = !!ChannelStore.getChannel(channelId)?.isGroupDM();
    const mode = group ? groupModes[channelId] ?? settings.store.groupMode : "known";
    return selectRecipients(ids, theirKeys, group || settings.store.selfOnlyDM, mode);
}

async function setGroupMode(channelId: string, mode: GroupMode) {
    if (!ChannelStore.getChannel(channelId)?.isGroupDM()) return toast.error("This command is for group DMs.");
    groupModes[channelId] = mode;
    await DataStore.set(GROUP_MODES_STORE, groupModes);
    toast.success(mode === "self" ? "Group encryption: only you can decrypt new messages." : "Group encryption: people with saved keys, plus you.");
    badgeSubscriptions.forEach(update => update());
}

const notifyBadge = (messageId: string) => badgeListeners.get(messageId)?.forEach(update => update());

function setEncrypted(messageId: string, encrypted: boolean) {
    if (encryptedMessageIds.has(messageId) === encrypted) return;
    if (encrypted) encryptedMessageIds.add(messageId);
    else encryptedMessageIds.delete(messageId);
    notifyBadge(messageId);
    badgeSubscriptions.forEach(update => update());
}

async function checkOwnBio() {
    const me = UserStore.getCurrentUser();
    if (!me || checkedOwnBio) return;
    checkedOwnBio = true;
    try {
        if (!await hasPlugin(me.id))
            toast.error(`Your bio doesn't contain "${MAGIC_BIO_STRING}", so other PGPcord users won't start key exchanges with you.`);
    } catch (e) {
        console.warn("[PGPcord] Could not check your bio", e);
    }
}

// ============================== Encryption ==============================

async function getPrivateKey() {
    const armored: string = settings.store.privateKey ?? "", passphrase: string = settings.store.passphrase ?? "";
    if (!armored.trim()) throw new Error("No private key set in PGPcord settings");

    // Reuse the unlocked key until the key or passphrase changes
    const source = armored + "\0" + passphrase;
    if (privateKeyCache?.source === source) return privateKeyCache.key;

    let key = await openpgp.readPrivateKey({ armoredKey: armored.trim() });
    if (!key.isDecrypted()) key = await openpgp.decryptKey({ privateKey: key, passphrase });
    privateKeyCache = { source, key };
    return key;
}

async function encryptFor(userIds: string[], text: string) {
    const encryptionKeys = await Promise.all(userIds.map(id => openpgp.readKey({ armoredKey: theirKeys[id] })));
    // Also encrypt to ourselves so we can read our own messages later
    encryptionKeys.push((await getPrivateKey()).toPublic());
    return await openpgp.encrypt({ message: await openpgp.createMessage({ text }), encryptionKeys }) as string;
}

function cachePlaintext(ciphertext: string, plaintext: string) {
    if (plaintextCache.size >= 500) plaintextCache.delete(plaintextCache.keys().next().value!);
    plaintextCache.set(ciphertext, plaintext);
}

function cachedPlaintext(ciphertext: string) {
    const cached = plaintextCache.get(ciphertext);
    return cached != null && !isArmoredMessage(cached) ? cached : undefined;
}

// Encrypts msg.content in place. Returns false if the result is too long to send.
async function encryptInPlace(userIds: string[], msg: { content: string; }) {
    const plaintext = msg.content;
    const ciphertext = await encryptFor(userIds, plaintext);
    // Whitelisted links ride along unencrypted so Discord can embed them. The full text stays in
    // the ciphertext and decrypting shows only that, so the links don't appear twice.
    const links = extractWhitelistedLinks(plaintext, parseLinkWhitelist(settings.store.whitelistedLinks ?? ""));
    const content = [ciphertext, ...links].join("\n");

    if (content.length > maxMessageLength()) {
        toast.error(`Encrypted message is too long (${content.length} characters). Try a shorter message.`);
        return false;
    }
    cachePlaintext(ciphertext, plaintext);
    msg.content = content;
    return true;
}

// ============================== Outgoing messages and edits ==============================

const prepareSend: MessageSendListener = async (channelId, msg, options, props) => {
    if (!settings.store.encryptionEnabled) return;
    const recipientIds = recipientsFor(channelId);
    if (!recipientIds) return;
    if (!running) return { cancel: true };
    if (props?.hasAttachments && !settings.store.allowPlainAttachments)
        return cancel("Attachments are unencrypted. Enable allowPlainAttachments in the fork settings to send them.");
    if (props?.hasStickers || options?.stickerIds?.length || options?.alsoForwardToChannelId || options?.scheduledTimestamp)
        return cancel("Stickers, forwarding and scheduled sends are not supported while PGP encryption is enabled.");
    if (!msg.content) return;

    // Never encrypt a key-exchange message
    const publicKeyMessage = publicKeyOf(msg.content);
    if (publicKeyMessage && [publicKeyMessage, KEY_REQUEST_STRING + "\n" + publicKeyMessage].includes(msg.content.trim())) return;

    try {
        const missing = recipientIds.filter(id => !theirKeys[id]);
        if (!missing.length) {
            // We have everyone's key: encrypt
            if (!await encryptInPlace(recipientIds, msg)) return { cancel: true };
            if (!recipientIds.length) {
                toast.success("Encrypted only to your own key. Other people in this chat cannot decrypt this message.");
                const channel = ChannelStore.getChannel(channelId);
                if (channel?.isDM() && channel.recipients?.[0]) void offerDmKey(channelId, channel.recipients[0]);
            }
            msg.tts = false;
            // Mentions inside ciphertext can't resolve anyway; keep the reply ping toggle as the user set it
            if (options) options.allowedMentions = { parse: [], repliedUser: options.allowedMentions?.repliedUser ?? true };
            return;
        }

        // Only start an exchange if everyone we're missing a key for has the plugin
        if (!(await Promise.all(missing.map(hasPlugin))).every(Boolean))
            return cancel("No saved key for this recipient. Use /pgp-request-keys, or explicitly turn encryption off to send plaintext.");
        if (missing.every(id => sentKeyTo[id]))
            return cancel(`Still waiting for public keys from ${missing.map(usernameOf).join(", ")}. Use the lock button to send unencrypted.`);
        const ownKey = ownPublicKey();
        if (!ownKey) return cancel("Set your PGP public key in the PGPcord settings first.");
        await openpgp.readKey({ armoredKey: ownKey }); // throws if the key is invalid

        // Send our public key instead of what was typed, and resend that once we have everyone's key
        (pendingMessages[channelId] ??= []).push(msg.content);
        msg.content = ownKey;
        await markKeySent(recipientIds);
        toast.success(`Sent your public key. Your message will be sent encrypted once ${recipientIds.length > 1 ? "everyone has" : "they"} sent theirs.`);
    } catch (e) {
        console.error("[PGPcord] Failed to prepare message, cancelling send", e);
        return cancel("PGPcord: encryption failed, message not sent. See console.");
    }
};

// Keep edits encrypted too, otherwise editing an encrypted message would resend it in plaintext
const prepareEdit: MessageEditListener = async (channelId, _messageId, msg) => {
    if (!settings.store.encryptionEnabled || !msg.content) return;
    const recipientIds = recipientsFor(channelId);
    if (!recipientIds) return;
    if (!running || !recipientIds.every(id => theirKeys[id])) return cancel("Missing recipient keys; encrypted edit cancelled.");
    try {
        if (!await encryptInPlace(recipientIds, msg)) return { cancel: true };
    } catch (e) {
        console.error("[PGPcord] Failed to encrypt edit, cancelling", e);
        return cancel("PGPcord: encryption failed, edit not saved. See console.");
    }
};

// If a listener throws outside its own try/catch, still cancel so plaintext never slips out
function cancelOnError<A extends any[], R>(listener: (...args: A) => PromiseLike<R> | R, what: string, toastText: string) {
    return async (...args: A): Promise<R | { cancel: boolean; }> => {
        try {
            return await listener(...args);
        } catch (e) {
            console.error(`[PGPcord Fork] ${what} preparation failed`, e);
            return cancel(toastText);
        }
    };
}

const onBeforeMessageSend: MessageSendListener = cancelOnError(prepareSend, "Send", "PGP encryption failed; your message was not sent.");
const onBeforeMessageEdit: MessageEditListener = cancelOnError(prepareEdit, "Edit", "PGP encryption failed; your edit was not saved.");

// ============================== Key exchange ==============================

// Sent a self-only DM to someone who runs the plugin: offer our key once so the exchange can start
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

// Sends the messages that were swapped out for our public key, now that we can encrypt them
async function flushPending(channelId: string, fallbackRecipients: string[]) {
    const recipientIds = recipientsFor(channelId) ?? fallbackRecipients;
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
            toast.error("PGPcord: failed to resend your queued message. See console.");
        }
    }
}

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
        theirKeys[userId] = armoredKey;
        await persistKeys();
    }

    const recipientIds = getRecipientIds(channelId) ?? [userId];
    const selectedRecipients = recipientsFor(channelId) ?? recipientIds;
    const everyoneHasKeys = selectedRecipients.every(id => theirKeys[id]);

    if (isNewKey) toast.success(recipientIds.length === 1
        ? "Saved their PGP public key. Messages in this DM will now be encrypted."
        : `Saved ${usernameOf(userId)}'s PGP public key.` + (everyoneHasKeys ? " Messages in this group will now be encrypted." : ""));

    // Reply with our key if they started the exchange, or if they explicitly asked for it.
    // Only answer requests as they arrive, not ones loaded from history.
    if (running && isNew && ((isNewKey && !sentKeyTo[userId]) || requested)) {
        const ownKey = ownPublicKey();
        if (ownKey) {
            await markKeySent(recipientIds);
            // Sent this way, it skips onBeforeMessageSend (that only hooks the chat box)
            await sendMessage(channelId, { content: ownKey });
        } else if (requested) {
            toast.error("They requested your PGP public key, but you haven't set one in the PGPcord settings.");
        }
    }

    if (isNewKey && everyoneHasKeys) await flushPending(channelId, selectedRecipients);
}

async function requestKeys(channelId: string) {
    if (!running) return;
    const recipientIds = getRecipientIds(channelId);
    if (!recipientIds?.length) return toast.error("Keys can only be requested in a DM or group DM.");
    const ownKey = ownPublicKey();
    if (!ownKey) return toast.error("Set your PGP public key in the PGPcord settings first.");

    try {
        await openpgp.readKey({ armoredKey: ownKey }); // throws if the key is invalid
        await markKeySent(recipientIds);
        await sendMessage(channelId, { content: KEY_REQUEST_STRING + "\n" + ownKey });
        toast.success(`Sent your public key and requested ${recipientIds.length > 1 ? "everyone else's" : "theirs"}.`);

        const withoutPlugin = (await Promise.all(recipientIds.map(async id => await hasPlugin(id) ? null : id))).filter(Boolean) as string[];
        if (withoutPlugin.length)
            toast.error(`${withoutPlugin.map(usernameOf).join(", ")} ${withoutPlugin.length > 1 ? "don't" : "doesn't"} have "${MAGIC_BIO_STRING}" in their bio, so they may not have PGPcord.`);
    } catch (e) {
        console.error("[PGPcord] Failed to request keys", e);
        toast.error("PGPcord: failed to request keys. See console.");
    }
}

// Someone sent us an encrypted message but we don't have their key: ask for it (once per user per session).
function autoRequestKeys(channelId: string, authorId: string | undefined, recipientIds: string[]) {
    if (!running || !authorId || !recipientIds.includes(authorId) || theirKeys[authorId] || autoRequestedKeys.has(authorId)) return;
    autoRequestedKeys.add(authorId);
    void requestKeys(channelId);
}

// ============================== Decryption ==============================

async function decryptCiphertext(ciphertext: string) {
    const cached = cachedPlaintext(ciphertext);
    if (cached != null) return cached;
    const key = await getPrivateKey();
    const plaintext = await decryptArmoredContent(ciphertext, async armoredMessage => {
        const { data } = await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage }), decryptionKeys: key });
        return data as string;
    });
    cachePlaintext(ciphertext, plaintext);
    return plaintext;
}

// Decrypts in the background and swaps the content in MessageStore when done
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
        // Only replace it if nobody edited the message while we were decrypting
        if (ciphertextOf(MessageStore.getMessage(channelId, messageId)?.content) === ciphertext) {
            setEncrypted(messageId, true);
            updateMessage(channelId, messageId, { content: plaintext, pgpCordEncrypted: true });
        }
    } catch {
        const current = MessageStore.getMessage(channelId, messageId);
        if (running && generation === lifecycle && (!current || ciphertextOf(current.content) === ciphertext)) {
            setEncrypted(messageId, false);
            decryptionErrors.set(messageId, { ciphertext, message: "Could not decrypt with your configured private key. Check the key and passphrase, then click to retry." });
        }
    } finally {
        decrypting.delete(jobId);
        notifyBadge(messageId);
    }
}

// Decrypts whatever MessageStore currently holds for these messages
function decryptStored(channelId: string, messages: { id: string; }[]) {
    for (const { id } of messages) {
        const ciphertext = ciphertextOf(MessageStore.getMessage(channelId, id)?.content);
        if (ciphertext) void decryptLater(channelId, id, ciphertext);
    }
}

// Swaps ciphertext for plaintext. Cached messages are swapped right away,
// anything else is decrypted in the background and re-rendered when done.
function decryptMessage(message: any) {
    if (typeof message?.content !== "string" || !getRecipientIds(message.channel_id)) return;

    const ciphertext = ciphertextOf(message.content);
    if (!ciphertext) {
        // Already swapped by the dispatch gate, or edited to plaintext
        setEncrypted(message.id, !!message.pgpCordEncrypted);
        return;
    }
    const cached = cachedPlaintext(ciphertext);
    if (cached != null) {
        message.content = cached;
        message.pgpCordEncrypted = true;
        setEncrypted(message.id, true);
    } else {
        setEncrypted(message.id, false);
        void decryptLater(message.channel_id, message.id, ciphertext);
    }
}

// Runs on every message before Discord's stores and notifications see it (via the dispatch gate in core.ts)
async function prepareGatedMessage(message: any, live: boolean) {
    // Decrypt the quoted message shown above replies
    const reference = message?.referenced_message;
    const referenceCiphertext = ciphertextOf(reference?.content);
    if (referenceCiphertext) {
        try {
            const plaintext = await decryptCiphertext(referenceCiphertext);
            if (running) message = { ...message, referenced_message: { ...reference, content: plaintext, pgpCordEncrypted: true, pgpCordCiphertext: referenceCiphertext } };
        } catch { }
    }

    const ciphertext = ciphertextOf(message?.content);
    if (!ciphertext) return message;
    try {
        const plaintext = await decryptCiphertext(ciphertext);
        if (!running) return message;
        setEncrypted(message.id, true);
        return {
            ...message,
            // Hidden text is put back by the interceptor once the message is in the store
            content: live && !settings.store.plaintextNotifications ? HIDDEN_NOTIFICATION_TEXT : plaintext,
            pgpCordEncrypted: true,
            pgpCordCiphertext: ciphertext
        };
    } catch {
        return message;
    }
}

// ============================== Flux interceptor ==============================

// Their public key if this message is from someone in the chat and contains one
function findIncomingKey(message: any, recipientIds: string[]) {
    return recipientIds.includes(message?.author?.id) ? publicKeyOf(message.content) : undefined;
}

// Runs on Discord's events before its stores see them
function interceptAction(action: any) {
    switch (action.type) {
        case "MESSAGE_CREATE":
        case "MESSAGE_UPDATE": {
            const { message } = action;
            const isNew = action.type === "MESSAGE_CREATE";
            const hadCiphertext = !!ciphertextOf(message?.content);
            decryptMessage(message);

            // The gate hid the plaintext from notifications; restore it once the store has the message
            if (message?.pgpCordCiphertext && !settings.store.plaintextNotifications) {
                const text = plaintextCache.get(message.pgpCordCiphertext);
                if (text != null) setTimeout(() => {
                    if (running && MessageStore.getMessage(message.channel_id, message.id)?.content === HIDDEN_NOTIFICATION_TEXT)
                        updateMessage(message.channel_id, message.id, { content: text });
                }, 0);
            }

            const recipientIds = getRecipientIds(message?.channel_id);
            if (!recipientIds) break;
            const key = findIncomingKey(message, recipientIds);
            if (key) void handleIncomingKey(message.channel_id, message.author.id, key, isNew, message.content.includes(KEY_REQUEST_STRING));
            else if (isNew && hadCiphertext) autoRequestKeys(message.channel_id, message.author?.id, recipientIds);
            break;
        }
        case "LOAD_MESSAGES_SUCCESS":
        case "LOAD_MESSAGES_AROUND_SUCCESS":
        case "LOAD_PINNED_MESSAGES_SUCCESS": {
            const messages: any[] = action.messages ?? [];
            const channelId: string | undefined = action.channelId ?? action.channel_id ?? messages[0]?.channel_id;
            for (const message of messages) {
                if (!message.channel_id && channelId) message.channel_id = channelId;
                decryptMessage(message);
            }
            // History interceptors run before MessageStore. Wait until the batch has been committed.
            if (channelId) setTimeout(() => { if (running) decryptStored(channelId, messages); }, 0);

            // Pick up keys sent while we were offline (messages are newest first, so take each author's latest)
            const recipientIds = getRecipientIds(channelId);
            if (!recipientIds) break;
            const latestKeys = new Map<string, string>();
            for (const message of messages) {
                const key = findIncomingKey(message, recipientIds);
                if (key && !latestKeys.has(message.author.id)) latestKeys.set(message.author.id, key);
            }
            // One at a time, so we don't reply with our key more than once
            void (async () => {
                for (const [userId, key] of latestKeys) await handleIncomingKey(channelId!, userId, key, false, false);
            })();
            break;
        }
    }
}

const interceptor = (action: any) => {
    try {
        interceptAction(action);
    } catch (e) {
        console.warn("[PGPcord Fork] Could not process message event", e);
    }
};

// ============================== UI ==============================

const svgIcon = (path: string): IconComponent => ({ height = 20, width = 20, className }) => (
    <svg width={width} height={height} className={className} viewBox="0 0 24 24"><path fill="currentColor" d={path} /></svg>
);
const LockIcon = svgIcon("M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Zm-3 8V7a3 3 0 1 1 6 0v3H9Z");
const UnlockIcon = svgIcon("M12 2a5 5 0 0 0-5 5h2a3 3 0 1 1 6 0v3H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Z");

// Lock next to the author name: green once decrypted, orange (click to retry) while still ciphertext
function EncryptedBadge({ message }: { message: any; }) {
    const forceUpdate = useForceUpdater();
    useEffect(() => {
        const id = message?.id;
        if (!id) return;
        const listeners = badgeListeners.get(id) ?? new Set();
        badgeListeners.set(id, listeners.add(forceUpdate));
        return () => { listeners.delete(forceUpdate); if (!listeners.size) badgeListeners.delete(id); };
    }, [message?.id]);

    const ciphertext = ciphertextOf(message?.content);
    useEffect(() => {
        if (ciphertext && message?.channel_id && getRecipientIds(message.channel_id))
            void decryptLater(message.channel_id, message.id, ciphertext);
    }, [message?.id, message?.channel_id, message?.content]);

    if (ciphertext) return (
        <button
            title={decryptionErrors.get(message.id)?.message ?? "Encrypted text has not been displayed as plaintext yet. Click to retry decryption."}
            onClick={() => { void decryptLater(message.channel_id, message.id, ciphertext, true); }}
            style={{ display: "inline-flex", marginLeft: 4, color: "var(--text-warning, #faa61a)", background: "none", border: 0, cursor: "pointer" }}
        >
            <LockIcon width={12} height={12} />
        </button>
    );
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

// ============================== Plugin ==============================

const command = (name: string, description: string, execute: (channelId: string) => Promise<void>) => ({
    name, description, inputType: ApplicationCommandInputType.BUILT_IN,
    execute: (_: unknown, ctx: { channel: { id: string; }; }) => execute(ctx.channel.id)
});

export default definePlugin({
    name: "PGPcord: Discord E2EE",
    description: "A discord Encryption layer that automatically encrypts messages between other users with the plugin installed.",
    authors: [{ name: "Raudy6", id: 680537383543898175n }, { name: "1TRF", id: 240274815842385922n }],
    settings,
    onBeforeMessageSend,
    onBeforeMessageEdit,
    commands: [
        command("pgp-self", "Encrypt new text in this group DM only to your own key", id => setGroupMode(id, "self")),
        command("pgp-group", "Encrypt new text to group members with saved keys, plus yourself", id => setGroupMode(id, "known")),
        command("pgp-request-keys", "Send your PGP public key in this DM or group DM and ask everyone to send theirs back", requestKeys)
    ],
    flux: { CONNECTION_OPEN: checkOwnBio },
    renderMessageDecoration: props => <SafeEncryptedBadge message={props.message} />,
    chatBarButton: { icon: LockIcon, render: props => <SafeEncryptionToggle {...props} /> },

    async start() {
        const generation = ++lifecycle;
        theirKeys = await DataStore.get(KEYS_STORE) ?? await DataStore.get("PGPcord_keys") ?? {};
        sentKeyTo = await DataStore.get(SENT_STORE) ?? await DataStore.get("PGPcord_sentKeyTo") ?? {};
        groupModes = await DataStore.get(GROUP_MODES_STORE) ?? {};
        if (generation !== lifecycle) return;
        await persistKeys();
        await persistSentKeys();
        if (generation !== lifecycle) return;
        pendingMessages = {}; // queued plaintext is never resent across restarts
        running = true;

        waitFor(filters.byStoreName("ReferencedMessageStore"), store => {
            if (running && generation === lifecycle)
                replyPreviews = decryptReplyPreviews(store, decryptCiphertext, channelId => !!getRecipientIds(channelId));
        });
        stopDispatchGate = createDispatchGate(FluxDispatcher, {
            applies: message => !!getRecipientIds(message?.channel_id),
            prepare: prepareGatedMessage
        });
        FluxDispatcher.addInterceptor(interceptor);

        const channelId = SelectedChannelStore.getChannelId();
        if (channelId) decryptStored(channelId, MessageStore.getMessages(channelId)?._array ?? []);
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
        pendingMessages = {};
        for (const collection of [plaintextCache, decryptionErrors, offeredDmKeys, encryptedMessageIds, badgeListeners, badgeSubscriptions])
            collection.clear();
    }
});
