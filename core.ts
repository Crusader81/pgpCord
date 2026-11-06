/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

export function selectRecipients(ids: string[], keys: Record<string, string>, group: boolean, mode: string): string[] {
    if (!group) return ids;
    // in groups, only include people whose keys we have
    return mode === "self" ? [] : ids.filter(id => !!keys[id]);
}

export function isArmoredMessage(text: string): boolean {
    return /^-----BEGIN PGP MESSAGE-----\s[\s\S]*-----END PGP MESSAGE-----$/.test(text.trim());
}

export async function decryptArmoredContent(ciphertext: string, decrypt: (armored: string) => Promise<string>) {
    let text = ciphertext;
    // unwrap messages that got encrypted more than once
    for (let layer = 0; layer < 3; layer++) {
        text = await decrypt(text.trim());
        if (!isArmoredMessage(text)) return text;
    }
    throw new Error("Message still contains encrypted layers after three decryptions.");
}

export async function mapSearchMessages(value: any, prepare: (message: any) => Promise<any>, channelId?: string, depth = 0): Promise<any> {
    if (depth > 8 || value == null || typeof value !== "object") return value;
    if (Array.isArray(value))
        return Promise.all(value.map(item => mapSearchMessages(item, prepare, channelId, depth + 1)));
    if (typeof value.content === "string" && (value.channel_id ?? channelId))
        return prepare({ ...value, channel_id: value.channel_id ?? channelId });
    const mapped = { ...value };
    for (const field of ["messages", "message", "data", "results", "searchResults"])
        if (value[field] != null) mapped[field] = await mapSearchMessages(value[field], prepare, channelId, depth + 1);
    return mapped;
}

type Action = { type: string; [key: string]: any; };
type Dispatcher = { dispatch(action: any): any; };
type Preparation = {
    applies(message: any): boolean;
    prepare(message: any, live: boolean): Promise<any>;
};

export function createDispatchGate(dispatcher: Dispatcher, preparation: Preparation, timeout = 10_000) {
    const original = dispatcher.dispatch;
    const queues = new Map<string, Promise<any>>();
    let active = true;

    async function prepare(message: any, live: boolean) {
        if (!active) return message;
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
            if (!preparation.applies(message)) return message;
            // let discord carry on if decryption takes too long
            return await Promise.race([
                preparation.prepare(message, live),
                new Promise(resolve => { timer = setTimeout(() => resolve(message), timeout); })
            ]);
        } catch {
            return message;
        } finally {
            clearTimeout(timer);
        }
    }

    async function transform(action: Action) {
        if (action.type === "SEARCH_MESSAGES_SUCCESS" || action.type === "SEARCH_FINISH")
            return mapSearchMessages(action, message => prepare(message, false), action.channelId ?? action.channel_id);
        if (action.type === "MESSAGE_CREATE" || action.type === "MESSAGE_UPDATE") {
            const message = await prepare({ ...action.message, channel_id: action.message?.channel_id ?? action.channelId ?? action.channel_id }, action.type === "MESSAGE_CREATE");
            return { ...action, message };
        }
        if (Array.isArray(action.messages)) {
            const messages = [...action.messages];
            let cursor = 0;
            await Promise.all(Array.from({ length: Math.min(4, messages.length) }, async () => {
                while (cursor < messages.length) {
                    const index = cursor++;
                    const message = messages[index];
                    messages[index] = await prepare({ ...message, channel_id: message.channel_id ?? action.channelId ?? action.channel_id }, false);
                }
            }));
            return { ...action, messages };
        }
        return action;
    }

    function dispatch(this: unknown, action: Action) {
        if (!active) return original.call(this, action);
        const { message } = action;
        const search = /^(SEARCH_MESSAGES_(SUCCESS|CLEAR|CLEAR_ALL|START|FAILURE)|SEARCH_FINISH)$/.test(action.type);
        const searchResults = action.type === "SEARCH_MESSAGES_SUCCESS" || action.type === "SEARCH_FINISH";
        const channel = search ? `search:${action.searchId ?? action.search_id ?? "default"}` : message?.channel_id ?? action.channelId ?? action.channel_id ?? action.messages?.[0]?.channel_id;
        const lifecycle = search || /^(MESSAGE_CREATE|MESSAGE_UPDATE|MESSAGE_DELETE|MESSAGE_DELETE_BULK|LOAD_MESSAGES_SUCCESS|LOAD_MESSAGES_AROUND_SUCCESS|LOAD_PINNED_MESSAGES_SUCCESS)$/.test(action.type);
        let encrypted = false;
        try {
            // Replies carry a copy of the message they reply to, which may be encrypted even if the reply isn't
            encrypted = [message, ...(Array.isArray(action.messages) ? action.messages : [])]
                .flatMap(m => [m, m?.referenced_message])
                .some(m => typeof m?.content === "string" && m.content.includes("-----BEGIN PGP MESSAGE-----")
                    && preparation.applies({ ...m, channel_id: m.channel_id ?? channel }));
        } catch {
            return original.call(this, action);
        }
        if (!channel || !lifecycle || (!searchResults && !encrypted && !queues.has(channel))) return original.call(this, action);
        // keep edits and deletes behind any decryption already running here
        const previous = queues.get(channel) ?? Promise.resolve();
        const task = previous.catch(() => {}).then(async () => {
            let next = action;
            try {
                if (active) next = await transform(action);
            } catch {
                next = action;
            }
            return original.call(this, active ? next : action);
        });
        queues.set(channel, task);
        const cleanup = () => { if (queues.get(channel) === task) queues.delete(channel); };
        void task.then(cleanup, cleanup);
        return task;
    }

    dispatcher.dispatch = dispatch;
    return () => {
        active = false;
        if (dispatcher.dispatch === dispatch) dispatcher.dispatch = original;
    };
}

// should decrypt replies without needing to go into history
export function decryptReplyPreviews(store: any, decrypt: (ciphertext: string) => Promise<string>, applies: (channelId: string) => boolean) {
    const armor = /-----BEGIN PGP MESSAGE-----[\s\S]+?-----END PGP MESSAGE-----/;
    const plaintext = new Map<string, string>();
    const pending = new Set<string>();
    const failed = new Set<string>();
    let records = new WeakMap<object, { text: string; message: any; }>();
    let active = true, generation = 0;
    const restore: (() => void)[] = [];

    function read(entry: any, fallbackChannel?: string) {
        const message = entry?.message;
        const channelId = message?.channel_id ?? fallbackChannel;
        const ciphertext = typeof message?.content === "string" ? message.content.match(armor)?.[0] : null;
        if (!active || !ciphertext || !channelId || !applies(channelId)) return entry;
        const text = plaintext.get(ciphertext);
        if (text != null) {
            let record = records.get(message);
            if (!record || record.text !== text) {
                const fields = { content: text, pgpCordEncrypted: true };
                record = { text, message: typeof message.merge === "function" ? message.merge(fields) : { ...message, ...fields } };
                records.set(message, record);
            }
            // give the preview a decrypted copy, leave the stored message alone
            return { ...entry, message: record.message };
        }
        // avoid starting the same job again on every render
        if (!pending.has(ciphertext) && !failed.has(ciphertext)) {
            pending.add(ciphertext);
            const started = generation;
            void Promise.resolve().then(() => decrypt(ciphertext)).then(text => {
                if (!active || generation !== started || typeof text !== "string") return;
                if (plaintext.size >= 500) plaintext.delete(plaintext.keys().next().value!);
                plaintext.set(ciphertext, text);
                // tell the reply preview to render again with the plaintext
                store.emitChange();
            }).catch(() => {
                if (active && generation === started) {
                    if (failed.size >= 500) failed.delete(failed.values().next().value!);
                    failed.add(ciphertext);
                }
            }).finally(() => { if (generation === started) pending.delete(ciphertext); });
        }
        return entry;
    }
    for (const method of ["getMessage", "getMessageByReference"]) {
        const original = store?.[method];
        if (typeof original !== "function") continue;
        const wrapped = function (this: any, ...args: any[]) {
            const entry = original.apply(this, args);
            try {
                const channelId = method === "getMessage" ? args[0] : args[0]?.channel_id ?? args[0]?.channelId;
                return read(entry, channelId);
            } catch { return entry; }
        };
        store[method] = wrapped;
        restore.push(() => { if (store[method] === wrapped) store[method] = original; });
    }
    return {
        retry() { generation++; failed.clear(); pending.clear(); store?.emitChange?.(); },
        stop() {
            active = false; generation++;
            restore.reverse().forEach(unpatch => unpatch());
            plaintext.clear(); pending.clear(); failed.clear(); records = new WeakMap();
        }
    };
}
