/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

export function selectRecipients(ids: string[], keys: Record<string, string>, group: boolean, mode: string): string[] {
    if (!group) return ids;
    return mode === "self" ? [] : ids.filter(id => !!keys[id]);
}

export function isArmoredMessage(text: string): boolean {
    return /^-----BEGIN PGP MESSAGE-----\s[\s\S]*-----END PGP MESSAGE-----$/.test(text.trim());
}

export async function decryptArmoredContent(ciphertext: string, decrypt: (armored: string) => Promise<string>) {
    let text = ciphertext;
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
