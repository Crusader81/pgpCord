/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

// =====================================================================================
// pgpCord core helpers
// -------------------------------------------------------------------------------------
// This file holds the plumbing for the pgpCord plugin, which lets you send and read
// PGP-encrypted messages inside Discord.
//
// A few terms used throughout:
//   - PGP:        A well-known encryption standard. Messages are scrambled with the
//                 recipient's "public key" and can only be unscrambled with their
//                 matching "private key".
//   - Armored:    PGP output turned into plain text so it can be pasted anywhere. It
//                 always starts with "-----BEGIN PGP MESSAGE-----" and ends with
//                 "-----END PGP MESSAGE-----".
//   - Ciphertext: The scrambled (encrypted) text.
//   - Plaintext:  The readable (decrypted) text.
//   - Dispatcher: Discord's internal "mail room". Every event (new message, edit,
//                 delete, search result...) is sent through it as an "action" object,
//                 and the rest of the app reacts to those actions.
//   - Store:      A place where Discord keeps data (like messages) in memory so the UI
//                 can look it up.
//   - Promise / async / await: JavaScript's way of handling work that finishes later
//                 (like decryption). "await" means "pause here until that work is done".
// =====================================================================================


// -------------------------------------------------------------------------------------
// selectRecipients
// Decides WHO a message should be encrypted for.
//
//   ids   - the user IDs of everyone in the conversation
//   keys  - a lookup table of userId -> that user's public PGP key
//   group - true if this is a group chat, false if it's a one-on-one DM
//   mode  - a setting; "self" means "only encrypt for myself" in groups
//
// Returns the list of user IDs to encrypt for.
// -------------------------------------------------------------------------------------
export function selectRecipients(ids: string[], keys: Record<string, string>, group: boolean, mode: string): string[] {
    // In a private DM, just use everyone in it (you and the other person).
    if (!group) return ids;
    // in groups, only include people whose keys we have
    // If mode is "self", encrypt for nobody else (empty list).
    // Otherwise keep only the people we actually have a public key for, since we
    // can't encrypt for someone without their key. ("!!" turns a value into true/false.)
    return mode === "self" ? [] : ids.filter(id => !!keys[id]);
}

// -------------------------------------------------------------------------------------
// isArmoredMessage
// Checks to see if the message being tested is encrypted.
//
// Returns true only if the WHOLE text (ignoring surrounding spaces) is a single PGP
// message block, i.e. it starts with the BEGIN line and ends with the END line.
// -------------------------------------------------------------------------------------
export function isArmoredMessage(text: string): boolean {
    // This is a "regular expression" (a text pattern):
    //   ^                               -> must be at the very start
    //   -----BEGIN PGP MESSAGE-----     -> the literal header line
    //   \s                              -> followed by whitespace (e.g. a newline)
    //   [\s\S]*                         -> then anything at all, any length
    //   -----END PGP MESSAGE-----       -> the literal footer line
    //   $                               -> must be at the very end
    // .trim() removes leading/trailing spaces before checking.
    return /^-----BEGIN PGP MESSAGE-----\s[\s\S]*-----END PGP MESSAGE-----$/.test(text.trim());
}

// -------------------------------------------------------------------------------------
// decryptArmoredContent
// Decrypts a message, peeling off extra layers if it was encrypted more than once.
//
//   ciphertext - the encrypted text
//   decrypt    - a function (supplied by the caller) that decrypts ONE layer
//
// Returns the readable text, or throws an error if it's still encrypted after 5 tries.
// -------------------------------------------------------------------------------------
export async function decryptArmoredContent(ciphertext: string, decrypt: (armored: string) => Promise<string>) {
    // Start with the encrypted text; we'll replace it with each decrypted result.
    let text = ciphertext;
    // unwrap messages that got encrypted more than once. Not sure why that would ever happen but why not.
    // Try at most 5 times so a weird message can't make us loop forever.
    for (let layer = 0; layer < 5; layer++) {
        // Decrypt one layer and wait for the result.
        text = await decrypt(text.trim());
        // If the result no longer looks encrypted, we're done; hand back the readable text.
        if (!isArmoredMessage(text)) return text;
    }
    // Still encrypted after 5 layers: give up and report a problem.
    throw new Error("Message still contains encrypted layers after five decryptions.");
}

// -------------------------------------------------------------------------------------
// mapSearchMessages
// Discord's search results come back as a deeply nested jumble of objects and lists.
// This function digs through that structure, finds every message inside, and runs
// `prepare` (e.g. decryption) on each one. It returns a NEW copy of the structure
// with the prepared messages swapped in; the original is not modified.
//
//   value     - the current piece of data being examined
//   prepare   - what to do to each message found (returns the new message)
//   channelId - a fallback channel ID for messages that don't list their own
//   depth     - how deep we've dug so far (used as a safety limit)
// -------------------------------------------------------------------------------------
export async function mapSearchMessages(value: any, prepare: (message: any) => Promise<any>, channelId?: string, depth = 0): Promise<any> {
    // Stop digging if:
    //  - we've gone more than 8 levels deep (safety limit against huge/looping data),
    //  - the value is empty (null/undefined), or
    //  - the value isn't an object (e.g. a number or string; nothing to dig into).
    if (depth > 8 || value == null || typeof value !== "object") return value;
    // If it's a list, process every item in it at the same time and wait for all of them.
    if (Array.isArray(value))
        return Promise.all(value.map(item => mapSearchMessages(item, prepare, channelId, depth + 1)));
    // If this object looks like a message (it has text "content" and we know its channel),
    // run `prepare` on it. We make a copy that's guaranteed to have a channel_id.
    // ("??" means "use the left side, or the right side if the left is missing".)
    if (typeof value.content === "string" && (value.channel_id ?? channelId))
        return prepare({ ...value, channel_id: value.channel_id ?? channelId });
    // Otherwise it's some wrapper object. Make a shallow copy of it...
    const mapped = { ...value };
    // ...and look inside the fields where Discord tends to put messages, digging into each.
    for (const field of ["messages", "message", "data", "results", "searchResults"])
        if (value[field] != null) mapped[field] = await mapSearchMessages(value[field], prepare, channelId, depth + 1);
    // Return the copy with any messages inside it prepared.
    return mapped;
}

// -------------------------------------------------------------------------------------
// Type definitions (TypeScript only; these describe the "shape" of data, they don't run)
// -------------------------------------------------------------------------------------

// An action sent through Discord's dispatcher: always has a "type" (like "MESSAGE_CREATE")
// plus any number of other fields.
type Action = { type: string; [key: string]: any; };
// Anything that has a `dispatch` function, i.e. Discord's dispatcher.
type Dispatcher = { dispatch(action: any): any; };
// The two things the caller must provide to tell the gate how to handle messages:
type Preparation = {
    // Should this message be processed at all? (e.g. is it in a channel we use PGP in?)
    applies(message: any): boolean;
    // Actually process (decrypt) the message. `live` is true for brand-new incoming
    // messages, false for old ones loaded from history or search.
    prepare(message: any, live: boolean): Promise<any>;
};

// -------------------------------------------------------------------------------------
// createDispatchGate
// Installs a "checkpoint" in front of Discord's dispatcher. Every message-related event
// passes through this checkpoint first. If it contains encrypted messages, the
// checkpoint holds the event, decrypts the messages, and only then lets the event
// through, so Discord displays readable text instead of ciphertext.
//
//   dispatcher  - Discord's message dispatcher
//   preparation - tells us which messages to handle and how to decrypt them
//   timeout     - max time (in milliseconds) to wait for decryption; 10_000 = 10 seconds
//
// Returns a function that, when called, removes the checkpoint and restores normal behavior.
// -------------------------------------------------------------------------------------
export function createDispatchGate(dispatcher: Dispatcher, preparation: Preparation, timeout = 10_000) {
    // Save Discord's real dispatch function so we can still call it (and restore it later).
    const original = dispatcher.dispatch;
    // A "waiting line" per channel. Each entry is the latest pending job for that channel.
    // New jobs for the same channel wait for the previous one, so events stay in order.
    const queues = new Map<string, Promise<any>>();
    // On/off switch. Once turned off, everything passes straight through untouched.
    let active = true;

    // ---------------------------------------------------------------------------------
    // prepare (inner helper)
    // Safely decrypts a single message. It NEVER fails: if anything goes wrong or takes
    // too long, it just returns the original message unchanged.
    // ---------------------------------------------------------------------------------
    async function prepare(message: any, live: boolean) {
        // If the gate has been turned off, don't do anything.
        if (!active) return message;
        // Will hold our countdown timer so we can cancel it afterwards.
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
            // If this message isn't one we should handle, return it as-is.
            if (!preparation.applies(message)) return message;
            // let discord carry on if decryption takes too long.
            // Promise.race runs two things at once and takes whichever finishes FIRST:
            //   1. the real decryption, or
            //   2. a timer that, after `timeout` ms, just gives back the original message.
            return await Promise.race([
                preparation.prepare(message, live),
                new Promise(resolve => { timer = setTimeout(() => resolve(message), timeout); })
            ]);
        } catch {
            // Decryption blew up for some reason; fall back to the original message.
            return message;
        } finally {
            // Whatever happened, stop the countdown timer so it doesn't fire later.
            clearTimeout(timer);
        }
    }

    // ---------------------------------------------------------------------------------
    // transform (inner helper)
    // Takes a Discord action and returns a copy with its messages decrypted.
    // Different kinds of actions store messages in different places, so we handle
    // each kind separately.
    // ---------------------------------------------------------------------------------
    async function transform(action: Action) {
        // Case 1: search results. These are deeply nested, so use mapSearchMessages to
        // find and decrypt every message inside. `false` = these are not live messages.
        if (action.type === "SEARCH_MESSAGES_SUCCESS" || action.type === "SEARCH_FINISH")
            return mapSearchMessages(action, message => prepare(message, false), action.channelId ?? action.channel_id);
        // Case 2: a single message was sent or edited.
        if (action.type === "MESSAGE_CREATE" || action.type === "MESSAGE_UPDATE") {
            // Decrypt a copy of the message, making sure it knows its channel ID
            // (it may be on the message itself or on the action, under either spelling).
            // It counts as "live" only if it's a brand-new message (CREATE), not an edit.
            const message = await prepare({ ...action.message, channel_id: action.message?.channel_id ?? action.channelId ?? action.channel_id }, action.type === "MESSAGE_CREATE");
            // Return a copy of the action with the decrypted message swapped in.
            return { ...action, message };
        }
        // Case 3: a batch of messages (e.g. loading chat history when you scroll up).
        if (Array.isArray(action.messages)) {
            // Copy the list so we don't modify Discord's original.
            const messages = [...action.messages];
            // Shared bookmark: the index of the next message nobody has started on yet.
            let cursor = 0;
            // Start up to 4 "workers" running at the same time. Each worker repeatedly
            // grabs the next unclaimed message, decrypts it, and puts the result back in
            // the same slot. This is faster than one at a time, without overloading
            // things by doing hundreds at once.
            await Promise.all(Array.from({ length: Math.min(4, messages.length) }, async () => {
                while (cursor < messages.length) {
                    // Claim the next message and move the bookmark forward.
                    const index = cursor++;
                    const message = messages[index];
                    // Decrypt it (with a guaranteed channel ID) and store the result.
                    messages[index] = await prepare({ ...message, channel_id: message.channel_id ?? action.channelId ?? action.channel_id }, false);
                }
            }));
            // Return a copy of the action with the decrypted list swapped in.
            return { ...action, messages };
        }
        // Any other kind of action: nothing to decrypt, return it unchanged.
        return action;
    }

    // ---------------------------------------------------------------------------------
    // dispatch (the replacement)
    // This is what Discord will call instead of its real dispatch function. It decides,
    // for every event, whether to let it straight through or to hold it for decryption.
    // ---------------------------------------------------------------------------------
    function dispatch(this: unknown, action: Action) {
        // Gate is off: behave exactly like Discord normally would.
        if (!active) return original.call(this, action);
        // Pull out the single message on this action, if there is one.
        const { message } = action;
        // Is this any kind of search-related event? (start, success, clear, failure, finish)
        const search = /^(SEARCH_MESSAGES_(SUCCESS|CLEAR|CLEAR_ALL|START|FAILURE)|SEARCH_FINISH)$/.test(action.type);
        // Is this specifically a search event that carries results?
        const searchResults = action.type === "SEARCH_MESSAGES_SUCCESS" || action.type === "SEARCH_FINISH";
        // Figure out which "waiting line" this event belongs to:
        //  - searches get their own line named "search:<id>" (or "search:default"),
        //  - everything else uses the channel ID, looked for in several possible places.
        const channel = search ? `search:${action.searchId ?? action.search_id ?? "default"}` : message?.channel_id ?? action.channelId ?? action.channel_id ?? action.messages?.[0]?.channel_id;
        // Is this an event we care about at all? (searches, or any message create/edit/
        // delete/load event). Everything else (typing indicators, presence, etc.) is ignored.
        const lifecycle = search || /^(MESSAGE_CREATE|MESSAGE_UPDATE|MESSAGE_DELETE|MESSAGE_DELETE_BULK|LOAD_MESSAGES_SUCCESS|LOAD_MESSAGES_AROUND_SUCCESS|LOAD_PINNED_MESSAGES_SUCCESS)$/.test(action.type);
        // Will be set to true if this event contains at least one encrypted message we handle.
        let encrypted = false;
        try {
            // Replies carry a copy of the message they reply to, which may be encrypted even if the reply isn't
            // Gather the single message plus any batch of messages, then also include the
            // message each one is replying to. Check whether ANY of them contains the PGP
            // header text AND is in a place where we're supposed to decrypt.
            encrypted = [message, ...(Array.isArray(action.messages) ? action.messages : [])]
                .flatMap(m => [m, m?.referenced_message])
                .some(m => typeof m?.content === "string" && m.content.includes("-----BEGIN PGP MESSAGE-----")
                    && preparation.applies({ ...m, channel_id: m.channel_id ?? channel }));
        } catch {
            // If checking crashed for any reason, play it safe and let the event through untouched.
            return original.call(this, action);
        }
        // Let the event straight through (no waiting) if ANY of these are true:
        //  - we couldn't figure out which channel it's for,
        //  - it's not a message/search event we care about, or
        //  - it has nothing encrypted, isn't search results, AND nothing is already
        //    waiting in this channel's line (so there's nothing to stay in order behind).
        if (!channel || !lifecycle || (!searchResults && !encrypted && !queues.has(channel))) return original.call(this, action);
        // keep edits and deletes behind any decryption already running here
        // Find the job currently at the back of this channel's line (or a "done" placeholder).
        const previous = queues.get(channel) ?? Promise.resolve();
        // Create our job: wait for the previous one to finish (ignoring whether it failed),
        // then decrypt and pass the event on to Discord.
        const task = previous.catch(() => {}).then(async () => {
            // Default to the original event in case decryption doesn't happen.
            let next = action;
            try {
                // Only decrypt if the gate is still on.
                if (active) next = await transform(action);
            } catch {
                // Decryption failed: just use the original event.
                next = action;
            }
            // Hand the event to Discord's real dispatcher. If the gate was turned off
            // while we were waiting, send the original instead of the decrypted copy.
            return original.call(this, active ? next : action);
        });
        // Put our job at the back of this channel's line.
        queues.set(channel, task);
        // Once our job is done, remove the line entirely, but ONLY if no newer job has
        // joined behind us (otherwise we'd lose track of that newer job).
        const cleanup = () => { if (queues.get(channel) === task) queues.delete(channel); };
        // Run cleanup whether the job succeeded or failed. ("void" = we don't need the result.)
        void task.then(cleanup, cleanup);
        // Give the caller the job, so it can wait for it if it wants.
        return task;
    }

    // Swap Discord's real dispatch for our checkpoint version. From now on, every event
    // goes through our `dispatch` above first.
    dispatcher.dispatch = dispatch;
    // Hand back an "undo" function. Calling it:
    return () => {
        // 1. turns the gate off (any queued jobs will pass events through unchanged), and
        active = false;
        // 2. puts Discord's real dispatch back, but only if nobody else has replaced it
        //    since; we don't want to accidentally undo another plugin's changes.
        if (dispatcher.dispatch === dispatch) dispatcher.dispatch = original;
    };
}

// decrypt replies without needing to go into history.
export function decryptReplyPreviews(store: any, decrypt: (ciphertext: string) => Promise<string>, applies: (channelId: string) => boolean) {
    // Pattern that finds a PGP message block anywhere inside some text.
    // "+?" means "match as little as possible", so it stops at the FIRST END line.
    const armor = /-----BEGIN PGP MESSAGE-----[\s\S]+?-----END PGP MESSAGE-----/;
    // Cache of results we've already decrypted: ciphertext -> plaintext.
    const plaintext = new Map<string, string>();
    // Ciphertexts currently being decrypted (so we don't start the same job twice).
    const pending = new Set<string>();
    // Ciphertexts that failed to decrypt (so we don't keep retrying them forever).
    const failed = new Set<string>();
    // Remembers the decrypted copy we built for each original message object, so we hand
    // back the SAME copy each time instead of building a new one on every redraw.
    // A WeakMap automatically forgets entries when the original message is thrown away.
    let records = new WeakMap<object, { text: string; message: any; }>();
    // `active` is the on/off switch. `generation` is a counter that goes up whenever we
    // reset; background jobs check it so results from before a reset are ignored.
    let active = true, generation = 0;
    // List of "undo" functions, one for each store method we patch.
    const restore: (() => void)[] = [];


    // read (inner helper)
    // Given what the store returned, hand back a version with the message decrypted
    // if we can, or kick off decryption in the background if we can't yet.
    function read(entry: any, fallbackChannel?: string) {
        // Get the message out of the store's result (if there is one).
        const message = entry?.message;
        // Work out which channel it's in.
        const channelId = message?.channel_id ?? fallbackChannel;
        // If the message text is a string, try to find a PGP block inside it.
        // `ciphertext` ends up as that block, or null if there isn't one.
        const ciphertext = typeof message?.content === "string" ? message.content.match(armor)?.[0] : null;
        // Nothing to do (return the store's result untouched) if: we've been stopped,
        // there's no encrypted block, we don't know the channel, or this channel doesn't use PGP.
        if (!active || !ciphertext || !channelId || !applies(channelId)) return entry;
        // Have we already decrypted this exact ciphertext?
        const text = plaintext.get(ciphertext);
        if (text != null) {
            // Yes. See if we already built a decrypted copy of this message object.
            let record = records.get(message);
            // If not (or if the decrypted text changed), build one now.
            if (!record || record.text !== text) {
                // The fields to override: readable text, plus a flag marking it as
                // having been encrypted (other parts of the plugin can use this, e.g. for a lock icon).
                const fields = { content: text, pgpCordEncrypted: true };
                // Discord's message objects often have a `merge` method that makes a
                // modified copy properly; use it if available, otherwise do a plain copy.
                record = { text, message: typeof message.merge === "function" ? message.merge(fields) : { ...message, ...fields } };
                // Remember this copy for next time.
                records.set(message, record);
            }
            // give the preview a decrypted copy, leave the stored message alone
            return { ...entry, message: record.message };
        }
        // avoid starting the same job again on every render
        // Not decrypted yet. Start decrypting, unless it's already in progress or already failed.
        if (!pending.has(ciphertext) && !failed.has(ciphertext)) {
            // Mark it as in progress.
            pending.add(ciphertext);
            // Remember which "generation" we started in, to detect resets later.
            const started = generation;
            // Start decryption in the background. Promise.resolve().then(...) makes sure
            // it runs a moment later rather than right now, so we don't slow down the
            // current screen draw.
            void Promise.resolve().then(() => decrypt(ciphertext)).then(text => {
                // Throw the result away if we've been stopped/reset since, or if the
                // result isn't text.
                if (!active || generation !== started || typeof text !== "string") return;
                // Keep the cache from growing forever: if it has 500 entries, delete the
                // oldest one (Maps remember insertion order, so the first key is the oldest).
                if (plaintext.size >= 500) plaintext.delete(plaintext.keys().next().value!);
                // Save the decrypted text in the cache.
                plaintext.set(ciphertext, text);
                // tell the reply preview to render again with the plaintext
                // (On the redraw, `read` will find it in the cache and return the decrypted copy.)
                store.emitChange();
            }).catch(() => {
                // Decryption failed. Unless we've been stopped/reset since, remember the
                // failure so we don't keep retrying. Same 500-entry limit as the cache.
                if (active && generation === started) {
                    if (failed.size >= 500) failed.delete(failed.values().next().value!);
                    failed.add(ciphertext);
                }
            // Either way, it's no longer in progress (unless a reset already cleared it).
            }).finally(() => { if (generation === started) pending.delete(ciphertext); });
        }
        // For now, return the store's result unchanged (still encrypted). It'll update
        // after decryption finishes and the redraw happens.
        return entry;
    }

    // Patch the two store methods Discord uses to look up a message for a reply preview.
    for (const method of ["getMessage", "getMessageByReference"]) {
        // Grab the store's real method.
        const original = store?.[method];
        // If the store doesn't have this method (e.g. Discord changed it), skip it.
        if (typeof original !== "function") continue;
        // Our replacement: call the real method, then run its result through `read`.
        const wrapped = function (this: any, ...args: any[]) {
            // Get what the store would normally return.
            const entry = original.apply(this, args);
            try {
                // Work out the channel ID from the arguments. The two methods take
                // different arguments:
                //  - getMessage(channelId, ...)           -> first argument is the channel ID
                //  - getMessageByReference(reference)     -> channel ID is inside the reference
                const channelId = method === "getMessage" ? args[0] : args[0]?.channel_id ?? args[0]?.channelId;
                // Return the (possibly decrypted) version.
                return read(entry, channelId);
            // If anything goes wrong, fall back to the store's normal answer.
            } catch { return entry; }
        };
        // Install our replacement on the store.
        store[method] = wrapped;
        // Record how to undo it: put the original back, but only if nobody else has
        // replaced our version since.
        restore.push(() => { if (store[method] === wrapped) store[method] = original; });
    }
    // Controls handed back to the caller:
    return {
        // retry(): forget past failures and in-progress jobs (bumping `generation` so any
        // old background jobs get ignored), then ask Discord to redraw so everything
        // gets attempted again. Useful e.g. after the user adds a new private key.
        retry() { generation++; failed.clear(); pending.clear(); store?.emitChange?.(); },
        // stop(): shut everything down.
        stop() {
            // Turn off and invalidate any background jobs still running.
            active = false; generation++;
            // Undo the patches, newest first (reverse order of how they were applied).
            restore.reverse().forEach(unpatch => unpatch());
            // Wipe all caches and tracking so no decrypted text lingers in memory.
            plaintext.clear(); pending.clear(); failed.clear(); records = new WeakMap();
        }
    };
}

// parseLinkWhitelist
// Turns the user's "allowed link sites" setting (free-form text) into a clean list of
// domain names.
export function parseLinkWhitelist(setting: string): string[] {
    // Split the text wherever there are spaces, newlines, or commas.
    return setting.split(/[\s,]+/)
        // god i hate regex
        .map(entry => entry.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^\*?\./, ""))
        // Remove any entries that ended up empty.
        .filter(Boolean);
}

// Links to whitelisted sites, which get sent in plaintext next to the ciphertext so Discord can embed them
export function extractWhitelistedLinks(text: string, domains: string[]): string[] {
    // No allowed sites means no links to pull out.
    if (!domains.length) return [];
    // Collects the links we find.
    const links: string[] = [];
    // <url> suppresses the embed, so leave those encrypted only
    // Find every link in the text. The pattern captures three optional/required pieces:
    //   match[1] = "<"   if the link is wrapped like <https://...> (Discord's "no preview" syntax)
    //   match[2] = "||"  if the link is inside a spoiler like ||https://...||
    //   match[3] = the URL itself: "http://" or "https://" followed by characters that
    //              aren't spaces, "<", ">", or "|"
    for (const match of text.matchAll(/(<)?(\|\|)?(https?:\/\/[^\s<>|]+)/g)) {
        // The user deliberately asked for no preview, so keep this link encrypted only.
        if (match[1]) continue;
        // Strip punctuation that probably isn't part of the link, e.g. the "." in
        // "check out https://example.com." or the ")" in "(https://example.com)".
        const url = match[3].replace(/[)\].,!?'"]+$/, "");
        // Pull out just the site name (e.g. "www.youtube.com") from the URL.
        let host: string;
        // If the URL is malformed and can't be parsed, skip it.
        try { host = new URL(url).hostname.toLowerCase(); } catch { continue; }
        // Keep it only if the site is on the allowed list, either exactly ("youtube.com")
        // or as a subdomain ("www.youtube.com" ends with ".youtube.com").
        if (!domains.some(domain => host === domain || host.endsWith("." + domain))) continue;
        const link = match[2] ? `||${url}||` : url; // keep spoilered links spoilered
        // Add it, unless we've already got this exact link.
        if (!links.includes(link)) links.push(link);
    }
    // Hand back the links to send in plain view.
    return links;
}
