import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { stripTypeScriptTypes } from "node:module";
import * as openpgp from "openpgp";
import { createDispatchGate, decryptArmoredContent, decryptReplyPreviews, selectRecipients } from "./core.ts";

const armor = "-----BEGIN PGP MESSAGE-----\nciphertext\n-----END PGP MESSAGE-----";
const action = (type, content = armor) => ({ type, message: { id: "message", channel_id: "group", content } });
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };

test("group selection excludes members without keys and supports self-only", () => {
    assert.deepEqual(selectRecipients(["friend", "other"], { friend: "key" }, true, "known"), ["friend"]);
    assert.deepEqual(selectRecipients(["friend", "other"], { friend: "key" }, true, "self"), []);
    assert.deepEqual(selectRecipients(["other"], {}, true, "known"), []);
    assert.deepEqual(selectRecipients(["friend"], {}, false, "self"), ["friend"]);
});

test("notification consumers receive plaintext on the first MESSAGE_CREATE", async () => {
    const seen = [];
    const dispatcher = { dispatch: value => { seen.push(value); } };
    const stop = createDispatchGate(dispatcher, {
        applies: () => true,
        prepare: async message => ({ ...message, content: "hello friend" })
    });
    const encrypted = action("MESSAGE_CREATE");
    await dispatcher.dispatch(encrypted);
    assert.equal(seen[0].message.content, "hello friend");
    assert.equal(encrypted.message.content, armor);
    stop();
});

test("decrypted history retains order and all history metadata", async () => {
    let delivered;
    const dispatcher = { dispatch: value => { delivered = value; } };
    const stop = createDispatchGate(dispatcher, {
        applies: message => message.channel_id === "group",
        prepare: async message => ({ ...message, content: `clear:${message.id}` })
    });
    await dispatcher.dispatch({ type: "LOAD_MESSAGES_SUCCESS", channelId: "group", hasMoreBefore: true, messages: [
        { id: "newer", content: armor }, { id: "older", content: armor }
    ] });
    assert.deepEqual(delivered.messages.map(m => m.content), ["clear:newer", "clear:older"]);
    assert.equal(delivered.hasMoreBefore, true);
    stop();
});

test("edits and deletion cannot overtake a message being decrypted", async () => {
    const wait = deferred(), seen = [];
    const dispatcher = { dispatch: value => { seen.push(value); } };
    const stop = createDispatchGate(dispatcher, {
        applies: () => true,
        prepare: async message => { await wait.promise; return { ...message, content: "clear" }; }
    });
    const create = dispatcher.dispatch(action("MESSAGE_CREATE"));
    const edit = dispatcher.dispatch(action("MESSAGE_UPDATE", "new edit"));
    const remove = dispatcher.dispatch({ type: "MESSAGE_DELETE", channelId: "group", id: "message" });
    dispatcher.dispatch({ type: "UNRELATED_ACTION" });
    assert.deepEqual(seen.map(a => a.type), ["UNRELATED_ACTION"]);
    wait.resolve();
    await Promise.all([create, edit, remove]);
    assert.deepEqual(seen.map(a => a.type), ["UNRELATED_ACTION", "MESSAGE_CREATE", "MESSAGE_UPDATE", "MESSAGE_DELETE"]);
    stop();
});

test("undecryptable messages, timeouts and stopping preserve original ciphertext", async () => {
    for (const mode of ["failure", "timeout", "stop"]) {
        const wait = deferred(), seen = [];
        const dispatcher = { dispatch: value => { seen.push(value); } };
        const original = dispatcher.dispatch;
        const stop = createDispatchGate(dispatcher, {
            applies: () => true,
            prepare: async () => { if (mode === "failure") throw new Error("not a recipient"); return wait.promise; }
        }, 10);
        const pending = dispatcher.dispatch(action("MESSAGE_CREATE"));
        if (mode === "stop") stop();
        await pending;
        assert.equal(seen[0].message.content, armor);
        stop();
        assert.equal(dispatcher.dispatch, original);
        wait.resolve({ content: "late plaintext" });
    }
});

test("real OpenPGP messages work for selected recipients and after a fresh read", async () => {
    const generate = name => openpgp.generateKey({ type: "ecc", curve: "curve25519Legacy", userIDs: [{ name }], format: "armored" });
    const [alice, bob, other] = await Promise.all([generate("Alice"), generate("Bob"), generate("Other")]);
    const privateKey = await openpgp.readPrivateKey({ armoredKey: alice.privateKey });
    const source = readFileSync(new URL("./index.tsx", import.meta.url), "utf8");
    const helper = source.slice(source.indexOf("async function encryptFor"), source.indexOf("\nconst maxMessageLength"));
    const encryptFor = new Function("openpgp", "theirKeys", "getPrivateKey", stripTypeScriptTypes(helper) + "\nreturn encryptFor;")(openpgp, { bob: bob.publicKey }, async () => privateKey);
    const decrypt = async (armoredMessage, armoredKey) => (await openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage }),
        decryptionKeys: await openpgp.readPrivateKey({ armoredKey })
    })).data;
    const ciphertext = await encryptFor(["bob"], "hello 🔐\nreadable history");
    assert.equal(await decrypt(ciphertext, alice.privateKey), "hello 🔐\nreadable history");
    assert.equal(await decrypt(ciphertext, bob.privateKey), "hello 🔐\nreadable history");
    await assert.rejects(decrypt(ciphertext, other.privateKey));
    const selfOnly = await encryptFor([], "just me");
    assert.equal(await decrypt(selfOnly, alice.privateKey), "just me");
    await assert.rejects(decrypt(selfOnly, bob.privateKey));
    await assert.rejects(decrypt(selfOnly, other.privateKey));
});

test("send hook encrypts self-only text, blocks disabled attachments and never falls back on error", async () => {
    const source = readFileSync(new URL("./index.tsx", import.meta.url), "utf8");
    const hook = source.slice(source.indexOf("const prepareSend:"), source.indexOf("// Keep edits encrypted too"));
    let fail = false, selected = [];
    const context = {
        settings: { store: { encryptionEnabled: true, allowPlainAttachments: false } },
        recipientsFor: () => selected,
        running: true,
        ChannelStore: { getChannel: () => ({ isDM: () => false }) },
        showToast: () => {},
        PUBLIC_KEY_REGEX: /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]+?-----END PGP PUBLIC KEY BLOCK-----/,
        KEY_REQUEST_STRING: "[PGPcord key request]",
        theirKeys: {},
        console: { error() {} },
        encryptInPlace: async (ids, message) => {
            assert.deepEqual(ids, []);
            if (fail) throw new Error("bad private key");
            message.content = "ciphertext";
            return true;
        }
    };
    const send = new Function("context", `with (context) { ${stripTypeScriptTypes(hook)}; return onBeforeMessageSend; }`)(context);
    const text = { content: "only me" };
    await send("group", text, {}, {});
    assert.equal(text.content, "ciphertext");
    const attachmentOnly = { content: "" };
    assert.equal((await send("group", attachmentOnly, {}, { hasAttachments: true })).cancel, true);
    fail = true;
    const draft = { content: "do not leak" };
    assert.equal((await send("group", draft, {}, {})).cancel, true);
    assert.equal(draft.content, "do not leak");
    selected = null;
    assert.equal(await send("guild", draft, {}, {}), undefined);
});

test("late fallback decryption does not overwrite a newer edit", async () => {
    const source = readFileSync(new URL("./index.tsx", import.meta.url), "utf8");
    const helper = source.slice(source.indexOf("async function decryptLater"), source.indexOf("// Swaps ciphertext for plaintext"));
    const wait = deferred(), updates = [], badges = [];
    const context = {
        openpgp: { readMessage: async () => ({}), decrypt: async () => wait.promise },
        getPrivateKey: async () => ({}),
        decrypting: new Set(), running: true, lifecycle: 0,
        decryptionErrors: new Map(), notifyBadge() {},
        decryptCiphertext: async () => (await wait.promise).data,
        cachePlaintext() {},
        setEncrypted: (...args) => badges.push(args),
        MessageStore: { getMessage: () => ({ content: "newer edit" }) },
        PGP_MESSAGE_REGEX: /-----BEGIN PGP MESSAGE-----[\s\S]+?-----END PGP MESSAGE-----/,
        updateMessage: (...args) => updates.push(args), console
    };
    const decrypt = new Function("context", `with (context) { ${stripTypeScriptTypes(helper)}; return decryptLater; }`)(context);
    const pending = decrypt("group", "message", armor);
    wait.resolve({ data: "old plaintext" });
    await pending;
    assert.deepEqual(updates, []);
    assert.deepEqual(badges, []);
});


test("history decryption retries after the store commits a batch", async () => {
    const source = readFileSync(new URL("./index.tsx", import.meta.url), "utf8");
    const helper = source.slice(source.indexOf("async function decryptLater"), source.indexOf("// Swaps ciphertext for plaintext"));
    let current;
    const context = {
        decrypting: new Set(), running: true, lifecycle: 0,
        decryptionErrors: new Map(), notifyBadge() {},
        decryptCiphertext: async () => "history plaintext",
        setEncrypted() {},
        MessageStore: { getMessage: () => current },
        PGP_MESSAGE_REGEX: /-----BEGIN PGP MESSAGE-----[\s\S]+?-----END PGP MESSAGE-----/,
        updateMessage: (_channel, _id, fields) => { current = { ...current, ...fields }; },
        setTimeout
    };
    const { decryptLater, repairHistory } = new Function("context", `with (context) { ${stripTypeScriptTypes(helper)}; return { decryptLater, repairHistory }; }`)(context);
    await decryptLater("group", "old", armor);
    assert.equal(current, undefined);
    current = { id: "old", content: armor };
    repairHistory("group", [{ id: "old" }]);
    await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(current.content, "history plaintext");
});

test("messages that were encrypted twice decrypt to text with a bounded layer count", async () => {
    const pair = await openpgp.generateKey({ type: "ecc", curve: "curve25519Legacy", userIDs: [{ name: "History test" }], format: "armored" });
    const key = await openpgp.readPrivateKey({ armoredKey: pair.privateKey });
    const encrypt = async text => openpgp.encrypt({ message: await openpgp.createMessage({ text }), encryptionKeys: key.toPublic() });
    const inner = await encrypt("original history text");
    const outer = await encrypt(inner);
    const plaintext = await decryptArmoredContent(outer, async armoredMessage => (await openpgp.decrypt({
        message: await openpgp.readMessage({ armoredMessage }), decryptionKeys: key
    })).data);
    assert.equal(plaintext, "original history text");
    let attempts = 0;
    await assert.rejects(decryptArmoredContent(armor, async () => { attempts++; return armor; }), /three/);
    assert.equal(attempts, 3);
});

test("history events with a snake-case channel ID still decrypt", async () => {
    let delivered;
    const dispatcher = { dispatch: value => { delivered = value; } };
    const stop = createDispatchGate(dispatcher, {
        applies: message => message.channel_id === "group",
        prepare: async message => ({ ...message, content: "history plaintext" })
    });
    await dispatcher.dispatch({ type: "LOAD_MESSAGES_SUCCESS", channel_id: "group", messages: [{ id: "old", content: armor }] });
    assert.equal(delivered.messages[0].content, "history plaintext");
    stop();
});


test("DM self-only fallback selects saved keys without waiting on unknown recipients", () => {
    const source = readFileSync(new URL("./index.tsx", import.meta.url), "utf8");
    const helper = source.slice(source.indexOf("function recipientsFor("), source.indexOf("async function setGroupMode"));
    const settings = { store: { selfOnlyDM: true, groupMode: "known" } };
    const theirKeys = {};
    const recipients = new Function("getRecipientIds", "ChannelStore", "selectRecipients", "theirKeys", "groupModes", "settings", stripTypeScriptTypes(helper) + "return recipientsFor;")(
        () => ["friend"], { getChannel: () => ({ isGroupDM: () => false }) }, selectRecipients, theirKeys, {}, settings
    );
    assert.deepEqual(recipients("dm"), []);
    theirKeys.friend = "public key";
    assert.deepEqual(recipients("dm"), ["friend"]);
    delete theirKeys.friend;
    settings.store.selfOnlyDM = false;
    assert.deepEqual(recipients("dm"), ["friend"]);
});


test("search result groups decrypt before delivery to the search store", async () => {
    const delivered = [];
    const dispatcher = { dispatch: event => delivered.push(event) };
    const stop = createDispatchGate(dispatcher, {
        applies: message => message.channel_id === "group",
        prepare: async message => ({ ...message, content: message.content === armor ? "search plaintext" : message.content })
    });
    const payload = { type: "SEARCH_MESSAGES_SUCCESS", searchId: "search", data: {
        total_results: 8121,
        messages: [
            [{ id: "hit", channel_id: "group", content: armor, hit: true }, { id: "context", channel_id: "group", content: "context", hit: false }],
            [{ id: "other", channel_id: "server", content: armor, hit: true }]
        ]
    } };
    await dispatcher.dispatch(payload);
    assert.equal(delivered[0].data.messages[0][0].content, "search plaintext");
    assert.equal(delivered[0].data.messages[0][0].hit, true);
    assert.equal(delivered[0].data.messages[0][1].content, "context");
    assert.equal(delivered[0].data.messages[1][0].content, armor);
    assert.equal(delivered[0].data.total_results, 8121);
    assert.equal(payload.data.messages[0][0].content, armor);
    stop();
});

test("top-level search batches and subsequent clears preserve ordering", async () => {
    const wait = deferred(), delivered = [];
    const dispatcher = { dispatch: event => delivered.push(event) };
    const stop = createDispatchGate(dispatcher, {
        applies: () => true,
        prepare: async message => { await wait.promise; return { ...message, content: "clear" }; }
    });
    const results = dispatcher.dispatch({ type: "SEARCH_MESSAGES_SUCCESS", searchId: "search", messages: [[{ id: "hit", channel_id: "group", content: armor }]] });
    const clear = dispatcher.dispatch({ type: "SEARCH_MESSAGES_CLEAR", searchId: "search" });
    wait.resolve();
    await Promise.all([results, clear]);
    assert.equal(delivered[0].messages[0][0].content, "clear");
    assert.equal(delivered[1].type, "SEARCH_MESSAGES_CLEAR");
    stop();
});


test("images and other uploads remain unchanged alongside encrypted text", async () => {
    const source = readFileSync(new URL("./index.tsx", import.meta.url), "utf8");
    const hook = source.slice(source.indexOf("const prepareSend:"), source.indexOf("// Keep edits encrypted too"));
    let encrypted = 0;
    const context = {
        settings: { store: { encryptionEnabled: true, allowPlainAttachments: true } },
        recipientsFor: () => ["friend"], running: true,
        theirKeys: { friend: "key" },
        showToast() {}, console,
        PUBLIC_KEY_REGEX: /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]+?-----END PGP PUBLIC KEY BLOCK-----/,
        KEY_REQUEST_STRING: "[PGPcord key request]",
        encryptInPlace: async (_ids, message) => { encrypted++; message.content = armor; return true; }
    };
    const send = new Function("context", `with (context) { ${stripTypeScriptTypes(hook)}; return onBeforeMessageSend; }`)(context);
    const uploads = [{ filename: "photo.png", uploadId: "upload", description: "caption" }];
    const options = { uploads };
    const text = { content: "private accompanying text" };
    assert.equal(await send("group", text, options, { hasAttachments: true }), undefined);
    assert.equal(text.content, armor);
    assert.equal(options.uploads, uploads);
    assert.deepEqual(uploads, [{ filename: "photo.png", uploadId: "upload", description: "caption" }]);
    assert.equal(await send("group", { content: "" }, { uploads }, { hasAttachments: true }), undefined);
    assert.equal(encrypted, 1);
    context.settings.store.allowPlainAttachments = false;
    assert.equal((await send("group", { content: "" }, { uploads }, { hasAttachments: true })).cancel, true);
});

test("plaintext replies to encrypted messages still pass through preparation", async () => {
    const delivered = [];
    const dispatcher = { dispatch: event => delivered.push(event) };
    const stop = createDispatchGate(dispatcher, {
        applies: message => message.channel_id === "dm",
        prepare: async message => ({ ...message, referenced_message: { ...message.referenced_message, content: "quoted plaintext" } })
    });
    await dispatcher.dispatch({ type: "MESSAGE_CREATE", message: { id: "reply", channel_id: "dm", content: "plain reply", referenced_message: { id: "orig", channel_id: "dm", content: armor } } });
    assert.equal(delivered[0].message.referenced_message.content, "quoted plaintext");
    assert.equal(delivered[0].message.content, "plain reply");
    stop();
});


const settle = () => new Promise(resolve => setImmediate(resolve));

test("reply previews decrypt without loading history or changing stored ciphertext", async () => {
    const message = { content: armor };
    const entry = { state: 0, message };
    let calls = 0, updates = 0;
    const store = { getMessage: () => entry, getMessageByReference: () => entry, emitChange: () => updates++ };
    const original = store.getMessage;
    const preview = decryptReplyPreviews(store, async () => { calls++; return "quoted plaintext"; }, id => id === "group");
    assert.equal(store.getMessage("group"), entry);
    store.getMessageByReference({ channel_id: "group" });
    await settle();
    const decrypted = store.getMessage("group");
    assert.equal(decrypted.message.content, "quoted plaintext");
    assert.equal(decrypted.message.pgpCordEncrypted, true);
    assert.equal(store.getMessageByReference({ channel_id: "group" }).message, decrypted.message);
    assert.equal(message.content, armor);
    assert.equal(calls, 1);
    assert.equal(updates, 1);
    preview.stop();
    assert.equal(store.getMessage, original);
});

test("reply previews retry missing keys and preserve Discord message models", async () => {
    let ready = false, calls = 0;
    const message = { content: armor, merge: fields => ({ ...fields, model: true }) };
    const store = { getMessage: () => ({ state: 0, message }), emitChange() {} };
    const preview = decryptReplyPreviews(store, async () => {
        calls++;
        if (!ready) throw new Error("Missing key");
        return "decrypted";
    }, id => id === "group");
    store.getMessage("elsewhere");
    assert.equal(calls, 0);
    store.getMessage("group");
    await settle();
    store.getMessage("group");
    await settle();
    assert.equal(calls, 1);
    ready = true;
    preview.retry();
    store.getMessage("group");
    await settle();
    assert.equal(store.getMessage("group").message.model, true);
    assert.equal(calls, 2);
    preview.stop();
});

test("stopping reply decryption ignores late results and handles unloaded replies", async () => {
    const waiting = deferred();
    let entry, updates = 0;
    const store = { getMessage: () => entry, emitChange: () => updates++ };
    const preview = decryptReplyPreviews(store, () => waiting.promise, () => true);
    assert.equal(store.getMessage("group"), undefined);
    entry = { state: 1 };
    assert.equal(store.getMessage("group"), entry);
    entry = { state: 0, message: { content: armor } };
    store.getMessage("group");
    await Promise.resolve();
    preview.stop();
    waiting.resolve("plaintext");
    await settle();
    assert.equal(updates, 0);
    assert.equal(store.getMessage("group"), entry);
});

test("whitelisted links are picked out to be sent alongside the ciphertext", async () => {
    const { parseLinkWhitelist, extractWhitelistedLinks } = await import("./core.ts");
    const domains = parseLinkWhitelist("youtube.com, https://klipy.com/, *.youtu.be\n");
    assert.deepEqual(domains, ["youtube.com", "klipy.com", "youtu.be"]);
    assert.deepEqual(
        extractWhitelistedLinks("watch https://www.youtube.com/watch?v=abc. and https://evil.example/x https://klipy.com/gifs/cat", domains),
        ["https://www.youtube.com/watch?v=abc", "https://klipy.com/gifs/cat"]
    );
    assert.deepEqual(extractWhitelistedLinks("<https://youtube.com/a> ||https://youtu.be/b|| https://notyoutube.com/c https://youtube.com.evil.example/d", domains), ["||https://youtu.be/b||"]);
    assert.deepEqual(extractWhitelistedLinks("https://youtube.com/a https://youtube.com/a", domains), ["https://youtube.com/a"]);
    assert.deepEqual(extractWhitelistedLinks("https://youtube.com/a", []), []);
});
