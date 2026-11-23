/**
 * @flaxia/mail-contract
 *
 * The single source of truth for the Flaxia Mail wire contract:
 *
 * 1. Mailbox address grammar and the reserved-local allowlist.
 * 2. The HMAC used between Flaxia Pages Functions and the Mail Worker
 *    (`x-flaxia-user-id` / `x-flaxia-ts` / `x-flaxia-sig`).
 * 3. The ECIES/AES-GCM envelope primitives shared by the Worker (wrap/encrypt)
 *    and the browser client (unwrap/decrypt).
 *
 * The module is pure WebCrypto and Web standard APIs: no Cloudflare, Node or
 * DOM imports. It runs in Workers, browsers and Node 22+.
 *
 * Protocol specification: `flaxia/docs/mail.md` §5 (internal API), §6.2 (ECIES),
 * §7 and §11.2 (addresses).
 */
// ---------------------------------------------------------------------------
// Mail addresses (docs/mail.md §7, §11.2)
// ---------------------------------------------------------------------------
export const MAIL_DOMAIN = 'flaxia.app';
export const USERNAME_PATTERN = /^[A-Za-z0-9_]{1,20}$/;
/**
 * Operational locals must never become user mailboxes, and lookalikes such as
 * root@/hostmaster@ invite impersonation. This is the single source of truth
 * for the SPA, Pages proxy and Mail Worker.
 */
export const RESERVED_LOCALS = new Set([
    'admin',
    'administrator',
    'abuse',
    'api',
    'app',
    'auth',
    'billing',
    'bounce',
    'bounces',
    'contact',
    'dkim',
    'dmarc',
    'dns',
    'donotreply',
    'flaxia',
    'help',
    'hostmaster',
    'info',
    'legal',
    'mail',
    'mailerdaemon',
    'marketing',
    'news',
    'no_reply',
    'noreply',
    'postmaster',
    'press',
    'privacy',
    'registrar',
    'root',
    'sales',
    'security',
    'spam',
    'spf',
    'status',
    'support',
    'team',
    'webmaster',
    'www',
]);
export function normalizeMailAddress(address) {
    return address.trim().toLowerCase();
}
export function primaryAddressForUsername(username, domain = MAIL_DOMAIN) {
    const local = username.trim().toLowerCase();
    if (!USERNAME_PATTERN.test(local))
        throw new Error('mail_invalid_username');
    if (RESERVED_LOCALS.has(local))
        throw new Error('mail_reserved');
    return `${local}@${domain}`;
}
export function isReservedLocal(local) {
    return RESERVED_LOCALS.has(local.trim().toLowerCase());
}
export function isValidMailAddress(address) {
    const normalized = normalizeMailAddress(address);
    const at = normalized.lastIndexOf('@');
    if (at < 1)
        return false;
    const local = normalized.slice(0, at);
    const domain = normalized.slice(at + 1);
    if (!/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$/.test(local))
        return false;
    return domain === MAIL_DOMAIN || domain.endsWith(`.${MAIL_DOMAIN}`);
}
// ---------------------------------------------------------------------------
// WebCrypto primitives (docs/mail.md §5)
// ---------------------------------------------------------------------------
const encoder = new TextEncoder();
function toHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');
}
export async function sha256Hex(value) {
    return toHex(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
}
export async function hmacHex(secret, message) {
    const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
    return toHex(signature);
}
/** Length-independent byte compare so a wrong signature cannot be brute-forced by timing. */
export function signatureEquals(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}
/** Maximum accepted clock skew for `x-flaxia-ts`, in seconds. */
export const MAIL_INTERNAL_MAX_SKEW_SECONDS = 300;
/**
 * Sign a trusted Pages -> Mail Worker call. The signature binds the
 * authenticated user id, the timestamp, the HTTP method, the exact
 * path+query, and the body hash so a captured signature cannot be replayed
 * against another endpoint.
 *
 * Returns `null` when no shared secret is configured (callers must fail
 * closed rather than send an unsigned request).
 */
export async function signMailInternal(env, userId, method, path, body = '') {
    const secret = env.MAIL_INTERNAL_SECRET;
    if (!secret)
        return null;
    const ts = String(Math.floor(Date.now() / 1000));
    const target = new URL(`https://flaxia-mail${path}`);
    const message = `${userId}.${ts}.${method.toUpperCase()}.${target.pathname}${target.search}.${await sha256Hex(body)}`;
    return {
        'x-flaxia-user-id': userId,
        'x-flaxia-ts': ts,
        'x-flaxia-sig': await hmacHex(secret, message),
    };
}
/**
 * Verify an internal call. Returns the authenticated user id, or `null` for a
 * missing/expired/wrong signature. The Worker never trusts a bare user id.
 */
export async function verifyMailInternal(env, req, body) {
    const userId = req.headers.get('x-flaxia-user-id');
    const ts = req.headers.get('x-flaxia-ts');
    const sig = req.headers.get('x-flaxia-sig');
    const secret = env.MAIL_INTERNAL_SECRET;
    if (!userId || !ts || !sig || !secret)
        return null;
    // Reject a non-numeric timestamp explicitly: `NaN > 300` is false, which
    // would otherwise skip the skew check entirely.
    const timestamp = Number(ts);
    if (!Number.isFinite(timestamp) || Math.abs(Date.now() / 1000 - timestamp) > MAIL_INTERNAL_MAX_SKEW_SECONDS) {
        return null;
    }
    const url = new URL(req.url);
    // Bind the signature to the exact call, not just the user + timestamp.
    const target = `${req.method.toUpperCase()}.${url.pathname}${url.search}.${await sha256Hex(body)}`;
    const expected = await hmacHex(secret, `${userId}.${ts}.${target}`);
    return signatureEquals(expected, sig) ? userId : null;
}
// ---------------------------------------------------------------------------
// ECIES envelope crypto (docs/mail.md §6.2)
// ---------------------------------------------------------------------------
const subtle = globalThis.crypto.subtle;
export function wrapInfo(messageId, recipientAddress) {
    return `flaxia.mail.wrap.v1:${messageId}:${recipientAddress}`;
}
export function attachmentKeyInfo(attachmentId) {
    return `flaxia.mail.attachment.v1:${attachmentId}`;
}
export function metaInfo(messageId) {
    return `flaxia.mail.meta.v1:${messageId}`;
}
export function subjectInfo(messageId) {
    return `flaxia.mail.subject.v1:${messageId}`;
}
export function fromNameInfo(messageId) {
    return `flaxia.mail.from-name.v1:${messageId}`;
}
export function attachmentNameInfo(attachmentId) {
    return `flaxia.mail.attachment-name.v1:${attachmentId}`;
}
export function payloadInfo(messageId) {
    return `flaxia.mail.payload.v1:${messageId}`;
}
export function encodeB64(bytes) {
    let binary = '';
    for (const x of bytes)
        binary += String.fromCharCode(x);
    return btoa(binary);
}
export function decodeB64(value) {
    const binary = atob(value);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++)
        out[i] = binary.charCodeAt(i);
    return out;
}
/** Worker-side alias kept for the existing Worker call sites. */
export const b64encode = encodeB64;
/** Worker-side alias kept for the existing Worker call sites. */
export const b64decode = decodeB64;
async function importSpki(spkiB64) {
    return (await subtle.importKey('spki', decodeB64(spkiB64), { name: 'ECDH', namedCurve: 'P-256' }, true, 
    // ECDH public keys must be imported with no usages (WebCrypto spec); the
    // private key supplies the usages in deriveBits/deriveKey.
    []));
}
async function importPkcs8(pkcs8B64) {
    return (await subtle.importKey('pkcs8', decodeB64(pkcs8B64), { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']));
}
/**
 * Validate a published identity key before storing it. An invalid or
 * non-P-256 SPKI would silently break every future inbound message for the
 * mailbox, so activation must fail closed.
 */
export async function isValidP256SpkiB64(value) {
    if (typeof value !== 'string' || value.length === 0 || value.length > 512)
        return false;
    try {
        const bytes = decodeB64(value);
        if (bytes.length === 0 || bytes.length > 256)
            return false;
        await subtle.importKey('spki', bytes, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
        return true;
    }
    catch {
        return false;
    }
}
async function deriveWrapKey(ephemeralPrivate, recipientPublic, info) {
    const shared = await subtle.deriveBits({ name: 'ECDH', public: recipientPublic }, ephemeralPrivate, 256);
    const hkdfBase = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    return (await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: encoder.encode(''), info: encoder.encode(info) }, hkdfBase, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']));
}
/** Wrap a 32-byte content key for one recipient. */
export async function wrapContentKey(contentKey, recipientSpkiB64, messageId, recipientAddress) {
    if (contentKey.length !== 32)
        throw new Error('content key must be 32 bytes');
    const ephemeral = (await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
        'deriveKey',
        'deriveBits',
    ]));
    const recipientPublic = await importSpki(recipientSpkiB64);
    const wrapKey = await deriveWrapKey(ephemeral.privateKey, recipientPublic, wrapInfo(messageId, recipientAddress));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = encoder.encode(wrapInfo(messageId, recipientAddress));
    const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad }, wrapKey, contentKey);
    const ephSpki = new Uint8Array(await subtle.exportKey('spki', ephemeral.publicKey));
    return {
        ephemeralPublicKey: encodeB64(ephSpki),
        iv: encodeB64(iv),
        wrappedContentKey: encodeB64(new Uint8Array(ciphertext)),
    };
}
/** Unwrap a content key with the recipient's private key. */
export async function unwrapContentKey(wrapped, recipientPkcs8B64, messageId, recipientAddress) {
    const privateKey = await importPkcs8(recipientPkcs8B64);
    const ephemeralPublic = await importSpki(wrapped.ephemeralPublicKey);
    const wrapKey = await deriveWrapKey(privateKey, ephemeralPublic, wrapInfo(messageId, recipientAddress));
    const aad = encoder.encode(wrapInfo(messageId, recipientAddress));
    const plaintext = await subtle.decrypt({ name: 'AES-GCM', iv: decodeB64(wrapped.iv), additionalData: aad }, wrapKey, decodeB64(wrapped.wrappedContentKey));
    return new Uint8Array(plaintext);
}
/** Derive the per-attachment key from the content key (HKDF). */
export async function deriveAttachmentKey(contentKey, attachmentId) {
    const hkdfBase = await subtle.importKey('raw', contentKey, 'HKDF', false, ['deriveBits']);
    const bits = await subtle.deriveBits({
        name: 'HKDF',
        hash: 'SHA-256',
        salt: encoder.encode(''),
        info: encoder.encode(attachmentKeyInfo(attachmentId)),
    }, hkdfBase, 256);
    return new Uint8Array(bits);
}
/** Encrypt a payload once with the content key. */
export async function encryptPayload(contentKey, plaintext, messageId) {
    const key = await subtle.importKey('raw', contentKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = encoder.encode(`flaxia.mail.payload.v1:${messageId}`);
    const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad }, key, plaintext);
    return { iv: encodeB64(iv), ciphertext: new Uint8Array(ciphertext) };
}
/** Encrypt arbitrary bytes with AES-256-GCM and an explicit AAD. */
export async function encryptBytes(keyBytes, plaintext, aad) {
    const key = await subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: encoder.encode(aad) }, key, plaintext);
    return { iv: encodeB64(iv), ciphertext: new Uint8Array(ciphertext) };
}
/** Encrypt a UTF-8 string; returns an `iv.ciphertext` envelope. */
export async function encryptString(keyBytes, plaintext, info) {
    const encrypted = await encryptBytes(keyBytes, encoder.encode(plaintext), info);
    return `${encrypted.iv}.${encodeB64(encrypted.ciphertext)}`;
}
export async function decryptPayload(contentKey, ivB64, ciphertext, messageId) {
    const key = await subtle.importKey('raw', contentKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
    const aad = encoder.encode(`flaxia.mail.payload.v1:${messageId}`);
    const plaintext = await subtle.decrypt({ name: 'AES-GCM', iv: decodeB64(ivB64), additionalData: aad }, key, ciphertext);
    return new Uint8Array(plaintext);
}
/** Decrypt bytes sealed with AES-256-GCM + explicit AAD. */
export async function decryptBytes(keyBytes, ivB64, ciphertext, aad) {
    const key = await subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
    const plaintext = await subtle.decrypt({ name: 'AES-GCM', iv: decodeB64(ivB64), additionalData: encoder.encode(aad) }, key, ciphertext);
    return new Uint8Array(plaintext);
}
/** Decrypt an `iv.ciphertext` envelope produced by the Mail Worker. */
export async function decryptString(keyBytes, envelope, info) {
    const [iv, ciphertext] = envelope.split('.', 2);
    if (!iv || !ciphertext)
        throw new Error('invalid encrypted string');
    const plaintext = await decryptBytes(keyBytes, iv, decodeB64(ciphertext), info);
    return new TextDecoder().decode(plaintext);
}
/** Seal attachment bytes with the per-attachment key derived from the content key. */
export async function encryptAttachment(contentKey, attachmentId, plaintext) {
    const key = await deriveAttachmentKey(contentKey, attachmentId);
    try {
        return await encryptBytes(key, plaintext, attachmentKeyInfo(attachmentId));
    }
    finally {
        key.fill(0);
    }
}
/** Decrypt an attachment with the key derived from the message content key. */
export async function decryptAttachment(contentKey, attachmentId, ivB64, ciphertext) {
    const key = await deriveAttachmentKey(contentKey, attachmentId);
    return decryptBytes(key, ivB64, ciphertext, attachmentKeyInfo(attachmentId));
}
// ---------------------------------------------------------------------------
// Client-sealed send envelope (docs/mail.md §6.2, §9.2)
// ---------------------------------------------------------------------------
export const MAX_SEND_BYTES = 10 * 1024 * 1024;
export const MAX_ATTACHMENTS = 20;
export const MAX_RECIPIENTS = 20;
function normalizeRecipient(address) {
    return address.trim().toLowerCase();
}
export function uniqueAddresses(lists) {
    const set = new Set();
    for (const list of lists) {
        for (const address of list ?? []) {
            const normalized = normalizeRecipient(address);
            if (normalized)
                set.add(normalized);
        }
    }
    return [...set];
}
export function isFlaxiaAddress(address, domain = MAIL_DOMAIN) {
    return address.endsWith(`@${domain}`);
}
/**
 * Seal a composed message into the wire envelope. `keys` must cover every
 * unique recipient plus the sender. Purely local: no network, no vault.
 *
 * `wrapAddresses` restricts which addresses get a wrapped content key.
 * The external/TLS path seals only a sender-retained Sent copy (external
 * recipients have no Flaxia key); drafts do the same. Without it every
 * recipient address needs a key.
 */
export async function sealEnvelope(fields, keys, context = {}, options) {
    const messageId = context.messageId ?? crypto.randomUUID();
    const keyByAddress = new Map(keys.map((key) => [normalizeRecipient(key.address), key]));
    const recipients = uniqueAddresses([fields.to, fields.cc, fields.bcc]);
    const contentKey = crypto.getRandomValues(new Uint8Array(32));
    try {
        const metaAttachments = [];
        const attachments = [];
        let totalBytes = 0;
        for (const attachment of fields.attachments.slice(0, MAX_ATTACHMENTS)) {
            const id = crypto.randomUUID();
            totalBytes += attachment.bytes.byteLength;
            if (totalBytes > MAX_SEND_BYTES)
                throw new Error('mail_too_large');
            const sealed = await encryptAttachment(contentKey, id, attachment.bytes);
            const filenameEnc = await encryptString(contentKey, attachment.name, attachmentNameInfo(id));
            attachments.push({
                id,
                iv: sealed.iv,
                ciphertext: encodeB64(sealed.ciphertext),
                filename_enc: filenameEnc,
                content_type: attachment.type || 'application/octet-stream',
                size_bytes: attachment.bytes.byteLength,
            });
            metaAttachments.push({
                id,
                filename: attachment.name,
                content_type: attachment.type || 'application/octet-stream',
                size_bytes: attachment.bytes.byteLength,
            });
        }
        const metadata = {
            subject: fields.subject,
            from_name: context.fromName ?? '',
            snippet: fields.text.slice(0, 160),
            to: fields.to,
            cc: fields.cc,
            attachments: metaAttachments,
        };
        const payloadBytes = new TextEncoder().encode(JSON.stringify({ text: fields.text }));
        const payload = await encryptPayload(contentKey, payloadBytes, messageId);
        totalBytes += payload.ciphertext.byteLength;
        if (totalBytes > MAX_SEND_BYTES)
            throw new Error('mail_too_large');
        const subjectEnc = await encryptString(contentKey, fields.subject, subjectInfo(messageId));
        const fromNameEnc = await encryptString(contentKey, context.fromName ?? '', fromNameInfo(messageId));
        const metaEnc = await encryptString(contentKey, JSON.stringify(metadata), metaInfo(messageId));
        const wireKeys = [];
        const wrapTargets = options?.wrapAddresses === undefined
            ? [...new Set([normalizeRecipient(fields.from), ...recipients])]
            : [...new Set(options.wrapAddresses.map(normalizeRecipient))];
        // Sending to yourself makes `from` a recipient too; wrap once per address.
        for (const address of wrapTargets) {
            const key = keyByAddress.get(address);
            if (!key)
                throw new Error('mail_recipient_key_missing');
            const wrapped = await wrapContentKey(contentKey, key.public_key, messageId, address);
            wireKeys.push({
                address,
                key_version: key.key_version,
                ephemeral_public_key: wrapped.ephemeralPublicKey,
                iv: wrapped.iv,
                wrapped_content_key: wrapped.wrappedContentKey,
            });
        }
        return {
            message_id: messageId,
            ...(context.threadId ? { thread_id: context.threadId } : {}),
            ...(context.inReplyToHash ? { in_reply_to_hash: context.inReplyToHash } : {}),
            from: normalizeRecipient(fields.from),
            to: fields.to.map(normalizeRecipient),
            cc: fields.cc.map(normalizeRecipient),
            bcc: fields.bcc.map(normalizeRecipient),
            subject_enc: subjectEnc,
            from_name_enc: fromNameEnc,
            meta_enc: metaEnc,
            payload: { iv: payload.iv, ciphertext: encodeB64(payload.ciphertext) },
            attachments,
            keys: wireKeys,
        };
    }
    finally {
        contentKey.fill(0);
    }
}
