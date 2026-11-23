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
/**
 * Version of the wire contract. Sent as `x-flaxia-contract` on every internal
 * call. The Worker rejects a mismatch with `mail_contract_mismatch` so a Pages
 * deploy cannot silently sign with an older address/HMAC/crypto contract than
 * the deployed Worker.
 */
export declare const MAIL_CONTRACT_VERSION = "0.1.1";
export declare const MAIL_DOMAIN = "flaxia.app";
export declare const USERNAME_PATTERN: RegExp;
/**
 * Operational locals must never become user mailboxes, and lookalikes such as
 * root@/hostmaster@ invite impersonation. This is the single source of truth
 * for the SPA, Pages proxy and Mail Worker.
 */
export declare const RESERVED_LOCALS: Set<string>;
export declare function normalizeMailAddress(address: string): string;
export declare function primaryAddressForUsername(username: string, domain?: string): string;
export declare function isReservedLocal(local: string): boolean;
export declare function isValidMailAddress(address: string): boolean;
export declare function sha256Hex(value: string): Promise<string>;
export declare function hmacHex(secret: string, message: string): Promise<string>;
/** Length-independent byte compare so a wrong signature cannot be brute-forced by timing. */
export declare function signatureEquals(a: string, b: string): boolean;
/** Any object carrying the shared internal secret (Pages env or Worker env). */
export interface MailInternalEnv {
    MAIL_INTERNAL_SECRET?: string;
}
/** Maximum accepted clock skew for `x-flaxia-ts`, in seconds. */
export declare const MAIL_INTERNAL_MAX_SKEW_SECONDS = 300;
/**
 * Sign a trusted Pages -> Mail Worker call. The signature binds the
 * authenticated user id, the timestamp, the HTTP method, the exact
 * path+query, and the body hash so a captured signature cannot be replayed
 * against another endpoint.
 *
 * Returns `null` when no shared secret is configured (callers must fail
 * closed rather than send an unsigned request).
 */
export declare function signMailInternal(env: MailInternalEnv, userId: string, method: string, path: string, body?: string): Promise<Record<string, string> | null>;
/**
 * Verify an internal call. Returns the authenticated user id, or `null` for a
 * missing/expired/wrong signature. The Worker never trusts a bare user id.
 */
export declare function verifyMailInternal(env: MailInternalEnv, req: Request, body: string): Promise<string | null>;
export declare function wrapInfo(messageId: string, recipientAddress: string): string;
export declare function attachmentKeyInfo(attachmentId: string): string;
export declare function metaInfo(messageId: string): string;
export declare function subjectInfo(messageId: string): string;
export declare function fromNameInfo(messageId: string): string;
export declare function attachmentNameInfo(attachmentId: string): string;
export declare function payloadInfo(messageId: string): string;
export declare function encodeB64(bytes: Uint8Array): string;
export declare function decodeB64(value: string): Uint8Array;
/** Worker-side alias kept for the existing Worker call sites. */
export declare const b64encode: typeof encodeB64;
/** Worker-side alias kept for the existing Worker call sites. */
export declare const b64decode: typeof decodeB64;
/**
 * Validate a published identity key before storing it. An invalid or
 * non-P-256 SPKI would silently break every future inbound message for the
 * mailbox, so activation must fail closed.
 */
export declare function isValidP256SpkiB64(value: unknown): Promise<boolean>;
export interface WrappedContentKey {
    ephemeralPublicKey: string;
    iv: string;
    wrappedContentKey: string;
}
/** Wrap a 32-byte content key for one recipient. */
export declare function wrapContentKey(contentKey: Uint8Array, recipientSpkiB64: string, messageId: string, recipientAddress: string): Promise<WrappedContentKey>;
/** Unwrap a content key with the recipient's private key. */
export declare function unwrapContentKey(wrapped: WrappedContentKey, recipientPkcs8B64: string, messageId: string, recipientAddress: string): Promise<Uint8Array>;
/** Derive the per-attachment key from the content key (HKDF). */
export declare function deriveAttachmentKey(contentKey: Uint8Array, attachmentId: string): Promise<Uint8Array>;
/** Encrypt a payload once with the content key. */
export declare function encryptPayload(contentKey: Uint8Array, plaintext: Uint8Array, messageId: string): Promise<{
    iv: string;
    ciphertext: Uint8Array;
}>;
/** Encrypt arbitrary bytes with AES-256-GCM and an explicit AAD. */
export declare function encryptBytes(keyBytes: Uint8Array, plaintext: Uint8Array, aad: string): Promise<{
    iv: string;
    ciphertext: Uint8Array;
}>;
/** Encrypt a UTF-8 string; returns an `iv.ciphertext` envelope. */
export declare function encryptString(keyBytes: Uint8Array, plaintext: string, info: string): Promise<string>;
export declare function decryptPayload(contentKey: Uint8Array, ivB64: string, ciphertext: Uint8Array, messageId: string): Promise<Uint8Array>;
/** Decrypt bytes sealed with AES-256-GCM + explicit AAD. */
export declare function decryptBytes(keyBytes: Uint8Array, ivB64: string, ciphertext: Uint8Array, aad: string): Promise<Uint8Array>;
/** Decrypt an `iv.ciphertext` envelope produced by the Mail Worker. */
export declare function decryptString(keyBytes: Uint8Array, envelope: string, info: string): Promise<string>;
/** Seal attachment bytes with the per-attachment key derived from the content key. */
export declare function encryptAttachment(contentKey: Uint8Array, attachmentId: string, plaintext: Uint8Array): Promise<{
    iv: string;
    ciphertext: Uint8Array;
}>;
/** Decrypt an attachment with the key derived from the message content key. */
export declare function decryptAttachment(contentKey: Uint8Array, attachmentId: string, ivB64: string, ciphertext: Uint8Array): Promise<Uint8Array>;
export declare const MAX_SEND_BYTES: number;
export declare const MAX_ATTACHMENTS = 20;
export declare const MAX_RECIPIENTS = 20;
export interface ComposeAttachmentInput {
    name: string;
    type: string;
    bytes: Uint8Array;
}
export interface ComposeFields {
    from: string;
    to: string[];
    cc: string[];
    bcc: string[];
    subject: string;
    text: string;
    attachments: ComposeAttachmentInput[];
}
export interface SendContext {
    fromName?: string;
    threadId?: string;
    inReplyToHash?: string;
    messageId?: string;
}
export interface RecipientKey {
    address: string;
    public_key: string;
    key_version: number;
}
export interface MailMetadata {
    subject: string;
    from_name: string;
    snippet: string;
    to?: string[];
    cc?: string[];
    bcc?: string[];
    attachments?: Array<{
        id: string;
        filename: string;
        content_type: string;
        size_bytes: number;
        inline?: boolean;
        blocked?: boolean;
    }>;
}
export interface SendAttachmentInput {
    /** Logical attachment id (also the HKDF info input). */
    id: string;
    iv: string;
    ciphertext: string;
    filename_enc: string;
    content_type: string;
    size_bytes: number;
}
export interface SendKeyInput {
    address: string;
    key_version: number;
    ephemeral_public_key: string;
    iv: string;
    wrapped_content_key: string;
}
/** Client-sealed envelope for POST /api/mail/messages and drafts (§9.2). */
export interface SendEnvelopeInput {
    message_id: string;
    thread_id?: string;
    in_reply_to_hash?: string;
    from: string;
    to: string[];
    cc?: string[];
    bcc?: string[];
    subject_enc: string;
    from_name_enc: string;
    meta_enc: string;
    payload: {
        iv: string;
        ciphertext: string;
    };
    attachments?: SendAttachmentInput[];
    keys: SendKeyInput[];
}
export declare function uniqueAddresses(lists: Array<string[] | undefined>): string[];
export declare function isFlaxiaAddress(address: string, domain?: string): boolean;
/**
 * Seal a composed message into the wire envelope. `keys` must cover every
 * unique recipient plus the sender. Purely local: no network, no vault.
 *
 * `wrapAddresses` restricts which addresses get a wrapped content key.
 * The external/TLS path seals only a sender-retained Sent copy (external
 * recipients have no Flaxia key); drafts do the same. Without it every
 * recipient address needs a key.
 */
export declare function sealEnvelope(fields: ComposeFields, keys: RecipientKey[], context?: SendContext, options?: {
    wrapAddresses?: string[];
}): Promise<SendEnvelopeInput>;
