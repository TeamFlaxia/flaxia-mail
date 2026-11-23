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
export const MAIL_CONTRACT_VERSION = '0.1.1';

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

export function normalizeMailAddress(address: string): string {
  return address.trim().toLowerCase();
}

export function primaryAddressForUsername(username: string, domain = MAIL_DOMAIN): string {
  const local = username.trim().toLowerCase();
  if (!USERNAME_PATTERN.test(local)) throw new Error('mail_invalid_username');
  if (RESERVED_LOCALS.has(local)) throw new Error('mail_reserved');
  return `${local}@${domain}`;
}

export function isReservedLocal(local: string): boolean {
  return RESERVED_LOCALS.has(local.trim().toLowerCase());
}

export function isValidMailAddress(address: string): boolean {
  const normalized = normalizeMailAddress(address);
  const at = normalized.lastIndexOf('@');
  if (at < 1) return false;
  const local = normalized.slice(0, at);
  const domain = normalized.slice(at + 1);
  if (!/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$/.test(local)) return false;
  return domain === MAIL_DOMAIN || domain.endsWith(`.${MAIL_DOMAIN}`);
}

// ---------------------------------------------------------------------------
// WebCrypto primitives (docs/mail.md §5)
// ---------------------------------------------------------------------------

const encoder = new TextEncoder();

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export async function sha256Hex(value: string): Promise<string> {
  return toHex(await crypto.subtle.digest('SHA-256', encoder.encode(value) as BufferSource));
}

export async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret) as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message) as BufferSource);
  return toHex(signature);
}

/** Length-independent byte compare so a wrong signature cannot be brute-forced by timing. */
export function signatureEquals(a: string, b: string): boolean {
  let diff = a.length === b.length ? 0 : 1;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

// ---------------------------------------------------------------------------
// Pages <-> Mail Worker internal HMAC (docs/mail.md §5, §8)
// ---------------------------------------------------------------------------

/** Any object carrying the shared internal secret (Pages env or Worker env). */
export interface MailInternalEnv {
  MAIL_INTERNAL_SECRET?: string;
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
export async function signMailInternal(
  env: MailInternalEnv,
  userId: string,
  method: string,
  path: string,
  body = '',
): Promise<Record<string, string> | null> {
  const secret = env.MAIL_INTERNAL_SECRET;
  if (!secret) return null;

  const ts = String(Math.floor(Date.now() / 1000));
  const target = new URL(`https://flaxia-mail${path}`);
  const message = `${userId}.${ts}.${method.toUpperCase()}.${target.pathname}${target.search}.${await sha256Hex(body)}`;
  return {
    'x-flaxia-user-id': userId,
    'x-flaxia-ts': ts,
    'x-flaxia-sig': await hmacHex(secret, message),
    'x-flaxia-contract': MAIL_CONTRACT_VERSION,
  };
}

/**
 * Verify an internal call. Returns the authenticated user id, or `null` for a
 * missing/expired/wrong signature. The Worker never trusts a bare user id.
 */
export async function verifyMailInternal(env: MailInternalEnv, req: Request, body: string): Promise<string | null> {
  const userId = req.headers.get('x-flaxia-user-id');
  const ts = req.headers.get('x-flaxia-ts');
  const sig = req.headers.get('x-flaxia-sig');
  const secret = env.MAIL_INTERNAL_SECRET;
  if (!userId || !ts || !sig || !secret) return null;
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

const subtle = (globalThis.crypto as Crypto).subtle;

export function wrapInfo(messageId: string, recipientAddress: string): string {
  return `flaxia.mail.wrap.v1:${messageId}:${recipientAddress}`;
}

export function attachmentKeyInfo(attachmentId: string): string {
  return `flaxia.mail.attachment.v1:${attachmentId}`;
}

export function metaInfo(messageId: string): string {
  return `flaxia.mail.meta.v1:${messageId}`;
}

export function subjectInfo(messageId: string): string {
  return `flaxia.mail.subject.v1:${messageId}`;
}

export function fromNameInfo(messageId: string): string {
  return `flaxia.mail.from-name.v1:${messageId}`;
}

export function attachmentNameInfo(attachmentId: string): string {
  return `flaxia.mail.attachment-name.v1:${attachmentId}`;
}

export function payloadInfo(messageId: string): string {
  return `flaxia.mail.payload.v1:${messageId}`;
}

export function encodeB64(bytes: Uint8Array): string {
  let binary = '';
  for (const x of bytes) binary += String.fromCharCode(x);
  return btoa(binary);
}

export function decodeB64(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Worker-side alias kept for the existing Worker call sites. */
export const b64encode = encodeB64;
/** Worker-side alias kept for the existing Worker call sites. */
export const b64decode = decodeB64;

async function importSpki(spkiB64: string): Promise<CryptoKey> {
  return (await subtle.importKey(
    'spki',
    decodeB64(spkiB64) as BufferSource,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    // ECDH public keys must be imported with no usages (WebCrypto spec); the
    // private key supplies the usages in deriveBits/deriveKey.
    [],
  )) as CryptoKey;
}

async function importPkcs8(pkcs8B64: string): Promise<CryptoKey> {
  return (await subtle.importKey(
    'pkcs8',
    decodeB64(pkcs8B64) as BufferSource,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits'],
  )) as CryptoKey;
}

/**
 * Validate a published identity key before storing it. An invalid or
 * non-P-256 SPKI would silently break every future inbound message for the
 * mailbox, so activation must fail closed.
 */
export async function isValidP256SpkiB64(value: unknown): Promise<boolean> {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512) return false;
  try {
    const bytes = decodeB64(value);
    if (bytes.length === 0 || bytes.length > 256) return false;
    await subtle.importKey('spki', bytes as BufferSource, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    return true;
  } catch {
    return false;
  }
}

async function deriveWrapKey(
  ephemeralPrivate: CryptoKey,
  recipientPublic: CryptoKey,
  info: string,
): Promise<CryptoKey> {
  const shared = await subtle.deriveBits(
    { name: 'ECDH', public: recipientPublic as unknown as CryptoKey },
    ephemeralPrivate as unknown as CryptoKey,
    256,
  );
  const hkdfBase = await subtle.importKey('raw', shared as BufferSource, 'HKDF', false, ['deriveKey']);
  return (await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: encoder.encode(''), info: encoder.encode(info) },
    hkdfBase,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  )) as CryptoKey;
}

export interface WrappedContentKey {
  ephemeralPublicKey: string;
  iv: string;
  wrappedContentKey: string;
}

/** Wrap a 32-byte content key for one recipient. */
export async function wrapContentKey(
  contentKey: Uint8Array,
  recipientSpkiB64: string,
  messageId: string,
  recipientAddress: string,
): Promise<WrappedContentKey> {
  if (contentKey.length !== 32) throw new Error('content key must be 32 bytes');
  const ephemeral = (await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveKey',
    'deriveBits',
  ])) as CryptoKeyPair;
  const recipientPublic = await importSpki(recipientSpkiB64);
  const wrapKey = await deriveWrapKey(ephemeral.privateKey, recipientPublic, wrapInfo(messageId, recipientAddress));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = encoder.encode(wrapInfo(messageId, recipientAddress));
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad },
    wrapKey,
    contentKey as BufferSource,
  );
  const ephSpki = new Uint8Array(await subtle.exportKey('spki', ephemeral.publicKey));
  return {
    ephemeralPublicKey: encodeB64(ephSpki),
    iv: encodeB64(iv),
    wrappedContentKey: encodeB64(new Uint8Array(ciphertext)),
  };
}

/** Unwrap a content key with the recipient's private key. */
export async function unwrapContentKey(
  wrapped: WrappedContentKey,
  recipientPkcs8B64: string,
  messageId: string,
  recipientAddress: string,
): Promise<Uint8Array> {
  const privateKey = await importPkcs8(recipientPkcs8B64);
  const ephemeralPublic = await importSpki(wrapped.ephemeralPublicKey);
  const wrapKey = await deriveWrapKey(privateKey, ephemeralPublic, wrapInfo(messageId, recipientAddress));
  const aad = encoder.encode(wrapInfo(messageId, recipientAddress));
  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv: decodeB64(wrapped.iv) as BufferSource, additionalData: aad },
    wrapKey,
    decodeB64(wrapped.wrappedContentKey) as BufferSource,
  );
  return new Uint8Array(plaintext);
}

/** Derive the per-attachment key from the content key (HKDF). */
export async function deriveAttachmentKey(contentKey: Uint8Array, attachmentId: string): Promise<Uint8Array> {
  const hkdfBase = await subtle.importKey('raw', contentKey as BufferSource, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode(''),
      info: encoder.encode(attachmentKeyInfo(attachmentId)),
    },
    hkdfBase,
    256,
  );
  return new Uint8Array(bits);
}

/** Encrypt a payload once with the content key. */
export async function encryptPayload(
  contentKey: Uint8Array,
  plaintext: Uint8Array,
  messageId: string,
): Promise<{ iv: string; ciphertext: Uint8Array }> {
  const key = await subtle.importKey('raw', contentKey as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = encoder.encode(payloadInfo(messageId));
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad },
    key,
    plaintext as BufferSource,
  );
  return { iv: encodeB64(iv), ciphertext: new Uint8Array(ciphertext) };
}

/** Encrypt arbitrary bytes with AES-256-GCM and an explicit AAD. */
export async function encryptBytes(
  keyBytes: Uint8Array,
  plaintext: Uint8Array,
  aad: string,
): Promise<{ iv: string; ciphertext: Uint8Array }> {
  const key = await subtle.importKey('raw', keyBytes as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, additionalData: encoder.encode(aad) },
    key,
    plaintext as BufferSource,
  );
  return { iv: encodeB64(iv), ciphertext: new Uint8Array(ciphertext) };
}

/** Encrypt a UTF-8 string; returns an `iv.ciphertext` envelope. */
export async function encryptString(keyBytes: Uint8Array, plaintext: string, info: string): Promise<string> {
  const encrypted = await encryptBytes(keyBytes, encoder.encode(plaintext), info);
  return `${encrypted.iv}.${encodeB64(encrypted.ciphertext)}`;
}

export async function decryptPayload(
  contentKey: Uint8Array,
  ivB64: string,
  ciphertext: Uint8Array,
  messageId: string,
): Promise<Uint8Array> {
  const key = await subtle.importKey('raw', contentKey as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const aad = encoder.encode(payloadInfo(messageId));
  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv: decodeB64(ivB64) as BufferSource, additionalData: aad },
    key,
    ciphertext as BufferSource,
  );
  return new Uint8Array(plaintext);
}

/** Decrypt bytes sealed with AES-256-GCM + explicit AAD. */
export async function decryptBytes(
  keyBytes: Uint8Array,
  ivB64: string,
  ciphertext: Uint8Array,
  aad: string,
): Promise<Uint8Array> {
  const key = await subtle.importKey('raw', keyBytes as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv: decodeB64(ivB64) as BufferSource, additionalData: encoder.encode(aad) },
    key,
    ciphertext as BufferSource,
  );
  return new Uint8Array(plaintext);
}

/** Decrypt an `iv.ciphertext` envelope produced by the Mail Worker. */
export async function decryptString(keyBytes: Uint8Array, envelope: string, info: string): Promise<string> {
  const [iv, ciphertext] = envelope.split('.', 2);
  if (!iv || !ciphertext) throw new Error('invalid encrypted string');
  const plaintext = await decryptBytes(keyBytes, iv, decodeB64(ciphertext), info);
  return new TextDecoder().decode(plaintext);
}

/** Seal attachment bytes with the per-attachment key derived from the content key. */
export async function encryptAttachment(
  contentKey: Uint8Array,
  attachmentId: string,
  plaintext: Uint8Array,
): Promise<{ iv: string; ciphertext: Uint8Array }> {
  const key = await deriveAttachmentKey(contentKey, attachmentId);
  try {
    return await encryptBytes(key, plaintext, attachmentKeyInfo(attachmentId));
  } finally {
    key.fill(0);
  }
}

/** Decrypt an attachment with the key derived from the message content key. */
export async function decryptAttachment(
  contentKey: Uint8Array,
  attachmentId: string,
  ivB64: string,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const key = await deriveAttachmentKey(contentKey, attachmentId);
  return decryptBytes(key, ivB64, ciphertext, attachmentKeyInfo(attachmentId));
}

// ---------------------------------------------------------------------------
// Client-sealed send envelope (docs/mail.md §6.2, §9.2)
// ---------------------------------------------------------------------------

export const MAX_SEND_BYTES = 10 * 1024 * 1024;
export const MAX_ATTACHMENTS = 20;
export const MAX_RECIPIENTS = 20;

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
  payload: { iv: string; ciphertext: string };
  attachments?: SendAttachmentInput[];
  keys: SendKeyInput[];
}

function normalizeRecipient(address: string): string {
  return address.trim().toLowerCase();
}

export function uniqueAddresses(lists: Array<string[] | undefined>): string[] {
  const set = new Set<string>();
  for (const list of lists) {
    for (const address of list ?? []) {
      const normalized = normalizeRecipient(address);
      if (normalized) set.add(normalized);
    }
  }
  return [...set];
}

export function isFlaxiaAddress(address: string, domain = MAIL_DOMAIN): boolean {
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
export async function sealEnvelope(
  fields: ComposeFields,
  keys: RecipientKey[],
  context: SendContext = {},
  options?: { wrapAddresses?: string[] },
): Promise<SendEnvelopeInput> {
  const messageId = context.messageId ?? crypto.randomUUID();
  const keyByAddress = new Map(keys.map((key) => [normalizeRecipient(key.address), key]));
  const recipients = uniqueAddresses([fields.to, fields.cc, fields.bcc]);

  const contentKey = crypto.getRandomValues(new Uint8Array(32));
  try {
    const metaAttachments: Array<{ id: string; filename: string; content_type: string; size_bytes: number }> = [];
    const attachments: NonNullable<SendEnvelopeInput['attachments']> = [];
    let totalBytes = 0;

    for (const attachment of fields.attachments.slice(0, MAX_ATTACHMENTS)) {
      const id = crypto.randomUUID();
      totalBytes += attachment.bytes.byteLength;
      if (totalBytes > MAX_SEND_BYTES) throw new Error('mail_too_large');
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

    const metadata: MailMetadata = {
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
    if (totalBytes > MAX_SEND_BYTES) throw new Error('mail_too_large');

    const subjectEnc = await encryptString(contentKey, fields.subject, subjectInfo(messageId));
    const fromNameEnc = await encryptString(contentKey, context.fromName ?? '', fromNameInfo(messageId));
    const metaEnc = await encryptString(contentKey, JSON.stringify(metadata), metaInfo(messageId));

    const wireKeys: SendKeyInput[] = [];
    const wrapTargets =
      options?.wrapAddresses === undefined
        ? [...new Set([normalizeRecipient(fields.from), ...recipients])]
        : [...new Set(options.wrapAddresses.map(normalizeRecipient))];
    // Sending to yourself makes `from` a recipient too; wrap once per address.
    for (const address of wrapTargets) {
      const key = keyByAddress.get(address);
      if (!key) throw new Error('mail_recipient_key_missing');
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
  } finally {
    contentKey.fill(0);
  }
}
