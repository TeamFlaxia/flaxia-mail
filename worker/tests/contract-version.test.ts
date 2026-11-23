// Contract-version handshake: a Pages deploy that signs with a different
// address/HMAC/crypto contract must fail loudly instead of producing a wall of
// 401s or undecryptable mail.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { MAIL_CONTRACT_VERSION } from '@flaxia/mail-contract';
import worker from '../src/index.ts';
import type { MailEnv } from '../src/ingest.ts';

const env = { MAIL_INTERNAL_SECRET: 'test-secret' } as unknown as MailEnv;

describe('mail contract version', () => {
  it('reports the contract version on /health', async () => {
    const res = await worker.fetch(new Request('https://flaxia-mail/health'), env);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true, contract: MAIL_CONTRACT_VERSION });
  });

  it('rejects a mismatched x-flaxia-contract before auth', async () => {
    const res = await worker.fetch(
      new Request('https://flaxia-mail/internal/quota', { headers: { 'x-flaxia-contract': '0.0.0' } }),
      env,
    );
    assert.equal(res.status, 409);
    assert.deepEqual(await res.json(), { error: 'mail_contract_mismatch' });
  });

  it('stays backward compatible when the header is absent', async () => {
    const res = await worker.fetch(new Request('https://flaxia-mail/internal/quota'), env);
    assert.equal(res.status, 401);
    assert.deepEqual(await res.json(), { error: 'mail_unauthorized' });
  });
});
