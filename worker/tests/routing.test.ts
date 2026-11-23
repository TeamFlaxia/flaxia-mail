// Routing invariants that belong to the Worker repo (docs/mail.md §11.1.3).
//
// The Email Routing forwarding itself is configured in the Cloudflare
// dashboard. The operator-facing documentation (destination, dashboard steps)
// stays in the Flaxia repo; here we only guard the Worker side: user mail must
// never be forwarded, the catch-all must stay on the Worker, and the Worker
// must not be publicly reachable.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { isReservedLocal } from '@flaxia/mail-contract';

const DESTINATION = 'teamflaxia@proton.me';
const source = (path: string): string => readFileSync(new URL(path, import.meta.url), 'utf8');

describe('mail worker routing', () => {
  it('keeps postmaster/abuse reserved (not user addresses)', () => {
    assert.equal(isReservedLocal('postmaster'), true);
    assert.equal(isReservedLocal('abuse'), true);
  });

  it('does not forward user mail (catch-all stays on the Worker)', () => {
    const worker = source('../src/index.ts');
    assert.ok(!worker.includes(DESTINATION), 'the Mail Worker must never see proton.me traffic');
    assert.ok(!worker.includes('MAIL_FALLBACK_FORWARD'), 'the fallback forward must stay removed');
  });

  it('stays reachable only through the service binding', () => {
    const wrangler = source('../wrangler.toml');
    assert.match(wrangler, /^workers_dev = false$/m, 'the Worker must not expose workers.dev');
    assert.match(wrangler, /^name = "flaxia-mail"$/m);
    assert.doesNotMatch(wrangler, /^\s*routes\s*=/m, 'the Mail Worker must not claim a public route');
    // Apex cutover (D6) has executed: inbound mail is the canonical receive
    // path and must be explicitly enabled, not silently defaulted by deploy.
    assert.match(wrangler, /^MAIL_INBOUND_ENABLED = "1"$/m, 'inbound mail must stay enabled');
  });
});
