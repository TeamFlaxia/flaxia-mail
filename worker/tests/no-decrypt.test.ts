// The Worker must only ever encrypt/seal. Vault and mail decryption stays in
// the browser; a decrypt helper appearing here would mean ciphertext or vault
// keys could be recovered server-side.
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';

const SRC = new URL('../src', import.meta.url).pathname;

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (full.endsWith('.ts')) out.push(full);
  }
  return out;
}

describe('mail worker keeps decryption client-side', () => {
  it('does not import or implement decryption/vault helpers', () => {
    const forbidden = /unwrapContentKey|decryptPayload|decryptString|decryptAttachment|unwrapSecret|decryptVaultItem|wrapVaultKey/;
    const offenders = walk(SRC).filter((file) => forbidden.test(readFileSync(file, 'utf8')));
    assert.deepEqual(
      offenders.map((file) => file.slice(SRC.length + 1)),
      [],
      'the Worker must only encrypt/seal; decryption stays in the browser',
    );
  });
});
