import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  isReservedLocal,
  isValidMailAddress,
  normalizeMailAddress,
  primaryAddressForUsername,
  RESERVED_LOCALS,
} from '../src/index.ts';

describe('mail addresses', () => {
  it('builds lowercase primary addresses from usernames', () => {
    assert.equal(primaryAddressForUsername('Alice_1'), 'alice_1@flaxia.app');
    assert.equal(primaryAddressForUsername('  Bob  '), 'bob@flaxia.app');
  });

  it('normalizes case and whitespace', () => {
    assert.equal(normalizeMailAddress('  Alice@FLAXIA.APP '), 'alice@flaxia.app');
  });

  it('rejects reserved locals', () => {
    for (const reserved of [
      'admin',
      'abuse',
      'billing',
      'dmarc',
      'hostmaster',
      'mailerdaemon',
      'noreply',
      'postmaster',
      'root',
      'security',
      'support',
      'team',
      'webmaster',
    ]) {
      assert.equal(isReservedLocal(reserved), true);
      assert.throws(() => primaryAddressForUsername(reserved), /mail_reserved/);
    }
  });

  it('keeps one reserved list in the contract and none in the Worker', () => {
    const sources = [
      ['contract', '../src/index.ts'],
      ['worker', '../worker/src/index.ts'],
    ] as const;
    const contract = readFileSync(new URL(sources[0][1], import.meta.url), 'utf8');
    assert.ok(contract.includes('export const RESERVED_LOCALS = new Set'));
    const worker = readFileSync(new URL(sources[1][1], import.meta.url), 'utf8');
    assert.match(worker, /from '@flaxia\/mail-contract'/);
    assert.ok(!worker.includes('const RESERVED_LOCALS = new Set'), 'the Worker must not duplicate the list');
    assert.ok(RESERVED_LOCALS.size >= 20, 'operational lookalikes must stay reserved');
  });

  it('rejects invalid usernames', () => {
    assert.throws(() => primaryAddressForUsername('bad name!'), /mail_invalid_username/);
    assert.throws(() => primaryAddressForUsername(''), /mail_invalid_username/);
    assert.throws(() => primaryAddressForUsername('a'.repeat(21)), /mail_invalid_username/);
  });

  it('validates mail addresses', () => {
    assert.equal(isValidMailAddress('alice@flaxia.app'), true);
    assert.equal(isValidMailAddress('alice@mail.flaxia.app'), true);
    assert.equal(isValidMailAddress('alice@example.com'), false);
    assert.equal(isValidMailAddress('no-at-sign'), false);
  });
});
