import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { MAIL_CONTRACT_VERSION } from '../src/index.ts';

describe('wire contract version', () => {
  it('matches the package version so a release cannot ship a stale wire version', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      version?: unknown;
    };
    assert.equal(typeof pkg.version, 'string');
    assert.equal(MAIL_CONTRACT_VERSION, pkg.version);
  });
});
