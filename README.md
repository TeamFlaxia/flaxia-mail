# Flaxia Mail

The mail service behind `@flaxia.app` mailboxes: a Cloudflare Worker with its
own D1 database, R2 bucket and queues, plus the shared wire contract used by the
Flaxia SPA and Pages Functions.

This repository replaces the former `flaxia/mail-worker/` directory. It is
deployed independently from the Flaxia Pages app; Flaxia reaches it through the
`MAIL_SERVICE` service binding and keeps only the `/api/mail/*` proxy and the
webmail UI.

## Layout

```text
.
├── src/index.ts          @flaxia/mail-contract (GitHub Release tarball)
├── dist/                 committed build output for git/offline installs
├── tests/                contract tests (address grammar, HMAC, ECIES, seal)
└── worker/
    ├── src/              flaxia-mail Worker (fetch / email / queue)
    ├── migrations/       MAIL_DB schema
    ├── tests/            Worker + in-memory D1 integration tests
    └── wrangler.toml     Worker, D1, R2, Queue, Email Routing config
```

## Contract

`@flaxia/mail-contract` is the single source of truth for:

- mailbox address grammar and the reserved-local list;
- the Pages ↔ Worker `x-flaxia-*` HMAC (`signMailInternal` / `verifyMailInternal`);
- `MAIL_CONTRACT_VERSION`, sent as `x-flaxia-contract` and reported by the
  Worker's `GET /health`; a mismatch fails with `409 mail_contract_mismatch`;
- ECIES content-key wrapping and AES-GCM envelope helpers;
- the client-sealed send envelope (`sealEnvelope`) and its wire types.

It is pure WebCrypto/Web standard APIs, so the same code runs in Workers,
browsers and Node 22+.

### Consuming it

Flaxia pins the package and imports the same functions:

```ts
import { signMailInternal, sealEnvelope } from '@flaxia/mail-contract';
```

The contract is not published to any package registry. It ships as a tarball
attached to a GitHub Release, and Flaxia vendors that tarball at
`flaxia/vendor/flaxia-mail-contract-<version>.tgz`.

Release flow:

1. Bump `version` in `package.json`, rebuild so `dist/` is committed, and tag
   the commit `contract-vX.Y.Z` (e.g. `contract-v0.1.1`). Push the tag.
2. `.github/workflows/release.yml` runs `npm ci`, `npm run build`, fails if
   `dist/` is stale, runs the contract tests, then `npm pack` and creates or
   updates the GitHub Release whose asset is
   `flaxia-mail-contract-X.Y.Z.tgz`.
3. Copy that asset into Flaxia and update the `file:` dependency:

```sh
# download the asset from the GitHub Release for contract-v0.1.1
gh release download contract-v0.1.1 -p flaxia-mail-contract-0.1.1.tgz
# in flaxia
cp flaxia-mail-contract-0.1.1.tgz vendor/
```

Then in `flaxia/package.json` point the dependency at the new tarball and
install:

```json
"@flaxia/mail-contract": "file:vendor/flaxia-mail-contract-0.1.1.tgz"
```

```sh
npm install
```

The committed `dist/` is what the tarball ships, so no build step runs on
install. The package stays public (it has no `private` field) and its Release
assets are downloadable, but releases only ever come from CI: a
`prepublishOnly` guard aborts any attempt to push it to a registry, so there is
no registry step and no npm auth token to configure.

## Development

```sh
npm install
npm install --prefix worker
npm run build          # contract dist
npm run typecheck
npm test               # contract tests
npm run test:worker    # Worker + in-memory D1 tests
```

Worker-only:

```sh
cd worker
npm run dev            # wrangler dev — service-binding only, no workers.dev
npm run migrate:local
npm run deploy
```

## Deployment

Production Worker secrets (set with `wrangler secret put --config worker/wrangler.toml`):

- `MAIL_INTERNAL_SECRET` — must equal the value configured on the Flaxia Pages project
- `MAIL_THREAD_SECRET` — subject-based thread fallback HMAC

Deploy order: **mail → Flaxia Pages**. A mail deploy failure must not block the
site; the Pages app tolerates an unavailable `MAIL_SERVICE` for non-mail routes.

The Worker has no public `workers.dev` route. Only the service binding and the
Email Routing `email()` handler are reachable.

Protocol and schema specification: `flaxia/docs/mail.md`.
