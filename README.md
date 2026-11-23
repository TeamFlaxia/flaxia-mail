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
├── src/index.ts          @flaxia/mail-contract (published package)
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
- ECIES content-key wrapping and AES-GCM envelope helpers;
- the client-sealed send envelope (`sealEnvelope`) and its wire types.

It is pure WebCrypto/Web standard APIs, so the same code runs in Workers,
browsers and Node 22+.

### Consuming it

Flaxia pins the package and imports the same functions:

```ts
import { signMailInternal, sealEnvelope } from '@flaxia/mail-contract';
```

Until the package is published to npm (the `contract-v*` publish workflow
needs an `NPM_TOKEN` secret), Flaxia consumes the packed tarball committed at
`flaxia/vendor/flaxia-mail-contract-0.1.1.tgz`:

```sh
# in this repo
npm run build
npm pack                      # -> flaxia-mail-contract-0.1.1.tgz
# in flaxia
cp ../flaxia-mail/flaxia-mail-contract-0.1.1.tgz vendor/
# bump the version + filename in flaxia/package.json, then npm install
```

The committed `dist/` is what the tarball ships, so no build step runs on
install. After the first npm publish, switch Flaxia to the registry semver
range (`^0.1.x`) and delete the vendored tarball.

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
