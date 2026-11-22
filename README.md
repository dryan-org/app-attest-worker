# app-attest-worker

Apple App Attest verification for Cloudflare Workers, shared by the Workers that
trust a Marie or CrumbDB build: the analytics Worker
([dryan-org/crumbdb-analytics](https://github.com/dryan-org/crumbdb-analytics))
and `marie-keys`
([dryan-org/podcatcher-workers](https://github.com/dryan-org/podcatcher-workers)).
Pure WebCrypto plus small parsers, so it runs in a Worker with `nodejs_compat`.

Behaviour was moved from the analytics Worker unchanged: same statuses, same
error bodies, same headers (`X-App-Attest-KeyId`, `X-App-Attest-Assertion`,
`X-App-Attest-Challenge`).

## Install

Installs from GitHub by tag, like `@dryan/pedantry`. It ships TypeScript source
(no build step); Wrangler and Vitest bundle it.

```zsh
npm install github:dryan-org/app-attest-worker#v0.1.0
```

In `vitest.config.ts` bundle it instead of treating it as an external dependency:

```ts
test: {
  server: {
    deps: {
      inline: ["@dryan/app-attest-worker"];
    }
  }
}
```

The Worker needs `"compatibility_flags": ["nodejs_compat"]`.

## What it needs from the Worker

The D1 database that holds the `apps`, `app_attest_ids` and `attest_keys` tables
(the dryan-analytics database; its migrations own the schema) and a KV namespace
for one-time challenge nonces.

```ts
import {
  handleAttest,
  handleChallenge,
  type AttestConfig,
} from "@dryan/app-attest-worker";

const config = (env: Env): AttestConfig => ({
  db: env.DB,
  challenges: env.CHALLENGES,
  allowDevelopment: env.ALLOW_DEVELOPMENT_ATTESTATION === "true",
  defaultApp: "crumbdb", // optional: the app a request that names none belongs to
});

// POST /challenge, POST /attest
handleChallenge(config(env));
handleAttest(request, config(env));
```

## API

- `handleChallenge(config)`: `POST /challenge`, `200 {"challenge"}` (64 hex characters, 60 seconds, single use).
- `handleAttest(request, config)`: `POST /attest`, registers a key into `attest_keys`.
- `attestHeaders(request)`: the key id and assertion headers, or a 401 `Response`.
- `checkChallenge(config, bodyChallenge, headers)`: consumes the challenge; a 401 `Response` or `null`.
- `checkAssertion(config, app, headers, bodyBytes, touchLastSeen)`: verifies the assertion over `SHA-256(body)` and advances the counter; a 401 `Response` or `null`. An unknown key is `401 {"error": UNKNOWN_KEY_ERROR}`.
- `resolveApp(config, bodyApp, headerApp)`, `loadApps`, `listApps`, `attestAppIdsFor`, `clearAppsCache`, `UnknownAppError`: the app registry (60 second cache).
- `verifyAttestation`, `verifyAssertion`, `AppAttestError`, and the byte helpers (`sha256`, `fromBase64`, `toBase64`, ...), from `src/appattest.ts` (also `@dryan/app-attest-worker/appattest`).
- `json`, `flag`: the response and var helpers.

An attested endpoint reads the headers, reads and parses the body, resolves the
app, then `checkChallenge` and `checkAssertion`, in that order (see
`ingestDiagnostics` in the analytics Worker, `podcastIndex` in `marie-keys`).

## Tests

```zsh
npm test    # typecheck and vitest
npm run lint
```

`@dryan/app-attest-worker/testing` is for Workers' own tests (it needs Node's
`node:sqlite`): an in-memory D1 (`attestDatabase`, `fakeD1`, `fakeKV`,
`testConfig`) and `FakeDevice`, which registers a key and signs assertions the
way the app does. Its `ATTEST_SCHEMA` copies the final shape of the analytics
tables; change it with them. A real attestation needs Apple's certificate chain,
so tests stub it through `AttestConfig.verifyAttestation`.

## Releasing

Bump `version`, merge, and tag `vX.Y.Z`. Consumers pin the tag.
