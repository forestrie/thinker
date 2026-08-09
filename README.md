# thinker

Forestrie × Cloudflare "Think" demo — **the Scribe**: a per-user Think agent
that produces a tamper-evident, externally verifiable record of a conversation.
The user attests to their input; the agent attests to its own choices and
outputs. Both are committed to a pre-provisioned Forestrie log via SCRAPI.

Plan of record: `devdocs/plans/plan-2608-08-cf-think-demo/thinker.md` (in the
forestrie devdocs repo). This repo is **external to canopy** — the agent is a
registrant/writer against canopy's public APIs, never a sealer.

## Layout

```
packages/think-scribe/   @forestrie/think-scribe — the reusable Think extension
apps/scribe-worker/      thin Worker hosting the Scribe Durable Object
config/                  pre-provisioned instance wiring (see instance.example.jsonc)
scripts/                 provision.sh (M2), verify-receipts.sh (M4)
```

## Development

```sh
pnpm install
cp apps/scribe-worker/.dev.vars.example apps/scribe-worker/.dev.vars   # add ANTHROPIC_API_KEY
pnpm dev            # wrangler dev (local DO + chat at http://localhost:8787)
pnpm typecheck
```

The model is Anthropic via the AI-SDK provider, selected in the Scribe's
`getModel()` — swappable by design. Default `claude-sonnet-5`; set
`MODEL_ID=claude-opus-4-8` for max quality.

## Auth & per-user instances (M1)

Every agent route requires a wcc-1 session (ARC-0023, minimal self-contained
implementation in `apps/scribe-worker/src/auth.ts`):

1. `POST /auth/challenge` → `{ challenge, message }`
2. Wallet `personal_sign`s `message` (EIP-191/KS256)
3. `POST /auth/session` `{ challenge, signature }` → `{ token, sub }` where
   `sub` is the recovered wallet address (TTL 10 min)
4. Talk to **your own** instance only: `/agents/scribe/user-<sub>/…` with
   `Authorization: Bearer <token>` (HTTP) or `?token=<token>` (WebSocket
   connect). Any other instance name → 403; the DO also binds its owner on
   first touch.

`GET /agents/scribe/user-<sub>/identity` returns the agent's per-instance
ES256 signing key (`kid` = x coordinate — the future `grantData` binding).
The private key is generated in the DO and stored only wrapped under
`SCRIBE_KEK` (workerd cannot persist CryptoKeys — spike S1), unwrapped to a
non-extractable handle at load. With `DEV_AUTH=1`, `Bearer dev:<name>` skips
the wallet flow locally. Smoke test: `node test/m1-smoke.mjs` against
`pnpm dev`.

## Milestones

- **M0** (this scaffold): workspace + bare Scribe Think DO streaming chat.
- **M1** (done): per-user routing (Option B), wcc-1 edge auth, DO-resident
  agent key (C2) behind the `KeyProvider` custody seam.
- **M2**: Forestrie write path — COSE Sign1 statements registered under a grant.
- **M3**: Tier-2 attestation — user-signed input envelope embedded in the agent's
  per-turn work statement.
- **M4**: deferred receipt collection + offline verification; the tamper beat.
- **M5**: KMS-seed key custody (C3), pre-issued grants, separate user-endorsed leaf.
