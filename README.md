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

## Milestones

- **M0** (this scaffold): workspace + bare Scribe Think DO streaming chat.
- **M1**: per-user routing (Option B), edge auth, DO-resident agent key.
- **M2**: Forestrie write path — COSE Sign1 statements registered under a grant.
- **M3**: Tier-2 attestation — user-signed input envelope embedded in the agent's
  per-turn work statement.
- **M4**: deferred receipt collection + offline verification; the tamper beat.
- **M5**: KMS-seed key custody (C3), pre-issued grants, separate user-endorsed leaf.
