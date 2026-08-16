# The Scribe — what it is, and what it shows

Two views of the same demo: what a **user** gets out of it, and which
**Forestrie** capabilities it exercises underneath. For build/run/milestone
detail see the [README](./README.md); the plan of record is
`devdocs/plans/plan-2608-08-cf-think-demo/thinker.md`.

## User-facing: what it does and why it matters

**The product in one sentence:** a chat assistant whose conversation is
_tamper-evident_ — you can later prove, to anyone, what was said and what the
agent did, without trusting the operator's word, and without the transcript
itself ever being published.

What a user experiences:

- **A wallet identity, no signup.** The browser holds a key; signing in is a
  signature, not a password. Your address _is_ your identity, and your own
  personal agent instance is derived from it — nobody else can reach it.
- **One activation step.** Before chatting, you sign once to "activate your
  log" — authorizing the network's sealer to checkpoint a log that _only your
  key controls_. The UI holds your leaves until you've done this, so nothing
  of yours is ever committed into a void.
- **Then just chat.** Every message you send is silently signed by your wallet
  and admitted as an _attested work unit_. The agent answers normally —
  streaming, tools, the usual — but for every turn it also signs a statement
  of what it did: which tools it called (as hashes), what it answered (as a
  hash), bound to exactly the input you signed.
- **The proof panel** shows each turn's journey: committed → sequenced →
  receipted, separately for _your_ leaf and the _agent's_ leaf. "Verify
  offline" runs the full cryptographic verification **in your browser** — no
  server involved, the log doesn't even need to be reachable.
- **The payoff — the tamper beat:** if anyone (including the operator) later
  edits the agent's memory of the conversation, verification flips to a red
  "tampered" flag on exactly the turn that was altered. The receipts prove
  which version was real.

**The value:** accountability for AI interactions. The user attests what they
asked; the agent attests what it did. Disputes ("the AI told me X", "the user
actually asked Y") become checkable facts rather than competing claims —
while privacy is preserved, because only salted hashes ever reach the public
log ("pipe, not store").

## Forestrie features used and showcased

**The write path (SCRAPI):** COSE Sign1 statements over CBOR, authorized by a
`Forestrie-Grant` header, `303 → status poll → permanent receipt URL`. The
statement payload is never stored — only its hash is committed.

**Grants — the authorization model (ARC-0019):**

- _Creation grants_ whose `grantData` binds the endorsed signer's key,
  exercising the **issuer ≠ endorsed-signer split**: a grant authority issues
  credentials endorsing keys it doesn't hold — the agent's ES256 kid and the
  user's 20-byte wallet address (KS256) alike.
- **Counterfactual pre-issue (O5):** the agent's key derives deterministically
  from a custodian seed + user + epoch, so its kid is knowable _before the
  agent exists_ — the authority pre-issues the grant, and the newborn agent
  simply collects it.
- Every grant carries its own inclusion receipt — credentials are themselves
  transparency-logged.

**Batch payment for work (x402, plan-2608-09):** the user pays **once** for a
`maxHeight`-bounded _batch_ grant good for N turns, not per message — the 402
challenge and wallet signature stay entirely off the turn path, so chatting
runs at normal latency. The requirement is a **parent-grant policy bit**
(`GF_DERIVED | GF_CHILD_PAYMENT_REQUIRED`), transparency-logged and
receipt-provable, switchable per hierarchy — not a global config. The topology
carries the policy: user grants parent under a **bit-carrying** authority log
(x402-gated), agent grants under a **bit-free** one (ungated) — keeping agents
free is _topological_, never an operator bypass. Three roles stay independent —
the browser **pays**, the grant authority **registers** (server-side; the
browser never registers), the grant **endorses** the user's key. The demo is
honest about the split: `maxHeight` is the hard, on-chain-enforced ceiling on
_sealed_ work; a DO-local `prepaidTurns` counter is the soft per-turn budget,
because appends are unmetered. At zero the UI offers a one-click top-up (a fresh
batch grant, its own provable artifact); the parent's payment policy is
**verifiable offline** in the browser from the parent grant's own receipt.

**Two-sided attestation, two logs, two trust roots (the demo's thesis):**
each turn lands as **two leaves** — the user's signed envelope on a log
_owned by the user's wallet_, and the agent's work statement on a log _owned
by the agent's key_ — cross-referenced by `workId = H(envelope)`, which is
also the turn's execution idempotency key, so the agent provably ran the work
it committed to.

**Sealing delegation (the BYOK story):** logs are checkpointed only by a
sealer the log's owner key has authorized, via delegation certificates
against coordinator-vouched sealer keys. The agent's DO signs its own (ES256,
renewed at drain); **the user's wallet signs theirs in the browser** — the
agent never touches the user's key. The activate-before-write ordering
mirrors the platform's own `prepare → delegate → create` discipline.

**Receipts and offline verification:** receipt = MMR inclusion proof + signed
checkpoint + delegation certificate. The browser verifies the whole chain
with no network: agent signature, receipt under the agent's key, work
binding, transcript binding, and the user leaf's full **KS256 rung** — EOA
recovery of the delegation certificate, coverage window, delegated-key
signature over the peak, and inclusion.

**Supporting cast:** wcc-1 wallet-challenge sessions (ARC-0023 shape) for
edge auth; and two platform improvements this work drove upstream — the grant
authority now self-renews its auth-log sealing lease, and the coordinator
wakes parked sealers the moment a late delegation certificate lands
([canopy PR #224](https://github.com/forestrie/canopy/pull/224)).

**The honest one-liner for both audiences:** Cloudflare gives the agent a
durable, per-user body; Forestrie gives its conversation a spine of
evidence — and the browser alone is enough to check it.
