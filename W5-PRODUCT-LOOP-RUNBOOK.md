# W5 product-loop validation runbook (plan-2608-09)

Validate the full paid batch-grant loop against the **flipped** canopy lane A
(`REGISTER_GRANT_ADMISSION=either` live). The canopy gate itself is already
proven by the CI `register-grant-payment` spec; this runbook proves the **thinker
product loop**: fresh wallet → pay once → N turns → both leaves receipted → turn
N+1 refused → top-up restores.

> **Topology.** This is a **local** stack — the grant authority runs on
> `localhost:8799`, so the loop is driven by `wrangler dev` + `vite dev` on your
> machine talking to live lane A. There is no production Cloudflare deploy (a
> deployed Worker can't reach the localhost authority).

---

## 0. Prerequisites

- **A funded Base Sepolia wallet in the browser.** In this demo the **browser is
  the payer** (the user's wallet signs the EIP-3009 x402 authorization; the
  authority is only the registrar). So the wallet you connect **must hold Base
  Sepolia USDC** (the price is `$0.01 × maxHeight` = **$0.16** for a 16-turn
  batch). EIP-3009 `transferWithAuthorization` is gasless for the signer (the
  facilitator submits), so USDC balance is what matters, not ETH.
  - Faucet: Circle Base Sepolia USDC faucet, or transfer from the dev wallet.
- **doppler authed** for `canopy/dev` (the authority pulls `COORDINATOR_APP_TOKEN`
  from it). Already verified in this session.
- **`.provision/` present** with the W4b.1 two-parent artifacts (agent-auth
  `f72af27c…`, user-auth `2c2b57ca…`) — already in place; no re-provision needed.

## 1. Stack (already running this session)

| Service         | Start command (from `thinker/`)   | Port | Health                                             |
| --------------- | --------------------------------- | ---- | -------------------------------------------------- |
| grant authority | `bash scripts/authority.sh`       | 8799 | `curl -s localhost:8799/healthz` → `{"ok":true,…}` |
| scribe-worker   | `pnpm --filter scribe-worker dev` | 8787 | wrangler log: `Ready on http://localhost:8787`     |
| scribe-ui       | `pnpm --filter scribe-ui dev`     | 5173 | `curl -sI localhost:5173` → `200`                  |

If any died, restart with the command above. Logs (this session) are under the
scratchpad: `authority.log`, `worker.log`.

## 2. Drive the loop in the browser

1. **Open** http://localhost:5173.
2. **Connect a FRESH wallet address.** Per-user Scribe state is keyed by wallet,
   so a fresh address guarantees you hit the _unpaid_ path (an address that
   already holds a grant would skip the 402). The fresh wallet must be funded
   (step 0).
3. **Activate your log** — sign once. The UI holds your leaves until this is done.
4. **Watch the first grant request trigger payment.** At bind the DO asks the
   authority for a user grant; the authority hits canopy register-grant under the
   **bit-carrying user-authority parent** → now that the lane is flipped, canopy
   returns **402** with the `X-PAYMENT-REQUIRED` challenge. The challenge is
   relayed to the browser; the UI surfaces a **pay / top-up** affordance.
5. **Pay.** Approve the x402 signature in the wallet. The signed `X-PAYMENT` goes
   back to the authority, which resubmits register-grant → **303** → the user
   grant is issued with `maxHeight = 16` and `prepaidTurns = 16` is seeded.
6. **Chat.** Each turn lands **two leaves** (your signed envelope + the agent's
   work statement). The **proof panel** shows committed → sequenced → receipted
   for both, and the sealing card shows **turns remaining** decrementing.
7. **Exhaust the batch.** After 16 turns `prepaidTurns` hits 0; the next turn is
   refused with **402 `{topUp:true}`** and the UI shows a **Top up** button.
8. **Top up.** Click it → repeats the purchase → a **fresh** `maxHeight=16` grant
   (new grant + new log per batch, O3) → chatting resumes.
9. **Offline proof.** Use **"Verify offline"** on a turn (full chain, in-browser,
   no network) and the **"Payment policy — provable offline"** card, which decodes
   the user-authority parent grant, reads `requiresChildPayment`, and verifies the
   parent's own inclusion receipt under the root key — the ARC-0029 L2 beat.

## 3. Success criteria

- [ ] Fresh wallet's first grant request returns **402** (not a silent 303) — the
      flip is engaging the gate.
- [ ] After paying, a user grant issues (`maxHeight 16`) and turns run at normal
      latency (payment is off the turn path).
- [ ] Every turn produces **two receipted leaves** (user + agent), cross-referenced
      by `workId`.
- [ ] Turn **17 is refused** with a top-up affordance; top-up restores chatting.
- [ ] Offline verification is **green**, and the payment-policy card proves the
      parent bit from its receipt.
- [ ] Tamper beat (optional): edit the agent's stored memory of a turn → offline
      verify flips that turn to **red/tampered**.

## 4. Observe / debug

- **Authority** (registrar + 402 choreography): tail `authority.log`. Look for the
  register-grant 402 then the resubmit → 303, and per-log sealing-lease renewals.
- **Worker**: tail `worker.log`. Look for the parked challenge on `/identity` /
  `/receipts`, `POST /pay-user-grant`, and `admitAttestedTurn` decrementing
  `prepaidTurns`.
- **Canopy gate (live)**: the 402 originates on lane A
  (`https://api-a.forest-2.forestrie.dev`) from the merged gate; L2 verifies the
  parent receipt server-side before challenging.
- **Wallet has no USDC** → the pay step fails at signature/settle; fund it (step 0)
  and retry the top-up.

## 5. Notes

- The lane flip + L2 gate are **already deployed and CI-verified** (canopy #233 +
  #234, deploy run 31905252708). This runbook is the product-loop confirmation on
  top of that.
- To reset for a clean run, connect a brand-new wallet address (don't reuse one
  that already bought a batch).
