import type { KeyProvider } from "./provider.ts";

/**
 * C3 — the preferred target custody (plan §8, D4): derive the per-user
 * agent key from a KMS-custodied seed instead of storing anything.
 *
 *   seed  = custodianMAC(kmsKey, "forestrie/agent-signer-seed/v1" ‖ userSub ‖ epoch)
 *   d     = HKDF(seed) → P-256 scalar (rejection-sampled into [1, n−1])
 *   sign locally; one signature per commitment — the async drain absorbs
 *   the custodian-MAC hop (brainstorm 04 §5).
 *
 * Because the derivation is a pure function of `userSub` and `epoch`, the
 * kid is counterfactually derivable OFFLINE — which is what lets the
 * authority pre-issue `grant_agent` before the DO ever runs (plan §11 O5).
 *
 * Lands in M5. The skeleton exists now so custody is a config-only swap:
 * everything upstream depends only on {@link KeyProvider}.
 */
export class KmsSeedKeyProvider implements KeyProvider {
  constructor(
    _custodianUrl: string,
    _userSub: string,
    _epoch: number,
  ) {
    throw new Error("KmsSeedKeyProvider (C3) lands in M5 — use DoResidentKeyProvider (C2)");
  }

  kid(): Uint8Array {
    throw new Error("not implemented");
  }
  publicKeyXY(): Promise<Uint8Array> {
    throw new Error("not implemented");
  }
  sign(_bytes: Uint8Array): Promise<Uint8Array> {
    throw new Error("not implemented");
  }
  rotate(_epoch: number): Promise<void> {
    throw new Error("not implemented");
  }
}
