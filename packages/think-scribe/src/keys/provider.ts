/**
 * Signing-key custody seam for the Scribe (plan §8). The agent's statement
 * key lives behind this interface so custody can move C2 (DO-resident) →
 * C3 (KMS-seed derived) without touching the attestation or Forestrie code.
 */
export interface KeyProvider {
  /**
   * The COSE `kid` / grant binding for the current key: the first 32 bytes
   * of the 64-byte ES256 x‖y — i.e. the x coordinate (ARC-0019 §6:
   * "for 64-byte ES256 x||y, the first 32 bytes / x" must match
   * `statementSignerBindingBytes(grant)`).
   */
  kid(): Uint8Array;

  /** 64-byte ES256 public key, x‖y. `grantData` for the agent's grant. */
  publicKeyXY(): Promise<Uint8Array>;

  /**
   * ECDSA P-256 / SHA-256 over `bytes`, returned as the 64-byte IEEE P1363
   * r‖s that COSE ES256 embeds directly.
   */
  sign(bytes: Uint8Array): Promise<Uint8Array>;

  /**
   * Rotate to a new key under `epoch` (operator-maintained integer,
   * ADR-0050 grammar). Yields a new kid, which means the authority must
   * re-issue the grant naming it; keep the N−1 key available for overlap.
   */
  rotate(epoch: number): Promise<void>;

  /**
   * The current key as a WebCrypto pair (private non-extractable, sign-only)
   * for flows that sign through library code rather than `sign()` — the
   * sealing-delegation certificate (`@forestrie/delegation-cose`) is the
   * consumer. Optional: custody backends that cannot hand out a handle
   * (remote KMS signing) simply don't offer delegation from the agent.
   */
  signingKeyPair?(): Promise<CryptoKeyPair>;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
