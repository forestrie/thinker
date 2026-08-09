import { p256 } from "@noble/curves/nist.js";
import type { KeyProvider } from "./provider.ts";

/**
 * C3 — the preferred target custody (plan §8, D4): derive the per-user
 * agent key from a KMS-custodied seed instead of storing anything.
 *
 *   seed  = custodianMAC("forestrie/agent-signer-seed/v1" ‖ userSub ‖ epoch)
 *   d     = HKDF(seed) → P-256 scalar (rejection-sampled into [1, n−1])
 *   sign locally; one signature per commitment — the async drain absorbs
 *   the custodian-MAC hop (brainstorm 04 §5).
 *
 * Because the derivation is a pure function of `userSub` and `epoch`, the
 * kid is counterfactually derivable OFFLINE — which is what lets the
 * authority pre-issue `grant_agent` before the DO ever runs (plan §11 O5):
 * anyone holding the custodian MAC capability can run the same derivation in
 * a provisioning script (scripts/derive-agent-kid.mjs) and endorse the kid
 * on a fresh agent log ahead of first touch.
 *
 * The custodian seam is {@link CustodianMac}: production is a narrow KMS MAC
 * endpoint (the key never leaves the KMS; only MACs come out), dev is
 * {@link localSeedCustodianMac} over a locally-held 32-byte secret
 * (env `KMS_SEED_SECRET`) — swapping is config-only, everything downstream
 * is identical.
 *
 * The derived scalar is imported into WebCrypto as a NON-extractable JWK so
 * signing (and the sealing-delegation `signingKeyPair()`) go through a
 * handle; the scalar bytes are dropped after import.
 */

/** MAC under the custodian-held key. Prod: KMS endpoint. Dev: local HMAC. */
export type CustodianMac = (info: Uint8Array) => Promise<Uint8Array>;

/** Dev custodian: HMAC-SHA256 under a locally-held 32-byte secret. */
export function localSeedCustodianMac(secret: Uint8Array): CustodianMac {
  if (secret.length !== 32)
    throw new Error(`local custodian seed must be 32 bytes, got ${secret.length}`);
  return async (info: Uint8Array) => {
    const key = await crypto.subtle.importKey(
      "raw",
      secret as BufferSource,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, info as BufferSource));
  };
}

const SEED_LABEL = "forestrie/agent-signer-seed/v1";
const HKDF_SALT = "forestrie/agent-signer-p256/v1";

/** NUL-delimited derivation input: label, userSub, epoch (decimal). */
export function custodianMacInfo(userSub: string, epoch: number): Uint8Array {
  if (!Number.isInteger(epoch) || epoch < 1)
    throw new Error(`epoch must be a positive integer, got ${epoch}`);
  if (userSub.includes("\u0000"))
    throw new Error("userSub must not contain NUL");
  return new TextEncoder().encode(`${SEED_LABEL}\u0000${userSub}\u0000${epoch}`);
}

const P256_ORDER = p256.Point.Fn.ORDER;

function bytesToBigInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function bigIntTo32(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * HKDF-SHA256 the seed into a P-256 scalar, rejection-sampling candidates
 * (info = `p256-scalar/{counter}`) until one lands in [1, n−1]. A single
 * candidate is accepted with probability ≈ 1 − 2⁻³²; the loop is for
 * correctness, not expectation.
 */
async function deriveScalar(seed: Uint8Array): Promise<Uint8Array> {
  const ikm = await crypto.subtle.importKey("raw", seed as BufferSource, "HKDF", false, [
    "deriveBits",
  ]);
  const salt = new TextEncoder().encode(HKDF_SALT);
  for (let counter = 0; counter < 64; counter++) {
    const bits = await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: salt as BufferSource,
        info: new TextEncoder().encode(`p256-scalar/${counter}`) as BufferSource,
      },
      ikm,
      256,
    );
    const candidate = bytesToBigInt(new Uint8Array(bits));
    if (candidate >= 1n && candidate < P256_ORDER) return bigIntTo32(candidate);
  }
  throw new Error("kms-seed: scalar derivation failed 64 rejection rounds");
}

function base64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export interface DerivedAgentKey {
  /** 64-byte ES256 x‖y — the grant `grantData`. */
  publicKeyXY: Uint8Array;
  /** First 32 bytes of x‖y (the x coordinate) — the COSE `kid`. */
  kid: Uint8Array;
  /** Non-extractable WebCrypto pair for signing/delegation. */
  keyPair: CryptoKeyPair;
}

/**
 * Full derivation, custodian MAC → signing handle. Also the offline path:
 * scripts call this with the dev custodian to pre-compute the kid (O5).
 */
export async function deriveAgentKey(
  custodianMac: CustodianMac,
  userSub: string,
  epoch: number,
): Promise<DerivedAgentKey> {
  const seed = await custodianMac(custodianMacInfo(userSub, epoch));
  const d = await deriveScalar(seed);
  const point = p256.getPublicKey(d, false); // 65-byte uncompressed
  const publicKeyXY = point.slice(1);

  const jwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    d: base64Url(d),
    x: base64Url(publicKeyXY.slice(0, 32)),
    y: base64Url(publicKeyXY.slice(32)),
  };
  d.fill(0);
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  delete jwk.d;
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
  return {
    publicKeyXY,
    kid: publicKeyXY.slice(0, 32),
    keyPair: { privateKey, publicKey },
  };
}

export class KmsSeedKeyProvider implements KeyProvider {
  // Explicit fields, not TS parameter properties: this module is imported by
  // the offline derive script via node type stripping, which rejects them.
  private readonly custodianMac: CustodianMac;
  private readonly userSub: string;
  private currentEpoch: number;
  private derived: DerivedAgentKey;

  private constructor(
    custodianMac: CustodianMac,
    userSub: string,
    epoch: number,
    derived: DerivedAgentKey,
  ) {
    this.custodianMac = custodianMac;
    this.userSub = userSub;
    this.currentEpoch = epoch;
    this.derived = derived;
  }

  static async load(
    custodianMac: CustodianMac,
    userSub: string,
    epoch: number,
  ): Promise<KmsSeedKeyProvider> {
    const derived = await deriveAgentKey(custodianMac, userSub, epoch);
    return new KmsSeedKeyProvider(custodianMac, userSub, epoch, derived);
  }

  epoch(): number {
    return this.currentEpoch;
  }

  kid(): Uint8Array {
    return this.derived.kid;
  }

  async publicKeyXY(): Promise<Uint8Array> {
    return this.derived.publicKeyXY;
  }

  async sign(bytes: Uint8Array): Promise<Uint8Array> {
    const sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      this.derived.keyPair.privateKey,
      bytes as BufferSource,
    );
    return new Uint8Array(sig); // 64-byte P1363 r‖s
  }

  async signingKeyPair(): Promise<CryptoKeyPair> {
    return this.derived.keyPair;
  }

  /**
   * Rotation is re-derivation: nothing is stored, so moving the epoch IS the
   * rotation. The new kid needs a new grant (the authority re-endorses it —
   * `RequestGrantProvider` re-requests when the stored grant's kid no longer
   * matches). N−1 keys stay derivable for overlap by construction.
   */
  async rotate(epoch: number): Promise<void> {
    if (epoch <= this.currentEpoch)
      throw new Error(
        `rotate: epoch ${epoch} must exceed current epoch ${this.currentEpoch}`,
      );
    this.derived = await deriveAgentKey(this.custodianMac, this.userSub, epoch);
    this.currentEpoch = epoch;
  }
}
