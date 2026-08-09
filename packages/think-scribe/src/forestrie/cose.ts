/**
 * COSE Sign1 signed-statement builder (plan T5). Produces the same shape as
 * the `forestrie sign-statement` CLI: plain COSE Sign1, ES256, with alg,
 * content type, kid and CWT claims (label 15: iss/sub) all in the protected
 * header. Canopy validates only structure, the `kid` ↔ `grantData` binding,
 * and the signature (ARC-0019 §6); iss/sub are SCITT hygiene.
 */
import { cborEncode, type CborMap } from "./cbor.ts";
import type { KeyProvider } from "../keys/provider.ts";

const ALG = 1; // COSE header label
const CONTENT_TYPE = 3;
const KID = 4;
const CWT_CLAIMS = 15; // RFC 9597
const CWT_ISS = 1;
const CWT_SUB = 2;
const ES256 = -7;

export interface SignedStatementInput {
  payload: Uint8Array;
  /** e.g. "application/json" */
  contentType: string;
  /** CWT sub claim — the statement's subject (e.g. a urn per work unit). */
  sub: string;
  /** CWT iss claim; defaults to the signer's kid as hex. */
  iss?: string;
}

/** Build and sign a COSE Sign1 signed statement with the agent key. */
export async function buildSignedStatement(
  keys: KeyProvider,
  input: SignedStatementInput,
): Promise<Uint8Array> {
  const kid = keys.kid();
  const iss =
    input.iss ?? [...kid].map((b) => b.toString(16).padStart(2, "0")).join("");

  const claims: CborMap = new Map();
  claims.set(CWT_ISS, iss);
  claims.set(CWT_SUB, input.sub);

  const protectedMap: CborMap = new Map();
  protectedMap.set(ALG, ES256);
  protectedMap.set(CONTENT_TYPE, input.contentType);
  protectedMap.set(KID, kid);
  protectedMap.set(CWT_CLAIMS, claims);
  const protectedBytes = cborEncode(protectedMap);

  // Sig_structure for Signature1 (RFC 9052 §4.4), empty external_aad.
  const sigStructure = cborEncode([
    "Signature1",
    protectedBytes,
    new Uint8Array(0),
    input.payload,
  ]);
  const signature = await keys.sign(sigStructure);

  // COSE_Sign1 = [protected bstr, unprotected map, payload bstr, signature bstr]
  return cborEncode([protectedBytes, new Map(), input.payload, signature]);
}
