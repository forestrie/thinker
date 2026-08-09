/**
 * Sealing delegation from workerd (FOR-390 / ADR-0052) — the agent's data
 * log is owned by the agent's own key (its creation grant's `grantData` =
 * the agent kid), so K(L) for that log lives in the DO and only the agent
 * can authorize a sealer to publish its checkpoints. Without this, writes
 * sequence but no checkpoint ever covers them and receipts 404 forever.
 *
 * A Workers port of the `forestrie delegate` CLI flow (public coordinator
 * endpoints only; no operator token):
 *
 *   1. GET  {coordinator}/api/logs/{logId}/pending-delegation — find the
 *      STANDING delegate-key entry (has `suggestedTtlSeconds`, no `mmrStart`).
 *   2. Verify the registrar voucher (COSE Sign1 over claims
 *      {1: sealerId, 2: epoch, 3: publicKey}) against the pinned registrar
 *      key — fail closed.
 *   3. Build the delegation certificate + on-chain proof over mmr 0..end,
 *      signed by K(L) (the DO key handle — never exported).
 *   4. POST {coordinator}/api/delegations/certificate.
 *
 * The PEM handling in the CLI is replaced by the provider's
 * `signingKeyPair()`; everything else is the same published-library code
 * (`@forestrie/delegation-cose`, `@forestrie/encoding`).
 */
import {
  buildDelegationCertificateEs256,
  buildDelegationCertificateKs256,
  decodeDelegatedCoseKeyFromBytes,
  parseDelegatedCoseKeyFromPayload,
  parseDelegationCertificate,
  signOnchainDelegationEs256,
  signOnchainDelegationKs256,
  type DelegationInput,
} from "@forestrie/delegation-cose";
import {
  decodeCborDeterministic,
  decodeCoseSign1,
  uuidToBytes,
  verifyCoseSign1WithParsedKey,
  type ParsedEcPublicKey,
} from "@forestrie/encoding";
import type { KeyProvider } from "../keys/provider.ts";

/** Horizon lease default: effectively unbounded (matches the CLI). */
const DEFAULT_HORIZON_MMR_END = Number.MAX_SAFE_INTEGER;

const CLAIM_SEALER_ID = 1;
const CLAIM_EPOCH = 2;
const CLAIM_PUBLIC_KEY = 3;

export class DelegateError extends Error {
  // Explicit field (not a TS parameter property): this module is imported by
  // node scripts via type stripping, which rejects parameter properties.
  readonly httpStatus?: number;
  constructor(message: string, httpStatus?: number) {
    super(`delegate: ${message}`);
    this.httpStatus = httpStatus;
  }
}

type StandingEntry = {
  delegatedPublicKey: string;
  suggestedTtlSeconds?: number;
  mmrStart?: number;
  voucher?: string;
  sealerId?: string;
  epoch?: number | string;
};

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

async function verifyVoucher(
  standing: StandingEntry,
  pinnedKeyXY: Uint8Array,
): Promise<void> {
  if (!standing.voucher || !standing.sealerId || standing.epoch === undefined)
    throw new DelegateError(
      "standing entry is missing its registrar voucher — refusing to bind",
    );
  if (pinnedKeyXY.length !== 64)
    throw new DelegateError("known sealer key must be 64 bytes x‖y");
  const pinned: ParsedEcPublicKey = {
    x: pinnedKeyXY.slice(0, 32),
    y: pinnedKeyXY.slice(32),
    curve: "P-256",
  };
  const voucherBytes = b64ToBytes(standing.voucher);
  if (!(await verifyCoseSign1WithParsedKey(voucherBytes, pinned)))
    throw new DelegateError("registrar voucher signature failed — refusing to bind");
  const decoded = decodeCoseSign1(voucherBytes);
  if (decoded === null) throw new DelegateError("registrar voucher undecodable");
  const claims = decodeCborDeterministic(decoded.payloadBstr);
  if (!(claims instanceof Map))
    throw new DelegateError("registrar voucher claims undecodable");
  if (claims.get(CLAIM_SEALER_ID) !== standing.sealerId)
    throw new DelegateError("registrar voucher sealerId mismatch");
  if (String(claims.get(CLAIM_EPOCH)) !== String(standing.epoch))
    throw new DelegateError("registrar voucher epoch mismatch");
  const vouchedKey = claims.get(CLAIM_PUBLIC_KEY);
  if (
    !(vouchedKey instanceof Uint8Array) ||
    !constantTimeEqual(vouchedKey, b64ToBytes(standing.delegatedPublicKey))
  )
    throw new DelegateError("registrar voucher publicKey mismatch");
}

export interface DelegateSealingParams {
  coordinatorUrl: string;
  /** The log to delegate — the agent's own data log (K(L) = agent key). */
  logId: string;
  /** Pinned registrar voucher key, base64 x‖y (64 bytes). */
  knownSealerKeyB64: string;
  horizonMmrEnd?: number;
  ttlSeconds?: number;
}

export interface DelegateSealingResult {
  sealerId: string;
  epoch: number | string;
  mmrEnd: number;
  expiresAt: number;
}

/**
 * Resolve the standing delegate-key entry for a log and verify its registrar
 * voucher — the shared front half of the ES256 (DO/agent) and KS256 (user
 * wallet, client-side) delegation paths.
 */
async function resolveStanding(
  params: DelegateSealingParams,
  fetchImpl: typeof fetch,
): Promise<StandingEntry> {
  const pendingRes = await fetchImpl(
    `${params.coordinatorUrl}/api/logs/${params.logId}/pending-delegation`,
  );
  if (!pendingRes.ok)
    throw new DelegateError(
      `pending-delegation fetch failed: ${(await pendingRes.text()).slice(0, 200)}`,
      pendingRes.status,
    );
  const pending = (await pendingRes.json()) as { entries?: StandingEntry[] };
  const standing = (pending.entries ?? []).find(
    (e) => e.suggestedTtlSeconds !== undefined && e.mmrStart === undefined,
  );
  if (!standing)
    throw new DelegateError(
      "no standing delegate-key entry for log — register a public root and a sealer delegate key first",
    );
  await verifyVoucher(standing, b64ToBytes(params.knownSealerKeyB64));
  return standing;
}

async function submitCertificate(
  params: DelegateSealingParams,
  standing: StandingEntry,
  certificate: Uint8Array,
  onchainSignature: Uint8Array,
  mmrStart: number,
  mmrEnd: number,
  fetchImpl: typeof fetch,
): Promise<DelegateSealingResult> {
  const info = parseDelegationCertificate(certificate);
  const submitRes = await fetchImpl(
    `${params.coordinatorUrl}/api/delegations/certificate`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        logId: params.logId,
        mmrStart,
        mmrEnd,
        delegatedPublicKey: standing.delegatedPublicKey,
        certificate: bytesToB64(certificate),
        issuedAt: info.issuedAt,
        expiresAt: info.expiresAt,
        onchainSignature: bytesToB64(onchainSignature),
      }),
    },
  );
  if (!submitRes.ok)
    throw new DelegateError(
      `certificate submit failed: ${(await submitRes.text()).slice(0, 200)}`,
      submitRes.status,
    );
  return {
    sealerId: standing.sealerId!,
    epoch: standing.epoch!,
    mmrEnd,
    expiresAt: info.expiresAt,
  };
}

/** Authorize the lane's vouched sealer for `logId`, signing with K(L). */
export async function delegateSealing(
  keys: KeyProvider,
  params: DelegateSealingParams,
  fetchImpl: typeof fetch = fetch,
): Promise<DelegateSealingResult> {
  if (!keys.signingKeyPair)
    throw new DelegateError("key provider cannot expose a signing key pair");
  const keyPair = await keys.signingKeyPair();

  const standing = await resolveStanding(params, fetchImpl);
  const mmrStart = 0;
  const mmrEnd = params.horizonMmrEnd ?? DEFAULT_HORIZON_MMR_END;
  const logIdHex32 = bytesToHex(uuidToBytes(params.logId));
  const delegatedPublicKeyBytes = b64ToBytes(standing.delegatedPublicKey);

  const certInput: DelegationInput = {
    logIdHex32,
    mmrStart,
    mmrEnd,
    delegatedPublicKeyCbor: delegatedPublicKeyBytes,
  };
  const ttlSeconds = params.ttlSeconds ?? standing.suggestedTtlSeconds;
  if (ttlSeconds !== undefined) certInput.ttlSeconds = ttlSeconds;
  const certificate = await buildDelegationCertificateEs256(certInput, keyPair);
  const delegated = parseDelegatedCoseKeyFromPayload(
    decodeDelegatedCoseKeyFromBytes(delegatedPublicKeyBytes),
  );
  const onchainProof = await signOnchainDelegationEs256(
    {
      logIdHex: logIdHex32,
      mmrStart,
      mmrEnd,
      delegatedKeyX: delegated.x,
      delegatedKeyY: delegated.y,
    },
    keyPair,
  );
  return submitCertificate(
    params,
    standing,
    certificate,
    onchainProof.signature,
    mmrStart,
    mmrEnd,
    fetchImpl,
  );
}

/**
 * KS256 variant (M5, O4 separate leaf): the USER's log is owned by their
 * wallet key (grant_user's grantData = the 20-byte address), so only the
 * wallet can authorize the lane's sealer for it. This runs CLIENT-side —
 * the demo client holds the wallet key; the DO never sees it. Same standing
 * entry + voucher gate as the ES256 path; only the signatures differ.
 * Without this lease the user's leaves sequence but never seal (receipts
 * stay pending) — the agent's leaves are unaffected.
 */
export async function delegateSealingKs256(
  walletPrivateKeyHex: string,
  rootSignerAddress: Uint8Array,
  params: DelegateSealingParams,
  fetchImpl: typeof fetch = fetch,
): Promise<DelegateSealingResult> {
  if (rootSignerAddress.length !== 20)
    throw new DelegateError("root signer address must be 20 bytes");
  const standing = await resolveStanding(params, fetchImpl);
  const mmrStart = 0;
  const mmrEnd = params.horizonMmrEnd ?? DEFAULT_HORIZON_MMR_END;
  const logIdHex32 = bytesToHex(uuidToBytes(params.logId));
  const delegatedPublicKeyBytes = b64ToBytes(standing.delegatedPublicKey);

  const certInput: DelegationInput = {
    logIdHex32,
    mmrStart,
    mmrEnd,
    delegatedPublicKeyCbor: delegatedPublicKeyBytes,
  };
  const ttlSeconds = params.ttlSeconds ?? standing.suggestedTtlSeconds;
  if (ttlSeconds !== undefined) certInput.ttlSeconds = ttlSeconds;
  const certificate = await buildDelegationCertificateKs256(
    certInput,
    rootSignerAddress,
    walletPrivateKeyHex,
  );
  const delegated = parseDelegatedCoseKeyFromPayload(
    decodeDelegatedCoseKeyFromBytes(delegatedPublicKeyBytes),
  );
  const onchainProof = signOnchainDelegationKs256(
    {
      logIdHex: logIdHex32,
      mmrStart,
      mmrEnd,
      delegatedKeyX: delegated.x,
      delegatedKeyY: delegated.y,
    },
    walletPrivateKeyHex,
  );
  return submitCertificate(
    params,
    standing,
    certificate,
    onchainProof.signature,
    mmrStart,
    mmrEnd,
    fetchImpl,
  );
}
