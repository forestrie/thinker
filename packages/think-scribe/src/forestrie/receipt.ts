/**
 * Offline receipt verification for a Scribe work unit (plan T8, §2) — the
 * Auditor stand-in primitive behind `scripts/verify-receipts.sh`, and the
 * seam the proof panel (MU) and the Auditor agent (direction B) reuse.
 *
 * Deliberately a subpath export (`@forestrie/think-scribe/forestrie/receipt`),
 * NOT re-exported from the package index: it pulls @forestrie/receipt-verify
 * (and transitively chain-rpc), which the Scribe worker bundle never needs —
 * the DO only collects receipt bytes, it does not verify them.
 *
 * Trust model (cut 1): "known log key" (FOR-297). The agent's data log is
 * owned by the agent key itself (provision.sh `grant`), so the receipt's
 * delegation certificate is verified under the agent's ES256 public key and
 * the sealer key extracted from it — fully offline, log absent. The binding
 * "this key owns that log" is asserted by key provenance (obtain publicKeyXY
 * out of band, e.g. from GET /identity at enrolment time — not from the same
 * export you are auditing); the genesis-trust-root walk is a later rung.
 */
import {
  entryIdHexToIdtimestampBe8,
  importEs256PublicKeyFromGrantDataXy64,
  verifyReceiptOfflineWithKeys,
} from "@forestrie/receipt-verify";
import { cborDecode, cborEncode, type CborMap } from "./cbor.ts";
import { sha256Hex } from "../attestation.ts";

const ALG = 1;
const KID = 4;
const ES256 = -7;

export class ReceiptError extends Error {}

/** A COSE Sign1 signed statement, opened for inspection and verification. */
export interface ParsedStatement {
  protectedHeader: CborMap;
  /** Signer kid from the protected header (agent: x-coordinate first-32). */
  kid: Uint8Array;
  payload: Uint8Array;
  /** The work-statement JSON claims, if the payload parses as JSON. */
  payloadJson: Record<string, unknown> | null;
  signature: Uint8Array;
  /** Sig_structure bytes — what the signature is actually over. */
  sigStructure: Uint8Array;
}

export function parseSignedStatement(statement: Uint8Array): ParsedStatement {
  let decoded;
  try {
    decoded = cborDecode(statement);
  } catch (err) {
    throw new ReceiptError(`statement is not decodable CBOR: ${err}`);
  }
  if (!Array.isArray(decoded) || decoded.length !== 4)
    throw new ReceiptError("statement is not a COSE Sign1 4-array");
  const [protectedBytes, , payload, signature] = decoded;
  if (
    !(protectedBytes instanceof Uint8Array) ||
    !(payload instanceof Uint8Array) ||
    !(signature instanceof Uint8Array)
  )
    throw new ReceiptError("statement protected/payload/signature must be byte strings");

  const header = cborDecode(protectedBytes);
  if (!(header instanceof Map) || header.get(ALG) !== ES256)
    throw new ReceiptError("statement alg must be ES256 (-7)");
  const kid = header.get(KID);
  if (!(kid instanceof Uint8Array))
    throw new ReceiptError("statement kid must be a byte string");

  let payloadJson: Record<string, unknown> | null = null;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(payload));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed))
      payloadJson = parsed as Record<string, unknown>;
  } catch {
    // Non-JSON payloads are legal COSE; binding checks will just fail.
  }

  const sigStructure = cborEncode([
    "Signature1",
    protectedBytes,
    new Uint8Array(0),
    payload,
  ]);
  return { protectedHeader: header, kid, payload, payloadJson, signature, sigStructure };
}

/** Verify the agent's ES256 signature on a parsed statement (T5). */
export async function verifyStatementSignature(
  parsed: ParsedStatement,
  publicKeyXY: Uint8Array,
): Promise<boolean> {
  if (publicKeyXY.length !== 64)
    throw new ReceiptError("agent public key must be 64 bytes x‖y");
  const point = new Uint8Array(65);
  point[0] = 0x04;
  point.set(publicKeyXY, 1);
  const key = await crypto.subtle.importKey(
    "raw",
    point as BufferSource,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    parsed.signature as BufferSource,
    parsed.sigStructure as BufferSource,
  );
}

/**
 * One work unit as the Scribe exports it (`GET /receipts`). Everything the
 * auditor needs travels together; `currentOutputText` is what the DO
 * *currently* claims the assistant said for this turn's leaf — recomputed
 * live from its session store at export time, which is exactly the field
 * the tamper beat drives apart from the receipted commitment.
 */
export interface WorkExport {
  workId: string;
  state: string;
  envelopeB64: string;
  statementB64?: string;
  entryId?: string;
  receiptB64?: string;
  leafId?: string;
  currentOutputText?: string | null;
}

export interface WorkCheck {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface WorkVerifyResult {
  ok: boolean;
  checks: WorkCheck[];
}

function decodeBase64(value: string): Uint8Array {
  const bin = atob(value);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Verify one receipted work unit fully offline. Checks, in dependency order:
 *
 *  1. statement-signature — the agent's ES256 COSE Sign1 verifies under the
 *     caller-trusted key, and the statement kid matches it.
 *  2. receipt — inclusion proof + sealed checkpoint + delegation certificate
 *     verify under the same key as log owner (known-log-key rung).
 *  3. work-binding — workId = SHA-256(user envelope); the committed
 *     statement names that workId and embeds that exact envelope (§7).
 *  4. transcript-binding — SHA-256 of the DO's currently-claimed output text
 *     equals the committed outputHash. This is the check the tamper beat
 *     breaks: rewrite the DO's memory and the receipts no longer match.
 */
export async function verifyWorkReceipt(
  work: WorkExport,
  agentPublicKeyXY: Uint8Array,
): Promise<WorkVerifyResult> {
  const checks: WorkCheck[] = [];
  const fail = (name: string, detail: string): WorkVerifyResult => {
    checks.push({ name, ok: false, detail });
    return { ok: false, checks };
  };

  if (!work.statementB64 || !work.receiptB64 || !work.entryId)
    return fail(
      "artifacts",
      `work ${work.workId.slice(0, 12)}… is not receipted (state=${work.state})`,
    );

  let parsed: ParsedStatement;
  const statement = decodeBase64(work.statementB64);
  try {
    parsed = parseSignedStatement(statement);
  } catch (err) {
    return fail("statement-signature", String(err));
  }
  const kidHex = [...parsed.kid]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const keyXHex = [...agentPublicKeyXY.slice(0, parsed.kid.length)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const sigOk =
    kidHex === keyXHex && (await verifyStatementSignature(parsed, agentPublicKeyXY));
  checks.push({
    name: "statement-signature",
    ok: sigOk,
    detail: sigOk ? `kid ${kidHex.slice(0, 16)}…` : "agent signature/kid mismatch",
  });

  let receiptOk = false;
  let receiptDetail: string;
  try {
    const result = await verifyReceiptOfflineWithKeys({
      receiptCbor: decodeBase64(work.receiptB64),
      payload: statement,
      idtimestampBe8: entryIdHexToIdtimestampBe8(work.entryId),
      trustKeys: [await importEs256PublicKeyFromGrantDataXy64(agentPublicKeyXY)],
    });
    receiptOk = result.ok;
    receiptDetail = result.ok
      ? `entry ${work.entryId}`
      : `${result.stage}: ${result.reason ?? "failed"}`;
  } catch (err) {
    receiptDetail = String(err);
  }
  checks.push({ name: "receipt", ok: receiptOk, detail: receiptDetail });

  const envelope = decodeBase64(work.envelopeB64);
  const claims = parsed.payloadJson ?? {};
  const workIdOk =
    (await sha256Hex(envelope)) === work.workId &&
    claims.workId === work.workId &&
    claims.userEnvelope === work.envelopeB64;
  checks.push({
    name: "work-binding",
    ok: workIdOk,
    detail: workIdOk
      ? `workId ${work.workId.slice(0, 16)}…`
      : "workId/envelope do not match the committed statement",
  });

  if (typeof work.currentOutputText === "string") {
    const currentHash = await sha256Hex(
      new TextEncoder().encode(work.currentOutputText),
    );
    const outputOk = currentHash === claims.outputHash;
    checks.push({
      name: "transcript-binding",
      ok: outputOk,
      detail: outputOk
        ? `outputHash ${currentHash.slice(0, 16)}…`
        : `DO claims ${currentHash.slice(0, 16)}… but the receipted statement commits ${String(claims.outputHash).slice(0, 16)}… — the record has been tampered`,
    });
  } else {
    checks.push({
      name: "transcript-binding",
      ok: true,
      detail: "skipped — no current transcript claim in the export",
    });
  }

  return { ok: checks.every((c) => c.ok), checks };
}
