/**
 * SCRAPI registration client (plan T6/T7): POST the signed statement to the
 * forest ROOT path with the Forestrie-Grant credential, then follow the 303
 * status/receipt contract. Wire facts (verified against canopy
 * `register-signed-statement.ts` / `query-registration-status.ts`):
 *
 *  - `POST {base}/register/{R}/entries`, `Content-Type: application/cose`,
 *    body = raw COSE Sign1 bytes; the grant routes the statement to its
 *    data log. 303 Location = transient status URL keyed by
 *    `contentHash = sha256(statement bytes)`.
 *  - Status URL 303s to itself (Retry-After) until sequenced, then 303s to
 *    the permanent receipt URL `…/{massifHeight}/entries/{entryId}/receipt`.
 *  - The receipt URL 404s until the entry's checkpoint is sealed (T9:
 *    minutes-latent) — callers poll from a scheduled task, never inline.
 *
 * Uses `redirect: "manual"` throughout: Workers fetch would otherwise chase
 * the 303s and lose the Location/Retry-After signal.
 */

export interface RegisterAccepted {
  /** Transient status URL from the 303 Location. */
  statusUrl: string;
  /** sha256(statement) hex — the transient id in the status URL. */
  contentHash: string;
}

export type RegistrationStatus =
  | { state: "pending"; retryAfterSeconds: number }
  | { state: "sequenced"; receiptUrl: string; entryId: string };

export type ReceiptStatus =
  | { state: "pending" }
  | { state: "ready"; receipt: Uint8Array; contentType: string | null };

export class ScrapiError extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
  ) {
    super(`scrapi: HTTP ${status}: ${detail}`);
  }
}

async function problemDetail(res: Response): Promise<string> {
  // Errors are application/problem+cbor; surface printable fragments rather
  // than pulling in a CBOR decoder for the failure path.
  const bytes = new Uint8Array(await res.arrayBuffer());
  const text = new TextDecoder().decode(bytes);
  const printable = text.replace(/[^\x20-\x7e]+/g, " ").trim();
  return printable || res.statusText;
}

/** Register a signed statement; resolves on the 303 accept. */
export async function registerStatement(
  baseUrl: string,
  rootLogId: string,
  statement: Uint8Array,
  grantB64: string,
  fetchImpl: typeof fetch = fetch,
): Promise<RegisterAccepted> {
  const res = await fetchImpl(`${baseUrl}/register/${rootLogId}/entries`, {
    method: "POST",
    headers: {
      "Content-Type": "application/cose",
      Authorization: `Forestrie-Grant ${grantB64}`,
    },
    body: statement as BodyInit,
    redirect: "manual",
  });
  if (res.status !== 303)
    throw new ScrapiError(res.status, await problemDetail(res));
  const statusUrl = res.headers.get("Location");
  if (!statusUrl) throw new ScrapiError(303, "registration 303 without Location");

  const digest = await crypto.subtle.digest(
    "SHA-256",
    statement.buffer as ArrayBuffer,
  );
  const contentHash = [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return { statusUrl, contentHash };
}

/** One status poll — no sleeping here; the caller owns pacing (T7). */
export async function queryRegistration(
  statusUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<RegistrationStatus> {
  const res = await fetchImpl(statusUrl, { redirect: "manual" });
  if (res.status !== 303)
    throw new ScrapiError(res.status, await problemDetail(res));
  const location = res.headers.get("Location") ?? statusUrl;
  const entryMatch = /\/entries\/([0-9a-f]{32})\/receipt$/.exec(location);
  if (entryMatch)
    return { state: "sequenced", receiptUrl: location, entryId: entryMatch[1]! };
  const retryAfter = Number(res.headers.get("Retry-After") ?? "1");
  return {
    state: "pending",
    retryAfterSeconds: Number.isFinite(retryAfter) ? retryAfter : 1,
  };
}

/** One receipt fetch — 404 means the covering checkpoint isn't sealed yet. */
export async function fetchReceipt(
  receiptUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<ReceiptStatus> {
  const res = await fetchImpl(receiptUrl, { redirect: "manual" });
  if (res.status === 404) return { state: "pending" };
  if (res.status !== 200)
    throw new ScrapiError(res.status, await problemDetail(res));
  return {
    state: "ready",
    receipt: new Uint8Array(await res.arrayBuffer()),
    contentType: res.headers.get("Content-Type"),
  };
}
