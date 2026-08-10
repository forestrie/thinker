// grant-authority — the M5 grant-issuing seam (plan §11 O5, O4; T4/T10).
// A small HTTP authority the Scribe's `RequestGrantProvider` calls at init,
// playing the role provision.sh played by hand: it holds the AUTH-log
// authority key and issues *creation grants* that endorse a signer by
// creating a fresh data log whose `grantData` names the signer (canopy
// grants.md §6 — extend-only follow-up grants on an initialized log are not
// accepted server-side, so a new writer key always gets a new log).
//
// Two signer shapes, one codepath:
//   POST /grants/agent {publicKeyXY}  grantData = 64-byte ES256 x‖y (the
//        agent kid). Called EITHER ahead of first touch with an offline-
//        derived C3 kid (pre-issue, O5) or by the DO at init (request) —
//        idempotent per kid, so both paths converge on the same grant.
//   POST /grants/user  {address}      grantData = 20-byte KS256 wallet
//        address (grant_user, O4 separate leaf). Also uploads the new log's
//        KS256 public root to the delegation coordinator (operator token) so
//        the USER can later authorize the lane sealer — canopy only
//        auto-forwards 64-byte ES256 owner keys.
//
// The books/payment-commitment stub (plan §9-C seam): any request may carry
// `paymentCommitment`; it is appended to .provision/books.jsonl before
// issuance. No enforcement — the x402 gate is a later cut; the seam exists.
//
// State: .provision/ (ids.env, authority.es256.pem, auth-grant.b64), issued
// grants under .provision/issued/. Requires provision.sh `up` to have run.
//
// Env: FORESTRIE_BASE_URL, DELEGATION_COORDINATOR_URL, COORDINATOR_APP_TOKEN
// (user grants only), GRANT_AUTHORITY_TOKEN (optional bearer), PORT.
import { createServer } from "node:http";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { delegateSealing } from "../packages/think-scribe/src/forestrie/delegate.ts";
import {
  bytesToForestrieGrantBase64,
  dataLogCreateExtendFlags,
  signGrantPayloadWithEs256Pem,
} from "@forestrie/grant-builder";
import {
  encodeGrantPayloadV0Canonical,
  mergeUnprotectedIntoCoseSign1,
  uuidToBytes,
} from "@forestrie/encoding";
import { HEADER_IDTIMESTAMP, HEADER_RECEIPT } from "@forestrie/grant-builder";
import {
  queryRegistrationOnce,
  registerGrant,
  resolveReceiptOnce,
} from "@forestrie/scrapi-client";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const P = join(ROOT, ".provision");
const ISSUED = join(P, "issued");
mkdirSync(ISSUED, { recursive: true });

const BASE_URL = process.env.FORESTRIE_BASE_URL ?? "https://api-a.forest-2.forestrie.dev";
const COORDINATOR_URL =
  process.env.DELEGATION_COORDINATOR_URL ?? "https://coordinator-a.forest-2.forestrie.dev";
const COORDINATOR_APP_TOKEN = process.env.COORDINATOR_APP_TOKEN ?? "";
const AUTHORITY_TOKEN = process.env.GRANT_AUTHORITY_TOKEN ?? "";
const PORT = Number(process.env.PORT ?? "8799");
/** Overall budget for grant sequencing + receipt (auth-log seal is ~1 min). */
const GRANT_TIMEOUT_MS = 240_000;
/** Registrar's public voucher key (as provision.sh) — not a secret. */
const KNOWN_SEALER_KEY =
  process.env.KNOWN_SEALER_KEY ??
  "z1YarLKXrsRe5egrwrFfbeYadd9lOqplKxbRuMGymHUOSY7YAfdOhhPWb3H72TrPMiMLw0CBMpDPXUGMEvbkOQ==";
/** Renew the auth-log sealing lease when under this runway (seconds). */
const SEALING_RENEW_MARGIN_S = 1800;
const SEALING_CHECK_INTERVAL_MS = 600_000;

const ids = Object.fromEntries(
  readFileSync(join(P, "ids.env"), "utf8")
    .split("\n")
    .filter((l) => l.startsWith("export "))
    .map((l) => l.slice(7).split("=", 2)),
);
const AUTH_LOG_ID = ids.AUTH_LOG_ID;
const ROOT_LOG_ID = ids.ROOT_LOG_ID;
if (!AUTH_LOG_ID || !ROOT_LOG_ID) {
  console.error("grant-authority: run provision.sh up first (.provision/ids.env)");
  process.exit(2);
}
const authorityPem = readFileSync(join(P, "authority.es256.pem"), "utf8");
const authGrantB64 = readFileSync(join(P, "auth-grant.b64"), "utf8").trim();

const hex = (b) => Buffer.from(b).toString("hex");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- auth-log sealing lease (the gap the 2026-08-10 outage exposed) --------
// Grant issuance blocks on the grant's inclusion receipt, which needs the
// AUTH log sealed — but the lease provision.sh signed at `up` time expires
// (~6h TTL) and nothing renewed it, so every grant request eventually 502'd
// with "grant receipt timed out (auth-log seal)". The authority holds K(L)
// for its own auth log, so it renews the lease itself: at startup, on a
// timer, and just-in-time before each issuance — the same delegate-at-drain
// pattern the Scribe DO uses for the agent's data log.

let authorityKeyPairPromise;
function authorityKeyPair() {
  authorityKeyPairPromise ??= (async () => {
    const priv = createPrivateKey(authorityPem);
    const pkcs8 = priv.export({ type: "pkcs8", format: "der" });
    const spki = createPublicKey(priv).export({ type: "spki", format: "der" });
    const alg = { name: "ECDSA", namedCurve: "P-256" };
    return {
      privateKey: await crypto.subtle.importKey("pkcs8", pkcs8, alg, false, ["sign"]),
      publicKey: await crypto.subtle.importKey("spki", spki, alg, true, ["verify"]),
    };
  })();
  return authorityKeyPairPromise;
}

let sealingExpiresAt = 0;
let sealingRenewal = null;
function renewAuthLogSealingIfNeeded() {
  if (sealingExpiresAt - Date.now() / 1000 > SEALING_RENEW_MARGIN_S) return Promise.resolve();
  sealingRenewal ??= (async () => {
    try {
      const result = await delegateSealing(
        { signingKeyPair: () => authorityKeyPair() },
        { coordinatorUrl: COORDINATOR_URL, logId: AUTH_LOG_ID, knownSealerKeyB64: KNOWN_SEALER_KEY },
      );
      sealingExpiresAt = result.expiresAt;
      console.log(
        `auth-log sealing lease renewed — sealer ${result.sealerId}, expires ${new Date(result.expiresAt * 1000).toISOString()}`,
      );
    } catch (err) {
      // Issuance degrades to the timeout the caller already handles; the
      // next check retries. Never crash the service over a renewal.
      console.error("auth-log sealing renewal failed (grants may time out until it succeeds):", err);
    } finally {
      sealingRenewal = null;
    }
  })();
  return sealingRenewal;
}

/** Issue a creation grant endorsing `grantData` on a fresh data log. */
async function issueCreationGrant(grantData) {
  // Just-in-time lease check: cheap no-op while the lease has runway, and
  // closes the window between timer ticks after a long idle stretch.
  await renewAuthLogSealingIfNeeded();
  const logId = crypto.randomUUID();
  const grant = {
    logId: uuidToBytes(logId),
    ownerLogId: uuidToBytes(AUTH_LOG_ID),
    grant: dataLogCreateExtendFlags(),
    maxHeight: 0,
    minGrowth: 0,
    grantData,
  };
  const payloadBytes = encodeGrantPayloadV0Canonical(grant);
  const sign1 = signGrantPayloadWithEs256Pem(payloadBytes, authorityPem);
  const grantBase64 = bytesToForestrieGrantBase64(sign1);

  const { statusUrl } = await registerGrant({
    baseUrl: BASE_URL,
    bootstrapLogId: ROOT_LOG_ID,
    grantBase64,
    parentGrantBase64: authGrantB64,
  });

  const deadline = Date.now() + GRANT_TIMEOUT_MS;
  let receiptUrl;
  let entryIdHex;
  for (;;) {
    if (Date.now() > deadline) throw new Error("grant sequencing timed out");
    const q = await queryRegistrationOnce({ baseUrl: BASE_URL, statusUrl });
    if (q.status === "receipt") {
      receiptUrl = q.receiptUrl;
      entryIdHex = q.entryIdHex;
      break;
    }
    if (q.status === "error") throw new Error(`grant status: ${q.detail}`);
    await sleep(Math.min(q.retryAfterMs ?? 2000, deadline - Date.now()));
  }
  let receipt;
  for (;;) {
    if (Date.now() > deadline) throw new Error("grant receipt timed out (auth-log seal)");
    const r = await resolveReceiptOnce({ receiptUrl });
    if (r.status === "receipt") {
      receipt = r.body;
      break;
    }
    if (r.status === "error") throw new Error(`grant receipt: HTTP ${r.httpStatus}`);
    await sleep(3000);
  }

  const completed = mergeUnprotectedIntoCoseSign1(
    sign1,
    new Map([
      [HEADER_RECEIPT, receipt],
      [HEADER_IDTIMESTAMP, Uint8Array.from(Buffer.from(entryIdHex.slice(0, 16), "hex"))],
    ]),
  );
  return { logId, entryIdHex, grantB64: bytesToForestrieGrantBase64(completed) };
}

/** Register a KS256-owned log's public root with the coordinator (operator). */
async function uploadKs256PublicRoot(logId, address) {
  if (!COORDINATOR_APP_TOKEN)
    throw new Error("COORDINATOR_APP_TOKEN not set — cannot register the user log's public root");
  const res = await fetch(`${COORDINATOR_URL}/api/logs/${logId}/public-root`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${COORDINATOR_APP_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ alg: -65799, key: Buffer.from(address).toString("base64") }),
  });
  if (!res.ok)
    throw new Error(`public-root upload failed: HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
}

function recordBooks(kind, subject, paymentCommitment) {
  appendFileSync(
    join(P, "books.jsonl"),
    JSON.stringify({
      at: new Date().toISOString(),
      kind,
      subject,
      paymentCommitment: paymentCommitment ?? null,
    }) + "\n",
  );
}

async function handleAgentGrant(body) {
  const xyHex = String(body.publicKeyXY ?? "");
  if (!/^[0-9a-f]{128}$/i.test(xyHex))
    return { status: 400, body: { error: "publicKeyXY must be 128 hex chars (64-byte ES256 x||y)" } };
  const kidHex = xyHex.slice(0, 64).toLowerCase();
  const issuedPath = join(ISSUED, `agent-${kidHex}.json`);
  if (existsSync(issuedPath))
    return { status: 200, body: { ...JSON.parse(readFileSync(issuedPath, "utf8")), preIssued: true } };

  recordBooks("grant_agent", kidHex, body.paymentCommitment);
  const issued = await issueCreationGrant(Uint8Array.from(Buffer.from(xyHex, "hex")));
  const out = { kind: "agent", kid: kidHex, logId: issued.logId, grantB64: issued.grantB64 };
  writeFileSync(issuedPath, JSON.stringify(out, null, 2));
  console.log(`issued grant_agent kid=${kidHex.slice(0, 16)}… log=${issued.logId}`);
  return { status: 201, body: { ...out, preIssued: false } };
}

async function handleUserGrant(body) {
  const addrHex = String(body.address ?? "").replace(/^0x/, "").toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(addrHex))
    return { status: 400, body: { error: "address must be a 20-byte hex KS256 wallet address" } };
  const issuedPath = join(ISSUED, `user-${addrHex}.json`);
  if (existsSync(issuedPath))
    return { status: 200, body: { ...JSON.parse(readFileSync(issuedPath, "utf8")), preIssued: true } };

  recordBooks("grant_user", addrHex, body.paymentCommitment);
  const address = Uint8Array.from(Buffer.from(addrHex, "hex"));
  const issued = await issueCreationGrant(address);
  await uploadKs256PublicRoot(issued.logId, address);
  const out = { kind: "user", address: `0x${addrHex}`, logId: issued.logId, grantB64: issued.grantB64 };
  writeFileSync(issuedPath, JSON.stringify(out, null, 2));
  console.log(`issued grant_user addr=0x${addrHex} log=${issued.logId}`);
  return { status: 201, body: { ...out, preIssued: false } };
}

const server = createServer(async (req, res) => {
  const send = (status, body) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  };
  try {
    if (req.method === "GET" && req.url === "/healthz")
      return send(200, { ok: true, authLogId: AUTH_LOG_ID, rootLogId: ROOT_LOG_ID });

    if (AUTHORITY_TOKEN && req.headers.authorization !== `Bearer ${AUTHORITY_TOKEN}`)
      return send(401, { error: "bad authority token" });

    if (req.method === "POST" && (req.url === "/grants/agent" || req.url === "/grants/user")) {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      let body;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
      } catch {
        return send(400, { error: "body must be JSON" });
      }
      const result =
        req.url === "/grants/agent" ? await handleAgentGrant(body) : await handleUserGrant(body);
      return send(result.status, result.body);
    }
    return send(404, { error: "unknown route" });
  } catch (err) {
    console.error(`${req.method} ${req.url} failed:`, err);
    return send(502, { error: String(err) });
  }
});

server.listen(PORT, () => {
  console.log(
    `grant-authority on :${PORT} — auth log ${AUTH_LOG_ID}, lane ${BASE_URL}` +
      (COORDINATOR_APP_TOKEN ? ", coordinator operator token loaded" : ", NO coordinator token (user grants will fail)"),
  );
  void renewAuthLogSealingIfNeeded();
  setInterval(() => void renewAuthLogSealingIfNeeded(), SEALING_CHECK_INTERVAL_MS).unref();
});
