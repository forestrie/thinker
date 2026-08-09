// M5 smoke: C3 custody + pre-issued grant on the derived kid (O5) + the O4
// flip to a separate user-endorsed leaf (plan §9 M5).
//
// The beats, in order:
//   1. Derive the agent kid OFFLINE from the custodian seed (C3) — before
//      the DO exists — and PRE-issue `grant_agent` on it via the authority.
//   2. First touch: the DO (KEY_PROVIDER=kms-seed) derives the same key —
//      /identity reports exactly the pre-issued kid (the O5 "yes").
//   3. An attested turn in ATTESTATION_MODE=separate registers TWO leaves:
//      the user's signed envelope under `grant_user` (requested from the
//      authority at drain — GrantProvider.request), then the agent's work
//      statement under the pre-issued `grant_agent` (collected, not
//      configured: no /configure-forestrie call anywhere in this smoke).
//   4. The USER's wallet authorizes sealing for the user's log (KS256,
//      client-side — the DO never sees the wallet key).
//   5. Both leaves get receipts; offline verification covers the user leaf
//      (KS256 delegation cert → delegated sealer key → inclusion).
//
// Prereqs: `wrangler dev` with M5 .dev.vars (KEY_PROVIDER=kms-seed,
// ATTESTATION_MODE=separate, GRANT_AUTHORITY_URL); scripts/authority.sh
// running; provision.sh state (.provision); ANTHROPIC_API_KEY valid.
//
// Run: node test/m5-smoke.mjs
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { delegateSealingKs256 } from "../../../packages/think-scribe/src/forestrie/delegate.ts";

const BASE = process.env.BASE_URL ?? "http://localhost:8787";
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const OUT = join(dirname(fileURLToPath(import.meta.url)), ".out");
mkdirSync(OUT, { recursive: true });

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`  ${ok ? "✓" : "✗"} ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
}
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// undici keep-alive vs workerd long gaps (grant issuance shell-outs): retry once.
async function fetchRetry(url, init) {
  try {
    return await fetch(url, init);
  } catch {
    await sleep(500);
    return fetch(url, init);
  }
}

function readDevVars() {
  return Object.fromEntries(
    readFileSync(join(ROOT, "apps", "scribe-worker", ".dev.vars"), "utf8")
      .split("\n")
      .filter((l) => l.includes("=") && !l.startsWith("#"))
      .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim()]),
  );
}

// --- wallet + wcc-1 session (m1 pattern) -----------------------------------
function eip191Digest(message) {
  const body = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
  const data = new Uint8Array(prefix.length + body.length);
  data.set(prefix);
  data.set(body, prefix.length);
  return keccak_256(data);
}
function addressOf(priv) {
  const pub = secp256k1.getPublicKey(priv, false);
  return `0x${hex(keccak_256(pub.slice(1)).slice(-20))}`;
}
async function mintSession(priv) {
  const chal = await (await fetch(`${BASE}/auth/challenge`, { method: "POST" })).json();
  const sig = secp256k1.sign(eip191Digest(chal.message), priv, {
    format: "recovered",
    prehash: false,
  });
  const wallet = new Uint8Array(65);
  wallet.set(sig.slice(1), 0);
  wallet[64] = sig[0] + 27;
  const res = await fetch(`${BASE}/auth/session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challenge: chal.challenge, signature: `0x${hex(wallet)}` }),
  });
  return res.json();
}

// --- minimal CBOR encode (envelope subset) ---------------------------------
function cborHead(major, arg, out) {
  const mt = major << 5;
  if (arg < 24) out.push(mt | arg);
  else if (arg < 0x100) out.push(mt | 24, arg);
  else if (arg < 0x10000) out.push(mt | 25, arg >> 8, arg & 0xff);
  else out.push(mt | 26, (arg >>> 24) & 0xff, (arg >>> 16) & 0xff, (arg >>> 8) & 0xff, arg & 0xff);
}
function cborEncode(value, out = []) {
  if (typeof value === "number") {
    if (value >= 0) cborHead(0, value, out);
    else cborHead(1, -1 - value, out);
  } else if (typeof value === "string") {
    const b = new TextEncoder().encode(value);
    cborHead(3, b.length, out);
    out.push(...b);
  } else if (value instanceof Uint8Array) {
    cborHead(2, value.length, out);
    out.push(...value);
  } else if (Array.isArray(value)) {
    cborHead(4, value.length, out);
    for (const item of value) cborEncode(item, out);
  } else if (value instanceof Map) {
    const entries = [...value.entries()].map(([k, v]) => {
      const kb = [];
      cborEncode(k, kb);
      return { kb, v };
    });
    entries.sort((a, b) => {
      const len = Math.min(a.kb.length, b.kb.length);
      for (let i = 0; i < len; i++) if (a.kb[i] !== b.kb[i]) return a.kb[i] - b.kb[i];
      return a.kb.length - b.kb.length;
    });
    cborHead(5, entries.length, out);
    for (const { kb, v } of entries) {
      out.push(...kb);
      cborEncode(v, out);
    }
  } else throw new Error(`unencodable: ${typeof value}`);
  return out;
}

// --- user input envelope (canopy KS256 COSE profile) -----------------------
function buildEnvelope(claims, priv) {
  const address = keccak_256(secp256k1.getPublicKey(priv, false).slice(1)).slice(-20);
  const payload = new TextEncoder().encode(JSON.stringify(claims));
  const protectedMap = new Map([
    [1, -65799],
    [3, "application/json"],
    [4, address],
  ]);
  const protectedBytes = Uint8Array.from(cborEncode(protectedMap));
  const sigStructure = Uint8Array.from(
    cborEncode(["Signature1", protectedBytes, new Uint8Array(0), payload]),
  );
  const hash = keccak_256(sigStructure);
  const recovered = secp256k1.sign(hash, priv, { format: "recovered", prehash: false });
  const signature = new Uint8Array(65);
  signature.set(recovered.slice(1), 0);
  signature[64] = recovered[0];
  return Uint8Array.from(cborEncode([protectedBytes, new Map(), payload, signature]));
}

function runVerifier(args) {
  try {
    const stdout = execFileSync("./scripts/verify-receipts.sh", args, {
      cwd: ROOT,
      stdio: "pipe",
      timeout: 120_000,
    }).toString();
    return { status: 0, stdout };
  } catch (err) {
    return { status: err.status ?? 1, stdout: String(err.stdout ?? "") + String(err.stderr ?? "") };
  }
}

async function main() {
  // A FRESH wallet (≠ m3/m4) so this DO instance is born on C3 custody.
  const priv = Uint8Array.from({ length: 32 }, (_, i) => i + 7);
  const sub = addressOf(priv).toLowerCase();
  const AGENT = `${BASE}/agents/scribe/user-${sub}`;
  const devVars = readDevVars();
  const authorityUrl = devVars.GRANT_AUTHORITY_URL ?? "http://localhost:8799";
  console.log(`M5 smoke — wallet user ${sub}`);

  const health = await fetch(`${authorityUrl}/healthz`).then((r) => r.json()).catch(() => null);
  check("grant-authority up", health?.ok === true, health?.authLogId);
  if (!health?.ok) return;

  // 1. O5 counterfactual: derive the agent kid OFFLINE, before the DO runs.
  const derived = JSON.parse(
    execFileSync("node", ["scripts/derive-agent-kid.mjs", "--user-sub", sub], {
      cwd: ROOT,
      stdio: "pipe",
    }).toString(),
  );
  check("offline kid derivation (C3)", /^[0-9a-f]{64}$/.test(derived.kid), `kid ${derived.kid.slice(0, 16)}…`);

  // 2. PRE-issue grant_agent on the derived kid (authority; lane writes).
  console.log("  … pre-issuing grant_agent on the derived kid (lane writes)");
  const preRes = await fetch(`${authorityUrl}/grants/agent`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      publicKeyXY: derived.publicKeyXY,
      paymentCommitment: "books:m5-smoke:pre-issue",
    }),
  });
  const pre = await preRes.json();
  check("grant_agent pre-issued on derived kid", preRes.ok && !!pre.grantB64, `agent log ${pre.logId}`);

  // 3. First touch — the DO derives the SAME key.
  const session = await mintSession(priv);
  check("wcc-1 session", typeof session.token === "string", session.sub);
  const AUTH = { Authorization: `Bearer ${session.token}` };

  const identity = await (await fetchRetry(`${AGENT}/identity`, { headers: AUTH })).json();
  check("DO runs C3 custody", identity.keyProvider === "kms-seed", identity.keyProvider);
  check(
    "DO kid == offline pre-issued kid (O5)",
    identity.kid === derived.kid,
    `kid ${String(identity.kid).slice(0, 16)}…`,
  );

  // 4. Agent-log sealing delegation (DO signs with the derived key).
  const del = await fetchRetry(`${AGENT}/delegate-sealing`, {
    method: "POST",
    headers: { ...AUTH, "Content-Type": "application/json" },
    body: JSON.stringify({ logId: pre.logId }),
  });
  check("agent delegate-sealing", del.ok, del.ok ? `sealer ${(await del.json()).sealerId}` : await del.text());

  // 5. The attested turn (separate mode: two leaves).
  const claims = {
    input: "Reply with one short sentence about attested conversations.",
    sessionId: `m5-smoke-${Date.now()}`,
    issuedAt: new Date().toISOString(),
    nonce: hex(crypto.getRandomValues(new Uint8Array(16))),
  };
  const envelope = buildEnvelope(claims, priv);
  const envelopeB64 = Buffer.from(envelope).toString("base64");
  const expectedWorkId = createHash("sha256").update(envelope).digest("hex");

  const turn = await fetchRetry(`${AGENT}/turn`, {
    method: "POST",
    headers: { ...AUTH, "Content-Type": "application/json" },
    body: JSON.stringify({ envelopeB64 }),
  });
  const turnBody = await turn.json().catch(async () => ({ err: await turn.text() }));
  check("attested turn admitted", turn.ok && turnBody.accepted, turnBody.status ?? JSON.stringify(turnBody));
  if (!turn.ok) return;

  // 6. Agent leaf → receipted; user leaf registered along the way. The user
  // grant is requested from the authority DURING the drain (~10s extra).
  let work;
  const seen = new Set();
  for (let i = 0; i < 90; i++) {
    work = await (await fetchRetry(`${AGENT}/work?id=${expectedWorkId}`, { headers: AUTH })).json();
    const state = `${work.state}/${work.userLeaf?.state ?? "-"}`;
    if (!seen.has(state)) {
      seen.add(state);
      console.log(`  … work ${state}`);
    }
    if (["receipted", "error"].includes(work.state)) break;
    await sleep(4000);
  }
  check(
    "agent leaf receipted (pre-issued grant collected via request-at-init)",
    work?.state === "receipted",
    work?.state === "error" ? work.error : `entry ${work?.entryId}`,
  );
  if (work?.state !== "receipted") return;

  const identity2 = await (await fetchRetry(`${AGENT}/identity`, { headers: AUTH })).json();
  check(
    "DO collected the PRE-issued agent grant (no configure call)",
    identity2.agentLogId === pre.logId,
    `agent log ${identity2.agentLogId}`,
  );
  check("grant_user issued at drain (user log exists)", !!identity2.userLogId, `user log ${identity2.userLogId}`);
  check(
    "user leaf registered on the user's log",
    ["registered", "sequenced", "receipted"].includes(work.userLeaf?.state),
    work.userLeaf?.state ?? work.userLeaf?.error,
  );

  // 7. The USER authorizes sealing for their log — wallet-signed, client-side.
  const knownSealerKeyB64 = devVars.KNOWN_SEALER_KEY;
  const coordinatorUrl = devVars.DELEGATION_COORDINATOR_URL;
  let userDel = null;
  try {
    userDel = await delegateSealingKs256(
      hex(priv),
      Uint8Array.from(Buffer.from(sub.slice(2), "hex")),
      {
        coordinatorUrl,
        logId: identity2.userLogId,
        knownSealerKeyB64,
      },
    );
  } catch (err) {
    check("user delegate-sealing (KS256, client wallet)", false, String(err));
  }
  if (userDel)
    check("user delegate-sealing (KS256, client wallet)", true, `sealer ${userDel.sealerId}`);

  // 8. User leaf → receipted (sealing is reactive; give it a few minutes).
  if (userDel) {
    for (let i = 0; i < 60; i++) {
      work = await (await fetchRetry(`${AGENT}/work?id=${expectedWorkId}`, { headers: AUTH })).json();
      const state = `${work.state}/${work.userLeaf?.state ?? "-"}`;
      if (!seen.has(state)) {
        seen.add(state);
        console.log(`  … work ${state}`);
      }
      if (["receipted", "error"].includes(work.userLeaf?.state)) break;
      await sleep(5000);
    }
    check(
      "user leaf receipted",
      work.userLeaf?.state === "receipted",
      work.userLeaf?.state === "error" ? work.userLeaf.error : `entry ${work.userLeaf?.entryId}`,
    );
  }

  // 9. Export + offline verification (incl. the user leaf's KS256 chain).
  const exportRes = await fetchRetry(`${AGENT}/receipts`, { headers: AUTH });
  const exported = await exportRes.json();
  check("receipts export", exportRes.ok && Array.isArray(exported.works));
  check("export declares separate mode", exported.attestationMode === "separate");
  const exportPath = join(OUT, "m5-receipts.json");
  writeFileSync(exportPath, JSON.stringify(exported, null, 2));

  const clean = runVerifier([
    "--export", exportPath,
    "--work", expectedWorkId,
    "--out", join(OUT, "m5-verify"),
  ]);
  check("verify-receipts.sh passes", clean.status === 0, clean.status === 0 ? "" : clean.stdout.slice(-400));
  check(
    "verifier walked the user leaf",
    clean.stdout.includes("user-leaf-inclusion"),
    "user-leaf-delegation → window → signature → inclusion",
  );

  // 10. Corrupt the USER leaf's receipt → its verification chain fails.
  if (work.userLeaf?.receiptB64) {
    const broken = structuredClone(exported);
    for (const w of broken.works)
      if (w.workId === expectedWorkId) {
        const raw = Buffer.from(w.userLeaf.receiptB64, "base64");
        raw[raw.length - 1] ^= 0xff;
        w.userLeaf.receiptB64 = raw.toString("base64");
      }
    const brokenPath = join(OUT, "m5-receipts-user-broken.json");
    writeFileSync(brokenPath, JSON.stringify(broken, null, 2));
    const bad = runVerifier(["--export", brokenPath, "--work", expectedWorkId]);
    check("corrupted USER receipt fails verification", bad.status !== 0 && bad.stdout.includes("user-leaf"));
  }
}

await main();
console.log(failures ? `\n${failures} FAILED` : "\nall checks passed");
process.exit(failures ? 1 : 0);
