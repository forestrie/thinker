// M2 smoke: the Forestrie write path from workerd against a real lane
// (S4 / plan T4–T8): sign in the DO → POST /register/{R}/entries (303) →
// status poll to sequenced → agent-signed sealing delegation → receipt →
// offline verify (via the forestrie CLI when FORESTRIE_CLI is set).
//
// Prereqs: `wrangler dev` with .dev.vars carrying FORESTRIE_BASE_URL,
// FORESTRIE_ROOT_LOG_ID, GRANT_AGENT, DELEGATION_COORDINATOR_URL,
// KNOWN_SEALER_KEY (from scripts/provision.sh), DEV_AUTH=1; and the grant
// provisioned for THIS instance's kid (provision.sh grant <publicKeyXY>).
// The agent log id comes from config/instance.jsonc (agentLogId).
//
// Run: node test/m2-smoke.mjs
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const BASE = process.env.BASE_URL ?? "http://localhost:8787";
const SUB = process.env.SMOKE_SUB ?? "m2tester";
const AUTH = { Authorization: `Bearer dev:${SUB}` };
const AGENT = `${BASE}/agents/scribe/user-${SUB}`;
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const OUT = join(dirname(fileURLToPath(import.meta.url)), ".out");
mkdirSync(OUT, { recursive: true });

let failures = 0;
function check(name, ok, detail = "") {
  const mark = ok ? "✓" : "✗";
  console.log(`  ${mark} ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
}

function instanceConfig() {
  const raw = readFileSync(join(ROOT, "config", "instance.jsonc"), "utf8");
  return JSON.parse(raw.replace(/^\s*\/\/.*$/gm, ""));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const cfg = instanceConfig();
  console.log(`M2 smoke — lane ${cfg.forestrieBaseUrl}, R ${cfg.R}`);

  // 1. Identity — the kid the grant must be bound to.
  const identity = await (await fetch(`${AGENT}/identity`, { headers: AUTH })).json();
  check("identity", typeof identity.kid === "string" && identity.kid.length === 64);

  // 2. Sealing delegation for the agent's own log (idempotent re-lease).
  const del = await fetch(`${AGENT}/delegate-sealing`, {
    method: "POST",
    headers: { ...AUTH, "Content-Type": "application/json" },
    body: JSON.stringify({ logId: cfg.agentLogId }),
  });
  const delBody = await del.json().catch(() => ({}));
  check("delegate-sealing", del.ok, del.ok ? `sealer ${delBody.sealerId}` : JSON.stringify(delBody));

  // 3. Sign + register from the DO.
  const sub = `urn:thinker:m2:smoke:${Date.now()}`;
  const reg = await fetch(`${AGENT}/register-test`, {
    method: "POST",
    headers: { ...AUTH, "Content-Type": "application/json" },
    body: JSON.stringify({ payload: { thinker: "m2-smoke", at: new Date().toISOString() }, sub }),
  });
  const regBody = await reg.json().catch(() => ({}));
  check("register 303 accepted", reg.ok && !!regBody.statusUrl, regBody.contentHash ?? JSON.stringify(regBody));
  check("kid matches identity", regBody.kid === identity.kid);
  if (!reg.ok) return;
  const statement = Buffer.from(regBody.statementB64, "base64");
  const stmtPath = join(OUT, "m2-statement.cose");
  writeFileSync(stmtPath, statement);

  // 4. Poll status (via the DO) until sequenced.
  let status;
  for (let i = 0; i < 30; i++) {
    status = await (
      await fetch(`${AGENT}/registration?status=${encodeURIComponent(regBody.statusUrl)}`, { headers: AUTH })
    ).json();
    if (status.state === "sequenced") break;
    await sleep((status.retryAfterSeconds ?? 1) * 1000);
  }
  check("sequenced", status?.state === "sequenced", status?.entryId);
  if (status?.state !== "sequenced") return;

  // 5. Receipt (via the DO) — checkpoint coverage lands within seconds once
  // the delegation stands, but allow a couple of minutes (T9).
  let receiptPath = join(OUT, "m2-receipt.cbor");
  let sealed = false;
  for (let i = 0; i < 24; i++) {
    const res = await fetch(`${AGENT}/registration?receipt=${encodeURIComponent(status.receiptUrl)}`, { headers: AUTH });
    if (res.status === 200) {
      writeFileSync(receiptPath, Buffer.from(await res.arrayBuffer()));
      sealed = true;
      break;
    }
    await sleep(5000);
  }
  check("receipt sealed", sealed, sealed ? `${status.entryId}` : "timed out (~2min)");
  if (!sealed) return;

  // 6. Offline verify — standard SCITT rung against the agent log's own key
  // (genesis-rooted verify does not span child logs yet; chain-anchored
  // verify is the stronger follow-up once the log anchors).
  const cli = process.env.FORESTRIE_CLI ?? join(process.env.HOME ?? "", "Dev/personal/forestrie/ietf-126-demo/forestrie");
  if (existsSync(cli)) {
    const knownKey = Buffer.from(identity.publicKeyXY, "hex").toString("base64");
    try {
      execFileSync(cli, [
        "verify",
        "--known-log-key", knownKey,
        "--receipt", receiptPath,
        "--payload", stmtPath,
        "--entry-id", status.entryId,
      ], { stdio: "pipe" });
      check("offline verify (known-log-key)", true);
    } catch (err) {
      check("offline verify (known-log-key)", false, String(err.stderr ?? err).slice(0, 300));
    }
  } else {
    console.log("  - offline verify skipped (forestrie CLI not found; set FORESTRIE_CLI)");
  }
}

await main();
console.log(failures ? `\n${failures} FAILED` : "\nall checks passed");
process.exit(failures ? 1 : 0);
