// M1 smoke: wcc-1 challenge → wallet sign → session → per-user instance
// routing + bind-on-first-touch + agent identity (kid) stability.
// Run against `wrangler dev`:  node test/m1-smoke.mjs
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

const BASE = process.env.BASE_URL ?? "http://localhost:8787";
const WS_BASE = BASE.replace(/^http/, "ws");

const hex = (bytes) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function eip191Digest(message) {
  const body = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(
    `\x19Ethereum Signed Message:\n${body.length}`,
  );
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
  // noble's "recovered" layout is recovery-byte-FIRST; wallets emit r‖s‖v.
  const sig = secp256k1.sign(eip191Digest(chal.message), priv, {
    format: "recovered",
    prehash: false,
  });
  const wallet = new Uint8Array(65);
  wallet.set(sig.slice(1), 0); // r‖s
  wallet[64] = sig[0] + 27; // wallet-style v
  const res = await fetch(`${BASE}/auth/session`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ challenge: chal.challenge, signature: `0x${hex(wallet)}` }),
  });
  if (!res.ok) throw new Error(`session mint failed: ${res.status} ${await res.text()}`);
  return res.json();
}

const identityUrl = (sub) => `${BASE}/agents/scribe/user-${sub}/identity`;

async function getIdentity(sub, token) {
  return fetch(identityUrl(sub), { headers: { authorization: `Bearer ${token}` } });
}

function wsProbe(url) {
  return new Promise((resolve) => {
    const ws = new WebSocket(url);
    const done = (result) => {
      try {
        ws.close();
      } catch {}
      resolve(result);
    };
    const timer = setTimeout(() => done("timeout"), 5000);
    ws.addEventListener("open", () => {
      clearTimeout(timer);
      done("open");
    });
    ws.addEventListener("error", () => {
      clearTimeout(timer);
      done("error");
    });
  });
}

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
}

// --- user A: full wallet flow ---------------------------------------------
const privA = secp256k1.utils.randomSecretKey();
const sessionA = await mintSession(privA);
check("wcc-1 session minted", typeof sessionA.token === "string");
check("recovered sub = wallet address", sessionA.sub === addressOf(privA), sessionA.sub);

const id1 = await getIdentity(sessionA.sub, sessionA.token);
check("identity 200", id1.status === 200, `status ${id1.status}`);
const identity = await id1.json();
check("kid is 32 bytes hex", /^[0-9a-f]{64}$/.test(identity.kid ?? ""), identity.kid);
check(
  "kid = x coordinate of publicKeyXY",
  identity.publicKeyXY?.startsWith(identity.kid) && identity.publicKeyXY.length === 128,
);
check("principal bound", identity.principal === sessionA.sub);

const id2 = await (await getIdentity(sessionA.sub, sessionA.token)).json();
check("kid stable across requests", id2.kid === identity.kid);

// --- authz boundaries ------------------------------------------------------
const noToken = await fetch(identityUrl(sessionA.sub));
check("no token → 401", noToken.status === 401, `status ${noToken.status}`);

const privB = secp256k1.utils.randomSecretKey();
const sessionB = await mintSession(privB);
const cross = await getIdentity(sessionA.sub, sessionB.token);
check("B's session on A's instance → 403", cross.status === 403, `status ${cross.status}`);

const idB = await (await getIdentity(sessionB.sub, sessionB.token)).json();
check("B gets a distinct instance/kid", idB.kid !== identity.kid);

// --- websocket connect (query-param token, plan §5) ------------------------
const wsOk = await wsProbe(
  `${WS_BASE}/agents/scribe/user-${sessionA.sub}?token=${encodeURIComponent(sessionA.token)}`,
);
check("WS connect with ?token= opens", wsOk === "open", wsOk);

const wsNoAuth = await wsProbe(`${WS_BASE}/agents/scribe/user-${sessionA.sub}`);
check("WS connect without token rejected", wsNoAuth === "error", wsNoAuth);

// --- dev-mode principal ----------------------------------------------------
const dev = await fetch(`${BASE}/agents/scribe/user-alice/identity`, {
  headers: { authorization: "Bearer dev:alice" },
});
check("dev:alice reaches user-alice (DEV_AUTH)", dev.status === 200, `status ${dev.status}`);

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
