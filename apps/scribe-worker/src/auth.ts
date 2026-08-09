import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

/**
 * Minimal self-contained wcc-1 verify (plan §4, ARC-0023 §4).
 *
 * The mandate BFF implements wcc-1 against the delegation-coordinator, but
 * the mandate fork is deferred (D6), so cut 1 runs the same shape locally:
 *
 *   POST /auth/challenge → envelope (domain, origin, scopes, nonce ~120s)
 *   wallet signs the canonical message (EIP-191 personal_sign, KS256)
 *   POST /auth/session   → recover signer → principal `sub` = the address,
 *                          short-lived HMAC session token (TTL 10 min)
 *
 * Sessions ride `Authorization: Bearer …` on HTTP; WebSocket connects pass
 * `?token=…` as a query param (net-new — ARC-0023 defines only the header).
 *
 * Deviations from the coordinator implementation, deliberate for cut 1:
 * - The challenge is stateless (self-authenticating HMAC blob), so nonces
 *   are single-window (~120s) rather than single-use. Replaying a leaked
 *   signed challenge can only re-mint a session for the wallet that signed
 *   it. Single-use nonces arrive with the coordinator-backed swap.
 * - No `authLogId`/publicRoot match: there is no registered log yet (that
 *   lands with provisioning in M2); the principal is simply the wallet.
 */

export interface AuthEnv {
  /** HMAC key (any high-entropy string) for challenge + session tokens. */
  SESSION_HMAC_SECRET: string;
  /** "1" accepts `dev:<sub>` bearer tokens — local dev only, never prod. */
  DEV_AUTH?: string;
}

const CHALLENGE_TTL_MS = 120_000;
const SESSION_TTL_MS = 600_000;
const AUD = "thinker-scribe";
const SCOPES = ["scribe:chat"];

interface ChallengeClaims {
  v: "wcc-1";
  domain: string;
  origin: string;
  scopes: string[];
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}

interface SessionClaims {
  v: 1;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
}

// -- token plumbing: b64url(json) + "." + b64url(HMAC(tag ‖ json)) ----------

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function b64urlDecode(text: string): Uint8Array {
  const bin = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmac(env: AuthEnv, tag: string, payload: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.SESSION_HMAC_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const input = new TextEncoder().encode(tag + ".");
  const data = new Uint8Array(input.length + payload.length);
  data.set(input);
  data.set(payload, input.length);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
}

async function mintToken(env: AuthEnv, tag: string, claims: unknown): Promise<string> {
  const payload = new TextEncoder().encode(JSON.stringify(claims));
  return `${b64url(payload)}.${b64url(await hmac(env, tag, payload))}`;
}

async function openToken<T>(env: AuthEnv, tag: string, token: string): Promise<T | null> {
  const dot = token.indexOf(".");
  if (dot < 0) return null;
  let payload: Uint8Array;
  let mac: Uint8Array;
  try {
    payload = b64urlDecode(token.slice(0, dot));
    mac = b64urlDecode(token.slice(dot + 1));
  } catch {
    return null;
  }
  const expect = await hmac(env, tag, payload);
  if (mac.length !== expect.length) return null;
  let diff = 0;
  for (let i = 0; i < mac.length; i++) diff |= mac[i] ^ expect[i];
  if (diff !== 0) return null;
  try {
    return JSON.parse(new TextDecoder().decode(payload)) as T;
  } catch {
    return null;
  }
}

// -- wcc-1 challenge --------------------------------------------------------

/** Canonical UTF-8 message the wallet personal_signs (SIWE-aligned layout). */
export function challengeMessage(c: ChallengeClaims): string {
  return [
    `${c.domain} wants you to sign in with your Ethereum account.`,
    "",
    "Forestrie Scribe wcc-1 session challenge.",
    "",
    `URI: ${c.origin}`,
    `Version: ${c.v}`,
    `Scopes: ${c.scopes.join(" ")}`,
    `Nonce: ${c.nonce}`,
    `Issued At: ${c.issuedAt}`,
    `Expiration Time: ${c.expiresAt}`,
  ].join("\n");
}

function eip191Digest(message: string): Uint8Array {
  const body = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(
    `\x19Ethereum Signed Message:\n${body.length}`,
  );
  const data = new Uint8Array(prefix.length + body.length);
  data.set(prefix);
  data.set(body, prefix.length);
  return keccak_256(data);
}

/** Recover the checksum-free lowercase 0x address from a 65-byte r‖s‖v sig. */
function recoverAddress(message: string, signatureHex: string): string | null {
  const hex = signatureHex.startsWith("0x") ? signatureHex.slice(2) : signatureHex;
  if (!/^[0-9a-fA-F]{130}$/.test(hex)) return null;
  const sig = new Uint8Array(65);
  for (let i = 0; i < 65; i++) sig[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  // Wallet layout is r‖s‖v with v = 27/28; noble wants compact r‖s plus the
  // raw recovery bit (its own "recovered" byte layout is recovery-FIRST, so
  // never feed the wallet bytes to fromBytes(…, "recovered") directly).
  let v = sig[64];
  if (v >= 27) v -= 27;
  if (v > 3) return null;
  try {
    const digest = eip191Digest(message);
    const pub = secp256k1.Signature.fromBytes(sig.slice(0, 64), "compact")
      .addRecoveryBit(v)
      .recoverPublicKey(digest)
      .toBytes(false);
    const addr = keccak_256(pub.slice(1)).slice(-20);
    let out = "0x";
    for (const b of addr) out += b.toString(16).padStart(2, "0");
    return out;
  } catch {
    return null;
  }
}

// -- HTTP surface -----------------------------------------------------------

/** Handle /auth/* routes; null when the request is not an auth route. */
export async function handleAuth(request: Request, env: AuthEnv): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.pathname === "/auth/challenge" && request.method === "POST") {
    const now = Date.now();
    const claims: ChallengeClaims = {
      v: "wcc-1",
      domain: url.hostname,
      origin: url.origin,
      scopes: SCOPES,
      nonce: b64url(crypto.getRandomValues(new Uint8Array(16))),
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + CHALLENGE_TTL_MS).toISOString(),
    };
    return Response.json({
      challenge: await mintToken(env, "wcc1-challenge", claims),
      message: challengeMessage(claims),
      expiresAt: claims.expiresAt,
    });
  }

  if (url.pathname === "/auth/session" && request.method === "POST") {
    let body: { challenge?: string; signature?: string };
    try {
      body = await request.json();
    } catch {
      return new Response("invalid JSON", { status: 400 });
    }
    if (!body.challenge || !body.signature)
      return new Response("challenge and signature required", { status: 400 });
    const claims = await openToken<ChallengeClaims>(env, "wcc1-challenge", body.challenge);
    if (!claims || claims.v !== "wcc-1")
      return new Response("invalid challenge", { status: 401 });
    if (Date.parse(claims.expiresAt) < Date.now())
      return new Response("challenge expired", { status: 401 });
    const sub = recoverAddress(challengeMessage(claims), body.signature);
    if (!sub) return new Response("signature does not verify", { status: 401 });
    const now = Date.now();
    const session: SessionClaims = {
      v: 1,
      sub,
      aud: AUD,
      iat: now,
      exp: now + SESSION_TTL_MS,
    };
    return Response.json({
      token: await mintToken(env, "wcc1-session", session),
      sub,
      exp: session.exp,
    });
  }

  return null;
}

/**
 * Extract and verify the session on a routed request. Bearer header for
 * HTTP; `?token=` query param for WebSocket connects. Returns the principal
 * `sub` or null.
 */
export async function verifySession(request: Request, env: AuthEnv): Promise<string | null> {
  const header = request.headers.get("authorization");
  const bearer = header?.match(/^Bearer\s+(.+)$/i)?.[1];
  const token = bearer ?? new URL(request.url).searchParams.get("token");
  if (!token) return null;

  if (env.DEV_AUTH === "1" && token.startsWith("dev:")) {
    const sub = token.slice(4).toLowerCase();
    return /^[a-z0-9][a-z0-9._-]{0,80}$/.test(sub) ? sub : null;
  }

  const claims = await openToken<SessionClaims>(env, "wcc1-session", token);
  if (!claims || claims.v !== 1 || claims.aud !== AUD) return null;
  if (claims.exp < Date.now()) return null;
  return claims.sub;
}
