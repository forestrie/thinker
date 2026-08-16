// SUPERSEDED by apps/grant-authority (a Cloudflare Worker) — plan A3.
// scripts/authority.sh now runs THAT on :8799, so local and deployed are one
// codebase. This file is no longer wired to anything and is kept only for the
// .provision/books.jsonl payment bookkeeping it does, which the Worker cannot
// (no filesystem). Do not add behaviour here: a second grant faucet holding
// K(L) of both authority logs is exactly the thing that drifts unnoticed.
// grant-authority — the M5 grant-issuing seam (plan §11 O5, O4; T4/T10).
// A small HTTP authority the Scribe's `RequestGrantProvider` calls at init,
// playing the role provision.sh played by hand: it holds the authority key
// (K(L) of BOTH authority logs) and issues *creation grants* that endorse a
// signer by creating a fresh data log whose `grantData` names the signer
// (canopy grants.md §6 — extend-only follow-up grants on an initialized log
// are not accepted server-side, so a new writer key always gets a new log).
//
// Two-parent topology (plan-2608-09 W4b.1, ARC-0029 §2 corollary A): the
// payment bit lives on the PARENT and gates every child uniformly, so agent
// grants parent under the bit-free agent-authority log and user grants under
// the user-authority log carrying GF_CHILD_PAYMENT_REQUIRED. Agents stay
// ungated by topology — never an ops/operator bypass token (canopy C7/C10).
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
// State: .provision/ (ids.env, authority.es256.pem, agent-auth-grant.b64,
// user-auth-grant.b64), issued grants under .provision/issued/. Requires
// provision.sh `up` (W4b.1 two-log shape) to have run.
//
// Env: FORESTRIE_BASE_URL, DELEGATION_COORDINATOR_URL, COORDINATOR_APP_TOKEN
// (user grants only), GRANT_AUTHORITY_TOKEN (optional bearer), PORT.
import { createServer } from 'node:http';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { delegateSealing } from '../packages/think-scribe/src/forestrie/delegate.ts';
import {
	bytesToForestrieGrantBase64,
	dataLogCreateExtendFlags,
	signGrantPayloadWithEs256Pem
} from '@forestrie/grant-builder';
import {
	encodeCborDeterministic,
	encodeGrantPayloadV0Canonical,
	mergeUnprotectedIntoCoseSign1,
	uuidToBytes
} from '@forestrie/encoding';
import { HEADER_IDTIMESTAMP, HEADER_RECEIPT } from '@forestrie/grant-builder';
import {
	forestrieGrantAuthorization,
	interpretRegisterRedirect,
	queryRegistrationOnce,
	resolveReceiptOnce
} from '@forestrie/scrapi-client';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const P = join(ROOT, '.provision');
const ISSUED = join(P, 'issued');
mkdirSync(ISSUED, { recursive: true });

const BASE_URL = process.env.FORESTRIE_BASE_URL ?? 'https://api-a.forest-2.forestrie.dev';
const COORDINATOR_URL =
	process.env.DELEGATION_COORDINATOR_URL ?? 'https://coordinator-a.forest-2.forestrie.dev';
const COORDINATOR_APP_TOKEN = process.env.COORDINATOR_APP_TOKEN ?? '';
const AUTHORITY_TOKEN = process.env.GRANT_AUTHORITY_TOKEN ?? '';
const PORT = Number(process.env.PORT ?? '8799');
/** Overall budget for grant sequencing + receipt (auth-log seal is ~1 min). */
const GRANT_TIMEOUT_MS = 240_000;
/** Registrar's public voucher key (as provision.sh) — not a secret. */
const KNOWN_SEALER_KEY =
	process.env.KNOWN_SEALER_KEY ??
	'z1YarLKXrsRe5egrwrFfbeYadd9lOqplKxbRuMGymHUOSY7YAfdOhhPWb3H72TrPMiMLw0CBMpDPXUGMEvbkOQ==';
/** Renew the auth-log sealing lease when under this runway (seconds). */
const SEALING_RENEW_MARGIN_S = 1800;
const SEALING_CHECK_INTERVAL_MS = 600_000;
/**
 * User-grant batch size (plan-2608-09 W4a): issued user grants carry
 * `maxHeight = batch` — the unit the x402 gate prices
 * (REGISTER_GRANT_PRICE_ATOMIC × maxHeight) and the prepaid-turns budget the
 * Scribe DO enforces (W4c). Agent grants stay maxHeight 0 (ungated,
 * pre-issued at provisioning).
 */
const USER_GRANT_BATCH_TURNS = Number(process.env.USER_GRANT_BATCH_TURNS ?? '16');

const ids = Object.fromEntries(
	readFileSync(join(P, 'ids.env'), 'utf8')
		.split('\n')
		.filter((l) => l.startsWith('export '))
		.map((l) => l.slice(7).split('=', 2))
);
const AGENT_AUTH_LOG_ID = ids.AGENT_AUTH_LOG_ID;
const USER_AUTH_LOG_ID = ids.USER_AUTH_LOG_ID;
const ROOT_LOG_ID = ids.ROOT_LOG_ID;
if (!AGENT_AUTH_LOG_ID || !USER_AUTH_LOG_ID || !ROOT_LOG_ID) {
	console.error(
		'grant-authority: run provision.sh up first (.provision/ids.env needs the W4b.1 two-log shape: AGENT_AUTH_LOG_ID + USER_AUTH_LOG_ID)'
	);
	process.exit(2);
}
const authorityPem = readFileSync(join(P, 'authority.es256.pem'), 'utf8');
/**
 * The two issuance parents (W4b.1). Same authority key owns both logs; the
 * class split is purely which parent a child grant registers under.
 */
const AGENT_AUTHORITY = {
	logId: AGENT_AUTH_LOG_ID,
	grantB64: readFileSync(join(P, 'agent-auth-grant.b64'), 'utf8').trim()
};
const USER_AUTHORITY = {
	logId: USER_AUTH_LOG_ID,
	grantB64: readFileSync(join(P, 'user-auth-grant.b64'), 'utf8').trim()
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- auth-log sealing leases (the gap the 2026-08-10 outage exposed) -------
// Grant issuance blocks on the grant's inclusion receipt, which needs the
// issuing auth log sealed — but the lease provision.sh signed at `up` time
// expires (~6h TTL) and nothing renewed it, so every grant request eventually
// 502'd with "grant receipt timed out (auth-log seal)". The authority holds
// K(L) for BOTH its auth logs (W4b.1), so it renews each lease itself: at
// startup, on a timer, and just-in-time before each issuance — the same
// delegate-at-drain pattern the Scribe DO uses for the agent's data log.

let authorityKeyPairPromise;
function authorityKeyPair() {
	authorityKeyPairPromise ??= (async () => {
		const priv = createPrivateKey(authorityPem);
		const pkcs8 = priv.export({ type: 'pkcs8', format: 'der' });
		const spki = createPublicKey(priv).export({ type: 'spki', format: 'der' });
		const alg = { name: 'ECDSA', namedCurve: 'P-256' };
		return {
			privateKey: await crypto.subtle.importKey('pkcs8', pkcs8, alg, false, ['sign']),
			publicKey: await crypto.subtle.importKey('spki', spki, alg, true, ['verify'])
		};
	})();
	return authorityKeyPairPromise;
}

/** Per-auth-log lease state: logId → { expiresAt, renewal }. */
const sealing = new Map(
	[AGENT_AUTH_LOG_ID, USER_AUTH_LOG_ID].map((id) => [id, { expiresAt: 0, renewal: null }])
);
function renewAuthLogSealingIfNeeded(logId) {
	const lease = sealing.get(logId);
	if (lease.expiresAt - Date.now() / 1000 > SEALING_RENEW_MARGIN_S) return Promise.resolve();
	lease.renewal ??= (async () => {
		try {
			const result = await delegateSealing(
				{ signingKeyPair: () => authorityKeyPair() },
				{ coordinatorUrl: COORDINATOR_URL, logId, knownSealerKeyB64: KNOWN_SEALER_KEY }
			);
			lease.expiresAt = result.expiresAt;
			console.log(
				`auth-log ${logId} sealing lease renewed — sealer ${result.sealerId}, expires ${new Date(result.expiresAt * 1000).toISOString()}`
			);
		} catch (err) {
			// Issuance degrades to the timeout the caller already handles; the
			// next check retries. Never crash the service over a renewal.
			console.error(
				`auth-log ${logId} sealing renewal failed (grants may time out until it succeeds):`,
				err
			);
		} finally {
			lease.renewal = null;
		}
	})();
	return lease.renewal;
}
function renewAllAuthLogSealingIfNeeded() {
	return Promise.all([...sealing.keys()].map((id) => renewAuthLogSealingIfNeeded(id)));
}

/**
 * Build (sign) a creation grant endorsing `grantData` on a fresh data log
 * owned by `authority` (agent- or user-authority, W4b.1). `maxHeight` > 0
 * sizes the grant to a purchased batch (user grants, W4a); 0 leaves it
 * unbounded (agent grants). Signing is cheap and stateless — the expensive
 * register/seal happens in {@link submitCreationGrant}.
 */
function buildCreationGrant(authority, grantData, maxHeight = 0) {
	const logId = crypto.randomUUID();
	const grant = {
		logId: uuidToBytes(logId),
		ownerLogId: uuidToBytes(authority.logId),
		grant: dataLogCreateExtendFlags(),
		maxHeight,
		minGrowth: 0,
		grantData
	};
	const payloadBytes = encodeGrantPayloadV0Canonical(grant);
	const sign1 = signGrantPayloadWithEs256Pem(payloadBytes, authorityPem);
	return { logId, sign1, grantBase64: bytesToForestrieGrantBase64(sign1) };
}

/**
 * POST a built grant to `/register/{ROOT}/grants` with `authority`'s parent
 * grant (grants.md §11). The stock `registerGrant` throws on any non-303, so it
 * cannot see the x402 gate (plan-2608-09 W2): when the parent grant carries
 * `GF_CHILD_PAYMENT_REQUIRED` and the lane admission is `paid`/`either`,
 * register-grant answers **402** with an `X-PAYMENT-REQUIRED` challenge. We do
 * the POST raw so we can (a) surface that challenge to the browser wallet and
 * (b) resubmit the identical grant carrying the wallet-signed `X-PAYMENT`
 * header (W4b — the authority is the registrar, the browser is the payer).
 *
 * Returns `{ status: "receipt", statusUrl }` on the 303 (dark lanes and paid
 * resubmits both land here) or `{ status: "payment_required", challengeB64 }`
 * on the 402. `interpretRegisterRedirect` still owns the 303 contract.
 */
async function registerGrantRaw(authority, grantBase64, { xPayment } = {}) {
	const headers = {
		Authorization: forestrieGrantAuthorization(grantBase64),
		'Content-Type': 'application/cbor'
	};
	if (xPayment) headers['X-PAYMENT'] = xPayment;
	const body = encodeCborDeterministic({ parentGrant: base64ToBytes(authority.grantB64) });
	const res = await fetch(`${BASE_URL.replace(/\/$/, '')}/register/${ROOT_LOG_ID}/grants`, {
		method: 'POST',
		headers,
		redirect: 'manual',
		body
	});
	if (res.status === 402) {
		// Challenge rides the response header (same shape as onboard/credits).
		const challengeB64 = res.headers.get('x-payment-required');
		if (!challengeB64)
			throw new Error('register-grant 402 without X-PAYMENT-REQUIRED challenge header');
		return { status: 'payment_required', challengeB64 };
	}
	const { statusUrl } = interpretRegisterRedirect(
		{
			status: res.status,
			location: res.headers.get('location') ?? undefined,
			body: new Uint8Array(await res.arrayBuffer())
		},
		BASE_URL
	);
	return { status: 'receipt', statusUrl };
}

/** Decode standard/url-safe base64 to bytes (Node Buffer handles both). */
function base64ToBytes(b64) {
	return Uint8Array.from(Buffer.from(b64, 'base64'));
}

/**
 * Register a built grant and wait out sequencing + the covering seal, then
 * splice the inclusion receipt into the COSE Sign1 → completed transparent
 * statement. Throws {@link PaymentRequired} carrying the challenge when the
 * x402 gate answers 402 and no `xPayment` was supplied (phase 1 of W4b).
 */
async function submitCreationGrant(authority, built, { xPayment } = {}) {
	// Just-in-time lease check: cheap no-op while the lease has runway, and
	// closes the window between timer ticks after a long idle stretch.
	await renewAuthLogSealingIfNeeded(authority.logId);
	const { logId, sign1, grantBase64 } = built;

	const submitted = await registerGrantRaw(authority, grantBase64, { xPayment });
	if (submitted.status === 'payment_required') throw new PaymentRequired(submitted.challengeB64);
	const { statusUrl } = submitted;

	const deadline = Date.now() + GRANT_TIMEOUT_MS;
	let receiptUrl;
	let entryIdHex;
	for (;;) {
		if (Date.now() > deadline) throw new Error('grant sequencing timed out');
		const q = await queryRegistrationOnce({ baseUrl: BASE_URL, statusUrl });
		if (q.status === 'receipt') {
			receiptUrl = q.receiptUrl;
			entryIdHex = q.entryIdHex;
			break;
		}
		if (q.status === 'error') throw new Error(`grant status: ${q.detail}`);
		await sleep(Math.min(q.retryAfterMs ?? 2000, deadline - Date.now()));
	}
	let receipt;
	for (;;) {
		if (Date.now() > deadline) throw new Error('grant receipt timed out (auth-log seal)');
		const r = await resolveReceiptOnce({ receiptUrl });
		if (r.status === 'receipt') {
			receipt = r.body;
			break;
		}
		if (r.status === 'error') throw new Error(`grant receipt: HTTP ${r.httpStatus}`);
		await sleep(3000);
	}

	const completed = mergeUnprotectedIntoCoseSign1(
		sign1,
		new Map([
			[HEADER_RECEIPT, receipt],
			[HEADER_IDTIMESTAMP, Uint8Array.from(Buffer.from(entryIdHex.slice(0, 16), 'hex'))]
		])
	);
	return { logId, entryIdHex, grantB64: bytesToForestrieGrantBase64(completed) };
}

/** Signals a register-grant 402 back up to the handler (W4b phase 1). */
class PaymentRequired extends Error {
	constructor(challengeB64) {
		super('register-grant requires payment');
		this.challengeB64 = challengeB64;
	}
}

/**
 * Build + register + complete in one call under the given issuance parent
 * (W4b.1) — the ungated path (agent grants, and user grants on a dark lane).
 * `xPayment` resubmits a paid grant (W4b phase 2). Propagates
 * {@link PaymentRequired} when the gate 402s and no payment was supplied.
 */
async function issueCreationGrant(authority, grantData, maxHeight = 0, opts = {}) {
	return submitCreationGrant(authority, buildCreationGrant(authority, grantData, maxHeight), opts);
}

/** Register a KS256-owned log's public root with the coordinator (operator). */
async function uploadKs256PublicRoot(logId, address) {
	if (!COORDINATOR_APP_TOKEN)
		throw new Error("COORDINATOR_APP_TOKEN not set — cannot register the user log's public root");
	const res = await fetch(`${COORDINATOR_URL}/api/logs/${logId}/public-root`, {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${COORDINATOR_APP_TOKEN}`,
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ alg: -65799, key: Buffer.from(address).toString('base64') })
	});
	if (!res.ok)
		throw new Error(
			`public-root upload failed: HTTP ${res.status} ${(await res.text()).slice(0, 200)}`
		);
}

function recordBooks(kind, subject, paymentCommitment) {
	appendFileSync(
		join(P, 'books.jsonl'),
		JSON.stringify({
			at: new Date().toISOString(),
			kind,
			subject,
			paymentCommitment: paymentCommitment ?? null
		}) + '\n'
	);
}

async function handleAgentGrant(body) {
	const xyHex = String(body.publicKeyXY ?? '');
	if (!/^[0-9a-f]{128}$/i.test(xyHex))
		return {
			status: 400,
			body: { error: 'publicKeyXY must be 128 hex chars (64-byte ES256 x||y)' }
		};
	const kidHex = xyHex.slice(0, 64).toLowerCase();
	const issuedPath = join(ISSUED, `agent-${kidHex}.json`);
	if (existsSync(issuedPath))
		return {
			status: 200,
			body: { ...JSON.parse(readFileSync(issuedPath, 'utf8')), preIssued: true }
		};

	recordBooks('grant_agent', kidHex, body.paymentCommitment);
	const issued = await issueCreationGrant(
		AGENT_AUTHORITY,
		Uint8Array.from(Buffer.from(xyHex, 'hex'))
	);
	const out = { kind: 'agent', kid: kidHex, logId: issued.logId, grantB64: issued.grantB64 };
	writeFileSync(issuedPath, JSON.stringify(out, null, 2));
	console.log(`issued grant_agent kid=${kidHex.slice(0, 16)}… log=${issued.logId}`);
	return { status: 201, body: { ...out, preIssued: false } };
}

/**
 * User grant, two-phase for the x402 gate (plan-2608-09 W4b). The
 * user-authority parent carries `GF_CHILD_PAYMENT_REQUIRED` (W4a/W4b.1), so
 * on a `paid`/`either` lane the child registration is payment-gated:
 *
 *   phase 1  POST {address}            → 402 { paymentRequired, challengeB64 }
 *            (the browser wallet signs the challenge)
 *   phase 2  POST {address, xPayment}  → 201 issued grant
 *
 * On a dark lane (admission `open`) phase 1 registers straight through and
 * issues (the `receipt` branch below) — byte-identical to pre-plan. The
 * authority is the registrar; the browser is the payer (H1 invariant).
 */
async function handleUserGrant(body) {
	const addrHex = String(body.address ?? '')
		.replace(/^0x/, '')
		.toLowerCase();
	if (!/^[0-9a-f]{40}$/.test(addrHex))
		return { status: 400, body: { error: 'address must be a 20-byte hex KS256 wallet address' } };
	const issuedPath = join(ISSUED, `user-${addrHex}.json`);
	// `renew` (W4c top-up): the caller's batch is spent — issue a FRESH grant
	// on a fresh log (O3, new grant per batch) instead of the cached one. The
	// cache still dedupes grant-at-bind retries on the non-renew path, and the
	// fresh issue overwrites it below so later non-renew reads converge.
	if (!body.renew && existsSync(issuedPath))
		return {
			status: 200,
			body: { ...JSON.parse(readFileSync(issuedPath, 'utf8')), preIssued: true }
		};

	const address = Uint8Array.from(Buffer.from(addrHex, 'hex'));
	const xPayment = typeof body.xPayment === 'string' && body.xPayment ? body.xPayment : undefined;

	let issued;
	try {
		// Phase 1 books the debt; a paid resubmit (phase 2) is the same subject.
		if (!xPayment) recordBooks('grant_user', addrHex, body.paymentCommitment);
		issued = await issueCreationGrant(USER_AUTHORITY, address, USER_GRANT_BATCH_TURNS, {
			xPayment
		});
	} catch (err) {
		if (err instanceof PaymentRequired)
			return {
				status: 402,
				body: {
					paymentRequired: true,
					challengeB64: err.challengeB64,
					address: `0x${addrHex}`,
					maxHeight: USER_GRANT_BATCH_TURNS
				}
			};
		throw err;
	}

	await uploadKs256PublicRoot(issued.logId, address);
	// maxHeight rides the response so the Scribe DO can seed prepaidTurns (W4c)
	// without decoding the grant payload.
	const out = {
		kind: 'user',
		address: `0x${addrHex}`,
		logId: issued.logId,
		grantB64: issued.grantB64,
		maxHeight: USER_GRANT_BATCH_TURNS
	};
	writeFileSync(issuedPath, JSON.stringify(out, null, 2));
	console.log(
		`issued grant_user addr=0x${addrHex} log=${issued.logId}${xPayment ? ' (x402 paid)' : ''}`
	);
	return { status: 201, body: { ...out, preIssued: false } };
}

const server = createServer(async (req, res) => {
	const send = (status, body) => {
		res.writeHead(status, { 'Content-Type': 'application/json' });
		res.end(JSON.stringify(body));
	};
	try {
		if (req.method === 'GET' && req.url === '/healthz')
			return send(200, {
				ok: true,
				agentAuthLogId: AGENT_AUTH_LOG_ID,
				userAuthLogId: USER_AUTH_LOG_ID,
				rootLogId: ROOT_LOG_ID
			});

		if (AUTHORITY_TOKEN && req.headers.authorization !== `Bearer ${AUTHORITY_TOKEN}`)
			return send(401, { error: 'bad authority token' });

		if (req.method === 'POST' && (req.url === '/grants/agent' || req.url === '/grants/user')) {
			const chunks = [];
			for await (const c of req) chunks.push(c);
			let body;
			try {
				body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
			} catch {
				return send(400, { error: 'body must be JSON' });
			}
			const result =
				req.url === '/grants/agent' ? await handleAgentGrant(body) : await handleUserGrant(body);
			return send(result.status, result.body);
		}
		return send(404, { error: 'unknown route' });
	} catch (err) {
		console.error(`${req.method} ${req.url} failed:`, err);
		return send(502, { error: String(err) });
	}
});

server.listen(PORT, () => {
	console.log(
		`grant-authority on :${PORT} — agent-auth ${AGENT_AUTH_LOG_ID}, user-auth ${USER_AUTH_LOG_ID} (payment bit), lane ${BASE_URL}` +
			(COORDINATOR_APP_TOKEN
				? ', coordinator operator token loaded'
				: ', NO coordinator token (user grants will fail)')
	);
	void renewAllAuthLogSealingIfNeeded();
	setInterval(() => void renewAllAuthLogSealingIfNeeded(), SEALING_CHECK_INTERVAL_MS).unref();
});
