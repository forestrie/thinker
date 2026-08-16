// M4 smoke: scheduled receipt collection + offline verification (plan §9 M4,
// T7→T8). An attested turn runs (m3 path), then the SCRIBE's OWN scheduled
// task follows sequencing and collects the sealed receipt — this client
// never touches the status URL. The receipt export then verifies offline via
// scripts/verify-receipts.sh, and a tampered export copy is shown to
// DIVERGE (verifier-level tamper detection; the live DO-SQLite tamper beat
// is scripts/tamper.sh, which needs the dev server stopped).
//
// Prereqs: `wrangler dev` with M2 .dev.vars; provision.sh state present
// (.provision/ids.env, auth grant); ANTHROPIC_API_KEY valid (a real model
// turn runs). Shells out to provision.sh to endorse this DO's kid.
//
// Run: node test/m4-smoke.mjs
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

const BASE = process.env.BASE_URL ?? 'http://localhost:8787';
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const OUT = join(dirname(fileURLToPath(import.meta.url)), '.out');
mkdirSync(OUT, { recursive: true });

let failures = 0;
function check(name, ok, detail = '') {
	console.log(`  ${ok ? '✓' : '✗'} ${name}${detail ? ` — ${detail}` : ''}`);
	if (!ok) failures++;
}
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// undici reuses keep-alive connections that workerd may have dropped during
// long gaps (e.g. the ~1 min provisioning shell-out) — retry once on reset.
async function fetchRetry(url, init) {
	try {
		return await fetch(url, init);
	} catch {
		await sleep(500);
		return fetch(url, init);
	}
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
	const chal = await (await fetch(`${BASE}/auth/challenge`, { method: 'POST' })).json();
	const sig = secp256k1.sign(eip191Digest(chal.message), priv, {
		format: 'recovered',
		prehash: false
	});
	const wallet = new Uint8Array(65);
	wallet.set(sig.slice(1), 0);
	wallet[64] = sig[0] + 27;
	const res = await fetch(`${BASE}/auth/session`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ challenge: chal.challenge, signature: `0x${hex(wallet)}` })
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
	if (typeof value === 'number') {
		if (value >= 0) cborHead(0, value, out);
		else cborHead(1, -1 - value, out);
	} else if (typeof value === 'string') {
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
		[3, 'application/json'],
		[4, address]
	]);
	const protectedBytes = Uint8Array.from(cborEncode(protectedMap));
	const sigStructure = Uint8Array.from(
		cborEncode(['Signature1', protectedBytes, new Uint8Array(0), payload])
	);
	const hash = keccak_256(sigStructure);
	const recovered = secp256k1.sign(hash, priv, { format: 'recovered', prehash: false });
	const signature = new Uint8Array(65);
	signature.set(recovered.slice(1), 0);
	signature[64] = recovered[0];
	return Uint8Array.from(cborEncode([protectedBytes, new Map(), payload, signature]));
}

function runVerifier(args) {
	try {
		const stdout = execFileSync('./scripts/verify-receipts.sh', args, {
			cwd: ROOT,
			stdio: 'pipe',
			timeout: 120_000
		}).toString();
		return { status: 0, stdout };
	} catch (err) {
		return { status: err.status ?? 1, stdout: String(err.stdout ?? '') + String(err.stderr ?? '') };
	}
}

async function main() {
	// Fixed key → stable per-user DO instance across runs (same as m3).
	const priv = Uint8Array.from({ length: 32 }, (_, i) => i + 3);
	const sub = addressOf(priv).toLowerCase();
	const AGENT = `${BASE}/agents/scribe/user-${sub}`;
	console.log(`M4 smoke — wallet user ${sub}`);

	const session = await mintSession(priv);
	check('wcc-1 session', typeof session.token === 'string', session.sub);
	const AUTH = { Authorization: `Bearer ${session.token}` };

	const identity = await (await fetchRetry(`${AGENT}/identity`, { headers: AUTH })).json();
	check('identity', identity.publicKeyXY?.length === 128, `kid ${identity.kid?.slice(0, 16)}…`);

	console.log('  … provisioning agent log + grant for this kid (lane writes)');
	execFileSync('./scripts/provision.sh', ['grant', identity.publicKeyXY], {
		cwd: ROOT,
		stdio: 'pipe',
		timeout: 300_000
	});
	const ids = Object.fromEntries(
		readFileSync(join(ROOT, '.provision', 'ids.env'), 'utf8')
			.split('\n')
			.filter((l) => l.startsWith('export '))
			.map((l) => l.slice(7).split('=', 2))
	);
	const agentLogId = ids.AGENT_LOG_ID;
	const grantB64 = readFileSync(join(ROOT, '.provision', 'agent-grant.b64'), 'utf8').trim();
	check('provisioned agent log', /^[0-9a-f-]{36}$/.test(agentLogId ?? ''), agentLogId);

	const conf = await fetchRetry(`${AGENT}/configure-forestrie`, {
		method: 'POST',
		headers: { ...AUTH, 'Content-Type': 'application/json' },
		body: JSON.stringify({ grantB64, agentLogId })
	});
	check('configure-forestrie', conf.ok);

	const del = await fetchRetry(`${AGENT}/delegate-sealing`, {
		method: 'POST',
		headers: { ...AUTH, 'Content-Type': 'application/json' },
		body: JSON.stringify({ logId: agentLogId })
	});
	check(
		'delegate-sealing',
		del.ok,
		del.ok ? `sealer ${(await del.json()).sealerId}` : await del.text()
	);

	// The attested turn.
	const claims = {
		input: 'Reply with one short sentence about transparency logs.',
		sessionId: `m4-smoke-${Date.now()}`,
		issuedAt: new Date().toISOString(),
		nonce: hex(crypto.getRandomValues(new Uint8Array(16)))
	};
	const envelope = buildEnvelope(claims, priv);
	const envelopeB64 = Buffer.from(envelope).toString('base64');
	const expectedWorkId = createHash('sha256').update(envelope).digest('hex');

	const turn = await fetchRetry(`${AGENT}/turn`, {
		method: 'POST',
		headers: { ...AUTH, 'Content-Type': 'application/json' },
		body: JSON.stringify({ envelopeB64 })
	});
	const turnBody = await turn.json().catch(async () => ({ err: await turn.text() }));
	check(
		'attested turn admitted',
		turn.ok && turnBody.accepted,
		turnBody.status ?? JSON.stringify(turnBody)
	);
	if (!turn.ok) return;

	// The DO's own scheduled task carries the work unit all the way to
	// "receipted" (T7→T8) — this client only watches the record.
	let work;
	const seen = new Set();
	for (let i = 0; i < 90; i++) {
		work = await (await fetchRetry(`${AGENT}/work?id=${expectedWorkId}`, { headers: AUTH })).json();
		if (work.state && !seen.has(work.state)) {
			seen.add(work.state);
			console.log(`  … work ${work.state}`);
		}
		if (['receipted', 'error'].includes(work.state)) break;
		await sleep(4000);
	}
	check(
		"receipt collected by the DO's scheduled task",
		work?.state === 'receipted',
		work?.state === 'error' ? work.error : `entry ${work?.entryId}`
	);
	if (work?.state !== 'receipted') return;
	check('entryId recorded', /^[0-9a-f]{32}$/.test(work.entryId ?? ''), work.entryId);
	check(
		'receipt bytes stored',
		typeof work.receiptB64 === 'string' && work.receiptB64.length > 100
	);

	// Receipt export: artifacts + the DO's current transcript claim.
	const exportRes = await fetchRetry(`${AGENT}/receipts`, { headers: AUTH });
	const exported = await exportRes.json();
	check('receipts export', exportRes.ok && Array.isArray(exported.works));
	const ours = (exported.works ?? []).find((w) => w.workId === expectedWorkId);
	check('export carries our work unit', ours?.state === 'receipted');
	check(
		'export claims current transcript',
		typeof ours?.currentOutputText === 'string' && ours.currentOutputText.length > 0,
		`"${(ours?.currentOutputText ?? '').slice(0, 60)}…"`
	);
	const exportPath = join(OUT, 'm4-receipts.json');
	writeFileSync(exportPath, JSON.stringify(exported, null, 2));

	// Offline verification (Auditor stand-in): everything passes untampered.
	// --work scopes to this run's turn: earlier runs' records stay in the DO
	// (including any past live tamper-beat edits) and are not ours to judge.
	const clean = runVerifier([
		'--export',
		exportPath,
		'--work',
		expectedWorkId,
		'--out',
		join(OUT, 'm4-verify')
	]);
	check(
		'verify-receipts.sh passes',
		clean.status === 0,
		clean.status === 0 ? '' : clean.stdout.slice(-300)
	);

	// Verifier-level tamper: rewrite the claimed transcript → divergence.
	const tampered = structuredClone(exported);
	for (const w of tampered.works)
		if (w.workId === expectedWorkId)
			w.currentOutputText = 'I never said that. This record was always thus.';
	const tamperedPath = join(OUT, 'm4-receipts-tampered.json');
	writeFileSync(tamperedPath, JSON.stringify(tampered, null, 2));
	const diverged = runVerifier(['--export', tamperedPath, '--work', expectedWorkId]);
	check(
		'tampered transcript DIVERGES',
		diverged.status !== 0 && diverged.stdout.includes('transcript-binding'),
		'verifier flags transcript-binding'
	);

	// Verifier-level tamper: corrupt a receipt byte → receipt check fails.
	const broken = structuredClone(exported);
	for (const w of broken.works)
		if (w.workId === expectedWorkId) {
			const raw = Buffer.from(w.receiptB64, 'base64');
			raw[raw.length - 1] ^= 0xff; // clobber signature bytes
			w.receiptB64 = raw.toString('base64');
		}
	const brokenPath = join(OUT, 'm4-receipts-broken.json');
	writeFileSync(brokenPath, JSON.stringify(broken, null, 2));
	const badReceipt = runVerifier(['--export', brokenPath, '--work', expectedWorkId]);
	check('corrupted receipt fails verification', badReceipt.status !== 0);

	console.log(
		'\n  live tamper beat: stop wrangler dev, then\n' +
			`    scripts/tamper.sh --leaf ${ours.leafId ?? '<leafId>'} "<phrase from the reply>" "<rewrite>"\n` +
			'  restart wrangler dev and re-run:\n' +
			`    scripts/verify-receipts.sh --url ${AGENT} --token <bearer>\n`
	);
}

await main();
console.log(failures ? `\n${failures} FAILED` : '\nall checks passed');
process.exit(failures ? 1 : 0);
