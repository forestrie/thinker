// M3 smoke: Tier-2 attestation end-to-end (plan §7, D3). A wallet user
// signs an input envelope (canopy KS256 COSE profile), the turn runs
// durably under workId = H(envelope), the Scribe assembles a per-turn work
// statement embedding the envelope, the drain signs+registers it, and the
// receipt seals and verifies offline.
//
// Prereqs: `wrangler dev` with M2 .dev.vars; provision.sh state present
// (.provision/ids.env, auth grant); ANTHROPIC_API_KEY valid (a real model
// turn runs). This script shells out to scripts/provision.sh to endorse the
// wallet user's DO kid (fresh agent data log + grant).
//
// Run: node test/m3-smoke.mjs
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
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

// --- minimal CBOR encode (envelope subset: int, bstr, tstr, array, map) ----
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
		// Deterministic order on encoded key bytes (all int keys here).
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

// --- input commitment (Phase D: the envelope commits, it does not carry) ----
// Mirrors packages/think-scribe/src/attestation.ts `saltedCommitmentHex`:
// H("thinker/input/v1:<nonce byte length>:" ‖ nonce ‖ input), hex.
function inputCommitment(nonce, input) {
	const nonceBytes = Buffer.from(nonce, 'utf8');
	return createHash('sha256')
		.update(Buffer.from(`thinker/input/v1:${nonceBytes.length}:`, 'utf8'))
		.update(nonceBytes)
		.update(Buffer.from(input, 'utf8'))
		.digest('hex');
}

// --- user input envelope (canopy KS256 COSE profile) -----------------------
function buildEnvelope(claims, priv) {
	const address = keccak_256(secp256k1.getPublicKey(priv, false).slice(1)).slice(-20);
	const payload = new TextEncoder().encode(JSON.stringify(claims));
	const protectedMap = new Map([
		[1, -65799], // KS256
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
	signature[64] = recovered[0]; // raw recovery 0..3
	return Uint8Array.from(cborEncode([protectedBytes, new Map(), payload, signature]));
}

async function main() {
	// Fixed key → stable per-user DO instance across runs.
	const priv = Uint8Array.from({ length: 32 }, (_, i) => i + 3);
	const sub = addressOf(priv).toLowerCase();
	const AGENT = `${BASE}/agents/scribe/user-${sub}`;
	console.log(`M3 smoke — wallet user ${sub}`);

	const session = await mintSession(priv);
	check('wcc-1 session', typeof session.token === 'string', session.sub);
	const AUTH = { Authorization: `Bearer ${session.token}` };

	// Agent identity → endorse this DO's kid (fresh agent log + grant).
	const identity = await (await fetch(`${AGENT}/identity`, { headers: AUTH })).json();
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

	const conf = await fetch(`${AGENT}/configure-forestrie`, {
		method: 'POST',
		headers: { ...AUTH, 'Content-Type': 'application/json' },
		body: JSON.stringify({ grantB64, agentLogId })
	});
	check('configure-forestrie', conf.ok);

	const del = await fetch(`${AGENT}/delegate-sealing`, {
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
	const input = 'In one short sentence: what makes this conversation tamper-evident?';
	const nonce = hex(crypto.getRandomValues(new Uint8Array(16)));
	const claims = {
		inputHash: inputCommitment(nonce, input),
		sessionId: `m3-smoke-${Date.now()}`,
		issuedAt: new Date().toISOString(),
		nonce
	};
	const envelope = buildEnvelope(claims, priv);
	const envelopeB64 = Buffer.from(envelope).toString('base64');
	const expectedWorkId = createHash('sha256').update(envelope).digest('hex');

	const turn = await fetch(`${AGENT}/turn`, {
		method: 'POST',
		headers: { ...AUTH, 'Content-Type': 'application/json' },
		// The plaintext rides in the body; the envelope carries only its hash.
		body: JSON.stringify({ envelopeB64, input })
	});
	const turnBody = await turn.json().catch(async () => ({ err: await turn.text() }));
	check(
		'attested turn admitted',
		turn.ok && turnBody.accepted,
		turnBody.status ?? JSON.stringify(turnBody)
	);
	check('workId = H(envelope)', turnBody.workId === expectedWorkId, turnBody.workId?.slice(0, 16));
	if (!turn.ok) return;

	// Turn runs (real model) → onChatResponse queues → drain registers.
	let work;
	for (let i = 0; i < 45; i++) {
		work = await (await fetch(`${AGENT}/work?id=${expectedWorkId}`, { headers: AUTH })).json();
		if (['registered', 'error'].includes(work.state)) break;
		await sleep(2000);
	}
	check(
		'work registered',
		work?.state === 'registered',
		work?.state === 'error' ? work.error : work?.contentHash?.slice(0, 16)
	);
	if (work?.state !== 'registered') return;

	// The committed statement names the work unit and commits to the output.
	// Since Phase D it carries NO plaintext by either route — not embedded in
	// the statement, and not inside the envelope the statement names.
	const statement = Buffer.from(work.statementB64, 'base64');
	writeFileSync(join(OUT, 'm3-statement.cose'), statement);
	// COSE payload = our JSON work statement; crude extract via JSON slice.
	const text = statement.toString('latin1');
	const payloadJson = JSON.parse(
		text.slice(text.indexOf('{"type":"thinker/work-statement/v1"'), text.lastIndexOf('}') + 1)
	);
	check('statement does NOT embed the user envelope', payloadJson.userEnvelope === undefined);
	check(
		'no plaintext anywhere on the outbound path',
		!statement.includes(input) &&
			!Buffer.from(envelopeB64, 'base64').toString('latin1').includes(input)
	);
	check('statement workId matches', payloadJson.workId === expectedWorkId);
	// What the lane actually holds for the user side: a commitment the plaintext
	// opens, and nothing else. (Claims are a flat JSON object inside the COSE
	// payload, so the first {...} run is exactly them.)
	const envelopeText = Buffer.from(envelopeB64, 'base64').toString('latin1');
	const registeredClaims = JSON.parse(/\{"inputHash".*?\}/.exec(envelopeText)?.[0] ?? '{}');
	check(
		'registered envelope commits to the input we sent',
		registeredClaims.inputHash === inputCommitment(claims.nonce, input),
		registeredClaims.inputHash?.slice(0, 16)
	);
	check(
		'statement has output hash + salt',
		/^[0-9a-f]{64}$/.test(payloadJson.outputHash) && /^[0-9a-f]{64}$/.test(payloadJson.salt)
	);
	check(
		'statement has leafId',
		typeof payloadJson.leafId === 'string' && payloadJson.leafId.length > 0
	);

	// Sequencing → receipt → offline verify.
	let status;
	for (let i = 0; i < 30; i++) {
		status = await (
			await fetch(`${AGENT}/registration?status=${encodeURIComponent(work.statusUrl)}`, {
				headers: AUTH
			})
		).json();
		if (status.state === 'sequenced') break;
		await sleep((status.retryAfterSeconds ?? 1) * 1000);
	}
	check('sequenced', status?.state === 'sequenced', status?.entryId);
	if (status?.state !== 'sequenced') return;

	let sealed = false;
	const receiptPath = join(OUT, 'm3-receipt.cbor');
	for (let i = 0; i < 24; i++) {
		const res = await fetch(
			`${AGENT}/registration?receipt=${encodeURIComponent(status.receiptUrl)}`,
			{ headers: AUTH }
		);
		if (res.status === 200) {
			writeFileSync(receiptPath, Buffer.from(await res.arrayBuffer()));
			sealed = true;
			break;
		}
		await sleep(5000);
	}
	check('receipt sealed', sealed, sealed ? status.entryId : 'timed out (~2min)');
	if (!sealed) return;

	const cli =
		process.env.FORESTRIE_CLI ??
		join(process.env.HOME ?? '', 'Dev/personal/forestrie/ietf-126-demo/forestrie');
	if (existsSync(cli)) {
		try {
			execFileSync(
				cli,
				[
					'verify',
					'--known-log-key',
					Buffer.from(identity.publicKeyXY, 'hex').toString('base64'),
					'--receipt',
					receiptPath,
					'--payload',
					join(OUT, 'm3-statement.cose'),
					'--entry-id',
					status.entryId
				],
				{ stdio: 'pipe' }
			);
			check('offline verify (known-log-key)', true);
		} catch (err) {
			check('offline verify (known-log-key)', false, String(err.stderr ?? err).slice(0, 300));
		}
	} else {
		console.log('  - offline verify skipped (forestrie CLI not found)');
	}
}

await main();
console.log(failures ? `\n${failures} FAILED` : '\nall checks passed');
process.exit(failures ? 1 : 0);
