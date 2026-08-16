// MU smoke: the scribe-ui client choreography, driven headlessly through the
// vite dev server (plan §9 MU, §5.1). What the browser does, node does here:
//
//   1. The dev server serves the app shell and proxies /auth + /agents
//      (including the WebSocket upgrade) to the scribe-worker.
//   2. wcc-1 session: challenge → wallet personal_sign → bearer, using the
//      exact signature layout wallet.svelte.ts produces.
//   3. AgentClient path: WS connect with ?token= through the proxy → the
//      server's cf_agent_chat_messages transcript sync arrives.
//   4. The proof panel's read path: GET /receipts through the proxy, then
//      OFFLINE verification with the SAME primitives the browser bundles
//      (verifyWorkReceipt incl. the user leaf's KS256 chain) over the
//      receipted M5 work units in the persisted dev DO state.
//   5. The UI envelope builder (src/lib/envelope.ts) round-trips: the
//      worker-side verifier accepts it and recovers the wallet address.
//   6. A fresh attested turn: POST /turn, then the live stream broadcast
//      reaches the WS client (the frames chat.svelte.ts renders).
//
// Prereqs: `wrangler dev` (apps/scribe-worker, M5 .dev.vars) and
// `vite dev` (apps/scribe-ui) running; the M5 smoke's DO state present.
//
// Run: node --experimental-strip-types test/mu-smoke.mjs
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { buildUserEnvelope, newTurnClaims, workIdOf } from '../src/lib/envelope.ts';
import { envelopeClaims } from '../src/lib/cbor.ts';
import { bytesToB64, bytesToHex, hexToBytes } from '../src/lib/utils.ts';
import { verifyWorkReceipt } from '@forestrie/think-scribe/forestrie/receipt';
import { verifyUserEnvelope } from '../../../packages/think-scribe/src/forestrie/envelope.ts';

const UI = process.env.UI_URL ?? 'http://localhost:5173';

let failures = 0;
function check(name, ok, detail = '') {
	console.log(`  ${ok ? '✓' : '✗'} ${name}${detail ? ` — ${detail}` : ''}`);
	if (!ok) failures++;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- the demo wallet, as wallet.svelte.ts implements it --------------------
// (that module carries Svelte runes so node exercises its logic via this
// structurally-identical stand-in; envelope.ts only needs these three)
function makeWallet(priv) {
	const pub = secp256k1.getPublicKey(priv, false);
	const address20 = keccak_256(pub.slice(1)).slice(-20);
	return {
		address: `0x${bytesToHex(address20)}`,
		addressBytes: () => address20,
		privateKeyHex: () => bytesToHex(priv),
		signPersonal(message) {
			const body = new TextEncoder().encode(message);
			const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
			const data = new Uint8Array(prefix.length + body.length);
			data.set(prefix);
			data.set(body, prefix.length);
			const recovered = secp256k1.sign(keccak_256(data), priv, {
				format: 'recovered',
				prehash: false
			});
			const sig = new Uint8Array(65);
			sig.set(recovered.slice(1), 0);
			sig[64] = recovered[0] + 27;
			return `0x${bytesToHex(sig)}`;
		},
		signDigestKs256(digest) {
			const recovered = secp256k1.sign(digest, priv, { format: 'recovered', prehash: false });
			const sig = new Uint8Array(65);
			sig.set(recovered.slice(1), 0);
			sig[64] = recovered[0];
			return sig;
		}
	};
}

async function main() {
	// The SAME wallet as m5-smoke → the DO instance with receipted M5 works.
	const wallet = makeWallet(Uint8Array.from({ length: 32 }, (_, i) => i + 7));
	const sub = wallet.address.toLowerCase();
	const AGENT = `${UI}/agents/scribe/user-${sub}`;
	console.log(`MU smoke — via ${UI}, wallet user ${sub}`);

	// 1. The dev server serves the shell.
	const shell = await fetch(UI).then((r) => r.text());
	check('vite serves the app shell', shell.includes('Scribe — attested conversation'));

	// 2. wcc-1 session through the /auth proxy.
	const chal = await (await fetch(`${UI}/auth/challenge`, { method: 'POST' })).json();
	check('challenge via proxy', typeof chal.message === 'string');
	const sess = await (
		await fetch(`${UI}/auth/session`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				challenge: chal.challenge,
				signature: wallet.signPersonal(chal.message)
			})
		})
	).json();
	check('session minted (UI signature layout)', typeof sess.token === 'string', sess.sub);
	if (typeof sess.token !== 'string') return;
	const AUTH = { Authorization: `Bearer ${sess.token}` };

	// 3. The AgentClient path: WS through the vite proxy, transcript sync.
	const wsUrl = `${UI.replace(/^http/, 'ws')}/agents/scribe/user-${sub}?token=${encodeURIComponent(sess.token)}`;
	const ws = new WebSocket(wsUrl);
	const frames = [];
	let syncResolve;
	const synced = new Promise((r) => (syncResolve = r));
	ws.addEventListener('message', (event) => {
		try {
			const frame = JSON.parse(String(event.data));
			frames.push(frame);
			if (frame.type === 'cf_agent_chat_messages') syncResolve(frame);
		} catch {
			/* ignore non-JSON */
		}
	});
	const opened = await new Promise((resolve) => {
		ws.addEventListener('open', () => resolve(true));
		ws.addEventListener('error', () => resolve(false));
		setTimeout(() => resolve(false), 10_000);
	});
	check('WebSocket connects through the proxy', opened);
	const sync = opened ? await Promise.race([synced, sleep(10_000)]) : null;
	check(
		'transcript sync (cf_agent_chat_messages) arrives',
		Array.isArray(sync?.messages),
		sync ? `${sync.messages.length} messages` : 'timed out'
	);

	// 4. The proof panel read path + offline verify, exactly as bundled.
	const identity = await (await fetch(`${AGENT}/identity`, { headers: AUTH })).json();
	check('identity (pinned trust root)', /^[0-9a-f]{128}$/.test(identity.publicKeyXY ?? ''));
	const exported = await (await fetch(`${AGENT}/receipts`, { headers: AUTH })).json();
	check(
		'receipts export via proxy',
		Array.isArray(exported.works),
		`${exported.works?.length} works`
	);
	const receipted = (exported.works ?? []).filter((w) => w.state === 'receipted');
	check('persisted M5 work units present', receipted.length > 0, `${receipted.length} receipted`);
	let verifiedAll = receipted.length > 0;
	for (const work of receipted) {
		const result = await verifyWorkReceipt(
			work,
			hexToBytes(identity.publicKeyXY),
			wallet.addressBytes()
		);
		const names = result.checks.map((c) => `${c.ok ? '✓' : '✗'}${c.name}`).join(' ');
		check(`offline verify ${work.workId.slice(0, 12)}…`, result.ok, names);
		verifiedAll &&= result.ok;
		if (work.userLeaf?.state === 'receipted')
			check(
				'user-leaf KS256 chain walked',
				result.checks.some((c) => c.name === 'user-leaf-inclusion' && c.ok)
			);
	}
	check('all receipted works verify in the UI path', verifiedAll);

	// 5. The UI envelope builder round-trips through the server verifier.
	const claims = newTurnClaims('Say, in one short sentence, why receipts matter.', 'mu-smoke');
	const envelope = buildUserEnvelope(claims, wallet);
	const verified = await verifyUserEnvelope(envelope);
	check(
		'UI envelope verifies server-side',
		verified.address.toLowerCase() === sub,
		`workId ${verified.workId.slice(0, 12)}…`
	);
	check('workId agrees client/server', (await workIdOf(envelope)) === verified.workId);
	const reread = envelopeClaims(envelope);
	check('envelope claims decode for display', reread?.input === claims.input);

	// 6. A fresh attested turn streams to the connected WS client.
	const turn = await fetch(`${AGENT}/turn`, {
		method: 'POST',
		headers: { ...AUTH, 'Content-Type': 'application/json' },
		body: JSON.stringify({ envelopeB64: bytesToB64(envelope) })
	});
	const turnBody = await turn.json().catch(async () => ({ err: await turn.text() }));
	check('attested turn admitted via proxy', turn.ok && turnBody.accepted, turnBody.status);
	if (turn.ok && turnBody.accepted) {
		let sawChunk = false;
		let sawDone = false;
		let streamedText = '';
		for (let i = 0; i < 120 && !sawDone; i++) {
			await sleep(1000);
			for (const frame of frames.splice(0)) {
				if (frame.type !== 'cf_agent_use_chat_response') continue;
				sawChunk = true;
				if (frame.done) sawDone = true;
				if (typeof frame.body === 'string' && frame.body.length > 0) {
					try {
						const chunk = JSON.parse(frame.body);
						if (chunk.type === 'text-delta') streamedText += chunk.delta ?? '';
					} catch {
						/* ignore */
					}
				}
			}
		}
		check('live stream broadcast reaches the WS client', sawChunk);
		check('stream completes', sawDone, streamedText.slice(0, 80));
		const work = await (
			await fetch(`${AGENT}/work?id=${verified.workId}`, { headers: AUTH })
		).json();
		check(
			'fresh work unit committed (queued or beyond)',
			['queued', 'registered', 'sequenced', 'receipted'].includes(work.state),
			work.state
		);
	}

	ws.close();
}

await main();
console.log(failures ? `\n${failures} FAILED` : '\nall checks passed');
process.exit(failures ? 1 : 0);
