// verify-receipts — offline receipt verification (Auditor stand-in, plan §2
// T8). Pulls the Scribe's receipt export (or reads a saved one) and verifies
// every receipted work unit with the log absent:
//
//   user-envelope       the user's KS256 signature over their input, and its
//                       binding to the instance's wcc-1 principal
//   statement-signature the agent's ES256 COSE Sign1 over the work statement
//   receipt             inclusion proof + sealed checkpoint + delegation cert
//                       under the known log key (@forestrie/receipt-verify)
//   work-binding        workId = H(envelope); the statement embeds it
//   user-leaf-*         (O4 separate mode, M5) the envelope's OWN leaf on the
//                       user's log: KS256 delegation cert under the wallet →
//                       coverage window → sealer signature → inclusion
//   transcript-binding  H(the DO's currently-claimed output) = committed
//                       outputHash — the check the tamper beat breaks
//
// Trust root = the agent's public key ("known log key", FOR-297). Default is
// the key the export itself reports — fine for the demo loop, but a real
// auditor passes --known-log-key with a value obtained at enrolment time.
//
// Usage:
//   verify-receipts.sh --url http://localhost:8787/agents/scribe/user-0x… \
//                      --token <wcc-1 bearer> [--out dir] [--known-log-key hex|b64]
//   verify-receipts.sh --export receipts.json [--known-log-key hex|b64]
//   … [--work <workId>]   verify a single work unit from the export
//
// Node >= 22.18 (imports the repo's TypeScript sources via type stripping).
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyWorkReceipt } from '../packages/think-scribe/src/forestrie/receipt.ts';
import { verifyUserEnvelope } from '../packages/think-scribe/src/forestrie/envelope.ts';

function die(msg) {
	console.error(`verify-receipts: ${msg}`);
	process.exit(2);
}

const args = process.argv.slice(2);
const opt = {};
for (let i = 0; i < args.length; i++) {
	const name = args[i];
	if (!name.startsWith('--')) die(`unexpected argument ${name}`);
	opt[name.slice(2)] = args[i + 1];
	i++;
}
if (!opt.url && !opt.export) die('need --url <agent url> (with --token) or --export <file>');

let exported;
if (opt.export) {
	exported = JSON.parse(readFileSync(opt.export, 'utf8'));
} else {
	if (!opt.token) die('--url needs --token <wcc-1 bearer>');
	const res = await fetch(`${opt.url.replace(/\/$/, '')}/receipts`, {
		headers: { Authorization: `Bearer ${opt.token}` }
	});
	if (!res.ok) die(`GET /receipts failed: HTTP ${res.status} ${await res.text()}`);
	exported = await res.json();
}

if (opt.out) {
	mkdirSync(opt.out, { recursive: true });
	writeFileSync(join(opt.out, 'receipts.json'), JSON.stringify(exported, null, 2));
}

function keyBytes(value) {
	if (/^[0-9a-f]{128}$/i.test(value)) return Uint8Array.from(Buffer.from(value, 'hex'));
	const raw = Buffer.from(value, 'base64');
	if (raw.length === 64) return Uint8Array.from(raw);
	die('known log key must be 64 bytes: 128 hex chars or base64');
}

let trustKey;
if (opt['known-log-key']) {
	trustKey = keyBytes(opt['known-log-key']);
} else {
	if (!exported.identity?.publicKeyXY)
		die('export carries no identity and no --known-log-key given');
	trustKey = keyBytes(exported.identity.publicKeyXY);
	console.log(
		'note: trusting the agent key reported by the export itself — a real auditor passes --known-log-key from enrolment'
	);
}

let works = exported.works ?? [];
if (opt.work) works = works.filter((w) => w.workId === opt.work);
console.log(
	`${works.length} work unit(s) ${opt.work ? 'selected' : 'exported'} for principal ${exported.principal}\n`
);

let receipted = 0;
let failed = 0;
for (const work of works) {
	const shortId = `${work.workId.slice(0, 16)}…`;
	if (work.state !== 'receipted') {
		console.log(
			`○ ${shortId} — ${work.state}${work.error ? ` (${work.error})` : ''}, not verifiable yet`
		);
		continue;
	}
	receipted++;

	const checks = [];
	try {
		const envelope = Uint8Array.from(Buffer.from(work.envelopeB64, 'base64'));
		const verified = await verifyUserEnvelope(envelope);
		const bound =
			typeof exported.principal !== 'string' ||
			verified.address.toLowerCase() === exported.principal.toLowerCase();
		checks.push({
			name: 'user-envelope',
			ok: bound,
			detail: bound
				? `signed by ${verified.address}`
				: `signer ${verified.address} is not the bound principal`
		});
	} catch (err) {
		checks.push({ name: 'user-envelope', ok: false, detail: String(err) });
	}

	// User-leaf trust root = the bound principal's wallet address (the same
	// enrolment-time provenance as the agent key) — not the envelope's own
	// claim of its signer, which would be self-referential.
	const principalAddress =
		typeof exported.principal === 'string' && /^0x[0-9a-f]{40}$/i.test(exported.principal)
			? Uint8Array.from(Buffer.from(exported.principal.slice(2), 'hex'))
			: null;
	const result = await verifyWorkReceipt(work, trustKey, principalAddress);
	checks.push(...result.checks);

	const ok = checks.every((c) => c.ok);
	if (!ok) failed++;
	console.log(`${ok ? '✔' : '✘'} ${shortId} — entry ${work.entryId}`);
	for (const check of checks)
		console.log(
			`    ${check.ok ? '✓' : '✗'} ${check.name}${check.detail ? ` — ${check.detail}` : ''}`
		);

	if (opt.out) {
		const stem = join(opt.out, work.workId.slice(0, 16));
		writeFileSync(`${stem}.statement.cose`, Buffer.from(work.statementB64, 'base64'));
		writeFileSync(`${stem}.receipt.cbor`, Buffer.from(work.receiptB64, 'base64'));
	}
}

if (!receipted) {
	console.log('\nno receipted work units to verify');
	process.exit(1);
}
if (failed) {
	console.log(`\n${failed}/${receipted} receipted work unit(s) DIVERGE from their receipts`);
	process.exit(1);
}
console.log(`\nall ${receipted} receipted work unit(s) verify offline`);
