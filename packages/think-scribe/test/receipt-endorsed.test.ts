/**
 * The offline rung under passkey custody after ADR-0065 (plan-2608-14 3.3):
 * the verifier resolves the leaf signer from the STATEMENT BYTES — the
 * endorsement rides inside the leaf at -65801 — never from a `/receipts`
 * export. The export-fed `resolveEndorsedSessionKey` is gone.
 *
 * A real sealed receipt needs a lane, so the receipt stage necessarily fails
 * on a stub here; these pin the stages BEFORE it (endorsement → leaf →
 * window) and the pure input-binding chain, asserting on the check list.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import * as receipt from '../src/forestrie/receipt.ts';
import {
	verifyUserLeafReceipt,
	verifyWorkReceipt,
	type WorkExport
} from '../src/forestrie/receipt.ts';
import { buildUserEnvelopeEs256, inputCommitment } from '../src/forestrie/envelope.ts';
import { buildSignedStatement } from '../src/forestrie/cose.ts';
import {
	buildWorkStatementPayload,
	newSaltHex,
	outputCommitment,
	sha256Hex
} from '../src/attestation.ts';
import type { KeyProvider } from '../src/keys/provider.ts';
import {
	INSIDE_MS,
	WINDOW,
	es256Signer,
	generateP256,
	passkeyCustody,
	type PasskeyCustody
} from './helpers/endorsed.ts';

const NONCE = 'e6f1c0d9a7b2453e8f0a1b2c3d4e5f60';
const INPUT = 'what did I actually ask?';
const OUTPUT = 'exactly this.';

const b64 = (bytes: Uint8Array) => {
	let bin = '';
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
};
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

/** SCRAPI entryId (32 hex) whose idtimestamp time component is `unixMs`. */
function entryIdForUnixMs(unixMs: number): string {
	const id = (BigInt(unixMs) - ((1n << 40n) - 1n)) << 24n;
	const be8 = new Uint8Array(8);
	new DataView(be8.buffer).setBigUint64(0, id, false);
	return hex(be8) + '00'.repeat(8);
}

async function agentKeys(): Promise<{ keys: KeyProvider; publicKeyXY: Uint8Array }> {
	const pair = await generateP256();
	const publicKeyXY = (await es256Signer(pair)).xy;
	const keys = {
		epoch: () => 1,
		kid: () => publicKeyXY.slice(0, 32),
		publicKeyXY: async () => publicKeyXY,
		sign: async (bytes: Uint8Array) =>
			new Uint8Array(
				await crypto.subtle.sign(
					{ name: 'ECDSA', hash: 'SHA-256' },
					pair.privateKey,
					bytes as BufferSource
				)
			),
		signingKeyPair: async () => pair,
		rotate: async () => {
			throw new Error('not used');
		}
	} as unknown as KeyProvider;
	return { keys, publicKeyXY };
}

let custody: PasskeyCustody;
let envelope: Uint8Array;
let work: WorkExport;
let agentXY: Uint8Array;
beforeAll(async () => {
	custody = await passkeyCustody();
	envelope = await buildUserEnvelopeEs256(
		{
			inputHash: inputCommitment(NONCE, INPUT),
			sessionId: 'session-1',
			issuedAt: '2026-08-29T09:00:00.000Z',
			nonce: NONCE
		},
		custody.sessionSigner,
		{ endorsement: custody.endorsement }
	);
	const workId = await sha256Hex(envelope);
	const { keys, publicKeyXY } = await agentKeys();
	agentXY = publicKeyXY;
	const salt = newSaltHex();
	const statement = await buildSignedStatement(keys, {
		payload: buildWorkStatementPayload({
			workId,
			steps: [],
			salt,
			outputHash: outputCommitment(salt, OUTPUT),
			leafId: 'leaf-1',
			requestId: 'req-1'
		}),
		contentType: 'application/json',
		sub: `urn:thinker:work:${workId}`
	});
	work = {
		workId,
		state: 'receipted',
		envelopeB64: b64(envelope),
		input: INPUT,
		statementB64: b64(statement),
		entryId: entryIdForUnixMs(INSIDE_MS),
		receiptB64: b64(new Uint8Array([0xa0])),
		leafId: 'leaf-1',
		currentOutputText: OUTPUT,
		userLeaf: {
			state: 'receipted',
			entryId: entryIdForUnixMs(INSIDE_MS),
			receiptB64: b64(new Uint8Array([0xa0]))
		}
	};
});

const check = (
	result: { checks: Array<{ name: string; ok: boolean; detail?: string }> },
	name: string
) => result.checks.find((c) => c.name === name);

describe('the export-fed rung is gone', () => {
	it('receipt.ts no longer exports resolveEndorsedSessionKey', () => {
		expect((receipt as Record<string, unknown>).resolveEndorsedSessionKey).toBeUndefined();
	});
});

describe('input binding under passkey custody — from the statement bytes', () => {
	it('resolves the session key from the leaf’s own endorsement under the PASSKEY root', async () => {
		const result = await verifyWorkReceipt(work, agentXY, custody.rootXy);
		const binding = check(result, 'input-binding');
		expect(binding?.ok).toBe(true);
		expect(binding?.detail).toMatch(/endorsed session key/);
	});

	it('REFUSES under a different root — no fallback to verifying the leaf under that root', async () => {
		const other = await passkeyCustody();
		const result = await verifyWorkReceipt(work, agentXY, other.rootXy);
		const binding = check(result, 'input-binding');
		expect(binding?.ok).toBe(false);
		expect(binding?.detail).toMatch(/endorsement_root_mismatch/);
	});

	it('still refuses a substituted plaintext under a valid endorsement chain', async () => {
		const result = await verifyWorkReceipt(
			{ ...work, input: 'something else' },
			agentXY,
			custody.rootXy
		);
		expect(check(result, 'input-binding')?.ok).toBe(false);
	});
});

describe('user-leaf rung — verifyEndorsedLeaf over the exact registered bytes', () => {
	it('passes endorsement → leaf → window and fails only at the (stub) receipt stage', async () => {
		const result = await verifyUserLeafReceipt(work.envelopeB64!, work.userLeaf!, custody.rootXy);
		const leaf = check(result, 'user-leaf-endorsed');
		expect(leaf?.ok).toBe(false);
		expect(leaf?.detail).toMatch(/^receipt:/);
	});

	it('fails at the window stage when the receipted idtimestamp is outside the endorsement window', async () => {
		const late = { ...work.userLeaf!, entryId: entryIdForUnixMs(WINDOW.notAfter + 60_000) };
		const result = await verifyUserLeafReceipt(work.envelopeB64!, late, custody.rootXy);
		expect(check(result, 'user-leaf-endorsed')?.detail).toMatch(/^window: endorsement_expired/);
	});

	it('fails at the endorsement stage under the wrong root', async () => {
		const other = await passkeyCustody();
		const result = await verifyUserLeafReceipt(work.envelopeB64!, work.userLeaf!, other.rootXy);
		expect(check(result, 'user-leaf-endorsed')?.detail).toMatch(
			/^endorsement: endorsement_root_mismatch/
		);
	});

	it('a plain (4a) envelope with no endorsement takes the root-signed path, not the endorsed rung', async () => {
		const root = await es256Signer(await generateP256());
		const plain = await buildUserEnvelopeEs256(
			{ inputHash: inputCommitment(NONCE, INPUT), sessionId: 's', issuedAt: 'i', nonce: NONCE },
			root
		);
		const result = await verifyUserLeafReceipt(b64(plain), work.userLeaf!, root.xy);
		expect(check(result, 'user-leaf-endorsed')).toBeUndefined();
		expect(check(result, 'user-leaf-receipt')).toBeDefined();
	});
});
