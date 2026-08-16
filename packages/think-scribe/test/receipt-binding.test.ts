/**
 * The binding checks in `verifyWorkReceipt`, after the Phase D redaction.
 *
 * Receipt/inclusion verification needs a real sealed receipt from a lane, so
 * these drive the checks that are pure local arithmetic — work binding, input
 * binding and transcript binding — and assert on the check list rather than the
 * overall verdict (the `receipt` check necessarily fails on a stub receipt).
 *
 * The one that matters most is the negative: a bundle whose `input` does not
 * open the commitment must say so, loudly, rather than pass because everything
 * else about it is well-formed.
 */
import { describe, expect, it } from 'vitest';
import { buildSignedStatement } from '../src/forestrie/cose.ts';
import { verifyWorkReceipt, type WorkExport } from '../src/forestrie/receipt.ts';
import { buildUserEnvelope, inputCommitment } from '../src/forestrie/envelope.ts';
import {
	buildWorkStatementPayload,
	newSaltHex,
	outputCommitment,
	sha256Hex
} from '../src/attestation.ts';
import type { KeyProvider } from '../src/keys/provider.ts';

const WALLET = new Uint8Array(32).fill(3);
const NONCE = 'e6f1c0d9a7b2453e8f0a1b2c3d4e5f60';
const INPUT = 'what did I actually ask?';
const OUTPUT = 'exactly this.';

async function stubKeys(): Promise<{ keys: KeyProvider; publicKeyXY: Uint8Array }> {
	const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
		'sign',
		'verify'
	])) as CryptoKeyPair;
	const raw = new Uint8Array((await crypto.subtle.exportKey('raw', pair.publicKey)) as ArrayBuffer);
	const publicKeyXY = raw.slice(1);
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

const b64 = (bytes: Uint8Array) => {
	let bin = '';
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
};

/** A receipted-shaped export whose statement genuinely commits to the turn. */
async function fixture(): Promise<{
	work: WorkExport;
	publicKeyXY: Uint8Array;
	salt: string;
	envelopeB64: string;
}> {
	const { keys, publicKeyXY } = await stubKeys();
	const envelope = buildUserEnvelope(
		{
			inputHash: inputCommitment(NONCE, INPUT),
			sessionId: 'session-1',
			issuedAt: '2026-08-16T09:00:00.000Z',
			nonce: NONCE
		},
		WALLET
	);
	const workId = await sha256Hex(envelope);
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
	return {
		publicKeyXY,
		salt,
		envelopeB64: b64(envelope),
		work: {
			workId,
			state: 'receipted',
			envelopeB64: b64(envelope),
			statementB64: b64(statement),
			entryId: '00'.repeat(8),
			receiptB64: b64(new Uint8Array([0xa0])),
			leafId: 'leaf-1',
			currentOutputText: OUTPUT
		}
	};
}

const check = (
	result: { checks: Array<{ name: string; ok: boolean; detail?: string }> },
	name: string
) => result.checks.find((c) => c.name === name);

describe('work binding without the embedded envelope', () => {
	it('passes on workId = H(envelope) and the statement naming it', async () => {
		const { work, publicKeyXY } = await fixture();
		const result = await verifyWorkReceipt(work, publicKeyXY);
		expect(check(result, 'work-binding')?.ok).toBe(true);
		expect(check(result, 'statement-signature')?.ok).toBe(true);
	});

	it('SKIPS rather than fails when the export omits the envelope', async () => {
		// D2: the statement no longer carries the envelope, so an export that
		// leaves it out must degrade to the workId conjunct — mirroring the
		// transcript-binding skip — not fail the whole unit.
		const { work, publicKeyXY } = await fixture();
		const result = await verifyWorkReceipt({ ...work, envelopeB64: undefined }, publicKeyXY);
		const binding = check(result, 'work-binding');
		expect(binding?.ok).toBe(true);
		expect(binding?.detail).toMatch(/envelope absent/);
		expect(check(result, 'input-binding')).toBeUndefined();
	});

	it('fails when the envelope is not the one the statement names', async () => {
		const { work, publicKeyXY } = await fixture();
		// A different envelope — same wallet, different nonce, so a different
		// workId. (Envelope construction is deterministic: identical claims and
		// key produce identical bytes, which is itself a tested property.)
		const other = buildUserEnvelope(
			{
				inputHash: inputCommitment('ff'.repeat(16), INPUT),
				sessionId: 'session-1',
				issuedAt: '2026-08-16T09:00:00.000Z',
				nonce: 'ff'.repeat(16)
			},
			WALLET
		);
		const result = await verifyWorkReceipt({ ...work, envelopeB64: b64(other) }, publicKeyXY);
		expect(check(result, 'work-binding')?.ok).toBe(false);
	});
});

describe('input binding from a proof bundle', () => {
	it('confirms the holder’s text opens the signed commitment', async () => {
		const { work, publicKeyXY } = await fixture();
		const result = await verifyWorkReceipt({ ...work, input: INPUT }, publicKeyXY);
		const binding = check(result, 'input-binding');
		expect(binding?.ok).toBe(true);
		expect(binding?.detail).toMatch(/H\(nonce ‖ input\)/);
	});

	it('REFUSES a bundle whose text is not what was committed', async () => {
		// A doctored bundle is the whole threat model of selective disclosure:
		// everything else verifies, and only this check separates "here is what
		// I said" from "here is what I would like you to think I said".
		const { work, publicKeyXY } = await fixture();
		const result = await verifyWorkReceipt(
			{ ...work, input: 'something I never sent' },
			publicKeyXY
		);
		const binding = check(result, 'input-binding');
		expect(binding?.ok).toBe(false);
		expect(binding?.detail).toMatch(/does NOT open/);
		expect(result.ok).toBe(false);
	});
});

describe('transcript binding is salted', () => {
	it('accepts the DO’s current text under the statement salt', async () => {
		const { work, publicKeyXY } = await fixture();
		const result = await verifyWorkReceipt(work, publicKeyXY);
		expect(check(result, 'transcript-binding')?.ok).toBe(true);
	});

	it('detects a rewritten transcript (the tamper beat)', async () => {
		const { work, publicKeyXY } = await fixture();
		const result = await verifyWorkReceipt(
			{ ...work, currentOutputText: 'something else entirely' },
			publicKeyXY
		);
		expect(check(result, 'transcript-binding')?.ok).toBe(false);
	});

	it('does not accept an UNSALTED hash of the right text', async () => {
		// Guards the D2 change itself: if outputHash ever regressed to a bare
		// sha256(outputText), this check would still pass and the brute-force
		// weakness would be back silently.
		const { salt } = await fixture();
		expect(outputCommitment(salt, OUTPUT)).not.toBe(
			await sha256Hex(new TextEncoder().encode(OUTPUT))
		);
	});
});
