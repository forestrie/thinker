/**
 * The agent's ES256 statement profile, plus the work-statement payload.
 *
 * Driven by a stub KeyProvider over a generated P-256 pair, so the whole
 * sign -> parse -> verify path runs offline. The cross-profile rejection
 * matters most: KS256 user envelopes and ES256 agent statements are both COSE
 * Sign1 4-arrays, and confusing one for the other must fail loudly.
 */
import { describe, expect, it } from 'vitest';
import { buildSignedStatement } from '../src/forestrie/cose.ts';
import {
	ReceiptError,
	parseSignedStatement,
	verifyStatementSignature
} from '../src/forestrie/receipt.ts';
import { buildUserEnvelope, inputCommitment } from '../src/forestrie/envelope.ts';
import {
	WORK_STATEMENT_TYPE,
	buildWorkStatementPayload,
	newSaltHex,
	outputCommitment,
	sha256Hex
} from '../src/attestation.ts';
import type { KeyProvider } from '../src/keys/provider.ts';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

/** Minimal in-memory KeyProvider over a fresh P-256 pair. */
async function stubKeys(): Promise<{ keys: KeyProvider; publicKeyXY: Uint8Array }> {
	const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
		'sign',
		'verify'
	])) as CryptoKeyPair;
	// exportKey's overload set can't narrow on the 'raw' literal under
	// @cloudflare/workers-types, so it widens to ArrayBuffer | JsonWebKey.
	const raw = new Uint8Array((await crypto.subtle.exportKey('raw', pair.publicKey)) as ArrayBuffer);
	const publicKeyXY = raw.slice(1); // drop the 0x04 uncompressed tag

	const keys: KeyProvider = {
		epoch: () => 1,
		kid: () => publicKeyXY.slice(0, 32),
		publicKeyXY: async () => publicKeyXY,
		sign: async (bytes) =>
			new Uint8Array(
				await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, bytes)
			),
		signingKeyPair: async () => pair,
		rotate: async () => {
			throw new Error('not used');
		}
	} as KeyProvider;

	return { keys, publicKeyXY };
}

const PAYLOAD = new TextEncoder().encode('{"hello":"world"}');

describe('sign -> parse -> verify', () => {
	it('verifies a freshly signed statement', async () => {
		const { keys, publicKeyXY } = await stubKeys();
		const statement = await buildSignedStatement(keys, {
			payload: PAYLOAD,
			contentType: 'application/json',
			sub: 'urn:thinker:work:abc'
		});

		const parsed = parseSignedStatement(statement);
		await expect(verifyStatementSignature(parsed, publicKeyXY)).resolves.toBe(true);
	});

	it('fails verification when a payload byte is flipped', async () => {
		const { keys, publicKeyXY } = await stubKeys();
		const statement = await buildSignedStatement(keys, {
			payload: PAYLOAD,
			contentType: 'application/json',
			sub: 'urn:thinker:work:abc'
		});

		const parsed = parseSignedStatement(statement);
		parsed.sigStructure[parsed.sigStructure.length - 1] ^= 0x01;
		await expect(verifyStatementSignature(parsed, publicKeyXY)).resolves.toBe(false);
	});
});

describe('protected header profile', () => {
	it('carries alg ES256, the content type, the kid and CWT iss/sub', async () => {
		const { keys } = await stubKeys();
		const statement = await buildSignedStatement(keys, {
			payload: PAYLOAD,
			contentType: 'application/json',
			sub: 'urn:thinker:work:abc',
			iss: 'issuer-name'
		});

		const { protectedHeader, kid } = parseSignedStatement(statement);
		expect(protectedHeader.get(1)).toBe(-7);
		expect(protectedHeader.get(3)).toBe('application/json');
		expect(hex(kid)).toBe(hex(keys.kid()));

		const claims = protectedHeader.get(15) as Map<number, unknown>;
		expect(claims.get(1)).toBe('issuer-name');
		expect(claims.get(2)).toBe('urn:thinker:work:abc');
	});

	it('defaults iss to the kid as lowercase hex', async () => {
		const { keys } = await stubKeys();
		const statement = await buildSignedStatement(keys, {
			payload: PAYLOAD,
			contentType: 'application/json',
			sub: 'urn:thinker:work:abc'
		});

		const claims = parseSignedStatement(statement).protectedHeader.get(15) as Map<number, unknown>;
		expect(claims.get(1)).toBe(hex(keys.kid()));
	});

	it('exposes payloadJson for a JSON payload and null for anything else', async () => {
		const { keys } = await stubKeys();
		const json = await buildSignedStatement(keys, {
			payload: PAYLOAD,
			contentType: 'application/json',
			sub: 's'
		});
		expect(parseSignedStatement(json).payloadJson).toEqual({ hello: 'world' });

		const opaque = await buildSignedStatement(keys, {
			payload: new TextEncoder().encode('not json at all'),
			contentType: 'text/plain',
			sub: 's'
		});
		expect(parseSignedStatement(opaque).payloadJson).toBeNull();
	});
});

describe('cross-profile and guard rejections', () => {
	it('rejects a KS256 user envelope — the two COSE profiles must not be confused', () => {
		const envelope = buildUserEnvelope(
			{
				inputHash: inputCommitment('n', 'hi'),
				sessionId: 's',
				issuedAt: '2026-08-16T09:00:00.000Z',
				nonce: 'n'
			},
			new Uint8Array(32).fill(9)
		);
		expect(() => parseSignedStatement(envelope)).toThrow(/alg must be ES256/);
	});

	it('rejects non-CBOR bytes', () => {
		expect(() => parseSignedStatement(new Uint8Array([0xff, 0xff]))).toThrow(/not decodable CBOR/);
	});

	it('rejects a 65-byte (uncompressed-point) key rather than 64-byte x‖y', async () => {
		const { keys } = await stubKeys();
		const parsed = parseSignedStatement(
			await buildSignedStatement(keys, {
				payload: PAYLOAD,
				contentType: 'application/json',
				sub: 's'
			})
		);
		await expect(verifyStatementSignature(parsed, new Uint8Array(65))).rejects.toBeInstanceOf(
			ReceiptError
		);
	});
});

describe('work-statement payload', () => {
	const input = {
		workId: 'ab'.repeat(32),
		steps: [{ stepNumber: 0, finishReason: 'stop', toolCalls: [], toolResults: [] }],
		salt: 'ef'.repeat(32),
		outputHash: 'cd'.repeat(32),
		leafId: 'leaf-1',
		requestId: 'req-1'
	};

	it('carries the type tag and every input field', () => {
		const parsed = JSON.parse(new TextDecoder().decode(buildWorkStatementPayload(input)));
		expect(parsed.type).toBe(WORK_STATEMENT_TYPE);
		expect(parsed.workId).toBe(input.workId);
		expect(parsed.agentChoices).toEqual(input.steps);
		expect(parsed.outputHash).toBe(input.outputHash);
		expect(parsed.leafId).toBe(input.leafId);
		expect(parsed.requestId).toBe(input.requestId);
		expect(parsed.salt).toBe(input.salt);
	});

	it('does NOT embed the user envelope (D2)', () => {
		// The statement used to carry `userEnvelope`, which — before the envelope
		// itself was redacted — put the user's plaintext on the public log a
		// second time. It costs nothing to drop: workId IS SHA-256(envelope), so
		// naming the workId already names those exact bytes.
		const parsed = JSON.parse(new TextDecoder().decode(buildWorkStatementPayload(input)));
		expect(parsed.userEnvelope).toBeUndefined();
		expect(Object.keys(parsed).sort()).toEqual([
			'agentChoices',
			'leafId',
			'outputHash',
			'requestId',
			'salt',
			'type',
			'workId'
		]);
	});

	it('takes the output commitment over the salt', () => {
		// A bare sha256(outputText) is brute-forceable for short replies — the
		// same weakness the envelope nonce fixes on the input side.
		const text = 'yes.';
		expect(outputCommitment(input.salt, text)).not.toBe(outputCommitment('00'.repeat(32), text));
		expect(outputCommitment(input.salt, text)).toBe(outputCommitment(input.salt, text));
	});

	it('mints a fresh 32-byte salt per statement', () => {
		expect(newSaltHex()).toMatch(/^[0-9a-f]{64}$/);
		expect(newSaltHex()).not.toBe(newSaltHex());
	});
});

describe('sha256Hex', () => {
	it.each([
		['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
		['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad']
	])('hashes %o correctly', async (input, expected) => {
		expect(await sha256Hex(new TextEncoder().encode(input))).toBe(expected);
	});

	it('hashes the view, not the whole backing buffer', async () => {
		// Regression guard for the digest(bytes.buffer) defect.
		const padded = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x61, 0x62, 0x63]);
		expect(await sha256Hex(padded.subarray(4))).toBe(
			await sha256Hex(new TextEncoder().encode('abc'))
		);
	});
});
