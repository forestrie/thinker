/**
 * The user's attestation envelope — the highest-value surface in the package.
 * Its wire profile has to match canopy's KS256 convention exactly, because the
 * same bytes are registrable under a KS256 grant in M5. A drift here is not a
 * test failure, it is receipts that no longer verify.
 *
 * Fixed key + fixed claims throughout, so the encoded output is a golden
 * vector: signing is RFC 6979 deterministic, and the encoder is deterministic
 * by construction.
 */
import { describe, expect, it } from 'vitest';
import {
	COSE_ALG_KS256,
	EnvelopeError,
	buildUserEnvelope,
	verifyUserEnvelope,
	type EnvelopeClaims
} from '../src/forestrie/envelope.ts';
import { cborDecode, cborEncode } from '../src/forestrie/cbor.ts';

const KEY = new Uint8Array(32).fill(7);
const CLAIMS: EnvelopeClaims = {
	input: 'what is a transparency log?',
	sessionId: '0a1b2c3d-0000-4000-8000-000000000001',
	issuedAt: '2026-08-16T09:00:00.000Z',
	nonce: 'ZmFrZS1ub25jZS12YWx1ZQ'
};

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

describe('round-trip', () => {
	it('verifies and returns the claims verbatim', async () => {
		const verified = await verifyUserEnvelope(buildUserEnvelope(CLAIMS, KEY));
		expect(verified.claims).toEqual(CLAIMS);
	});

	it('derives workId as SHA-256 of the envelope bytes', async () => {
		const envelope = buildUserEnvelope(CLAIMS, KEY);
		const verified = await verifyUserEnvelope(envelope);
		const expected = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', envelope)));
		expect(verified.workId).toBe(expected);
	});

	it('hashes the view, not the whole backing buffer', async () => {
		// Regression guard: digest(envelope.buffer) would hash the 4-byte prefix
		// too and silently produce a different workId for the same envelope.
		const envelope = buildUserEnvelope(CLAIMS, KEY);
		const padded = new Uint8Array(envelope.length + 4);
		padded.set(envelope, 4);
		const view = padded.subarray(4);
		expect(view.byteOffset).toBe(4);
		expect((await verifyUserEnvelope(view)).workId).toBe(
			(await verifyUserEnvelope(envelope)).workId
		);
	});

	it('recovers a lowercase 0x address', async () => {
		const { address } = await verifyUserEnvelope(buildUserEnvelope(CLAIMS, KEY));
		expect(address).toMatch(/^0x[0-9a-f]{40}$/);
	});

	it('is byte-deterministic for identical inputs (RFC 6979)', () => {
		expect(hex(buildUserEnvelope(CLAIMS, KEY))).toBe(hex(buildUserEnvelope(CLAIMS, KEY)));
	});
});

describe('wire profile', () => {
	it('carries exactly {1: KS256, 3: application/json, 4: 20-byte address}', () => {
		const decoded = cborDecode(buildUserEnvelope(CLAIMS, KEY));
		if (!Array.isArray(decoded)) throw new Error('envelope must be an array');
		const header = cborDecode(decoded[0] as Uint8Array);
		if (!(header instanceof Map)) throw new Error('protected header must be a map');

		expect([...header.keys()].sort((a, b) => a - b)).toEqual([1, 3, 4]);
		expect(header.get(1)).toBe(COSE_ALG_KS256);
		expect(header.get(3)).toBe('application/json');
		expect((header.get(4) as Uint8Array).length).toBe(20);
	});

	it('signs r‖s‖v with a RAW recovery byte, not +27', () => {
		// The comment at envelope.ts:69 flags this as easy to get backwards, and
		// a noble upgrade could silently flip it. 27 would fail verify's v > 3.
		const decoded = cborDecode(buildUserEnvelope(CLAIMS, KEY));
		if (!Array.isArray(decoded)) throw new Error('envelope must be an array');
		const signature = decoded[3] as Uint8Array;
		expect(signature.length).toBe(65);
		expect(signature[64]).toBeGreaterThanOrEqual(0);
		expect(signature[64]).toBeLessThanOrEqual(3);
	});

	it('is a 4-element COSE Sign1 with an empty unprotected map', () => {
		const decoded = cborDecode(buildUserEnvelope(CLAIMS, KEY));
		if (!Array.isArray(decoded)) throw new Error('envelope must be an array');
		expect(decoded).toHaveLength(4);
		expect(decoded[1]).toEqual(new Map());
	});
});

describe('rejections', () => {
	const reject = async (envelope: Uint8Array, pattern: RegExp) => {
		await expect(verifyUserEnvelope(envelope)).rejects.toThrow(pattern);
		await expect(verifyUserEnvelope(envelope)).rejects.toBeInstanceOf(EnvelopeError);
	};

	it('rejects non-CBOR bytes', async () => {
		await reject(new Uint8Array([0xff, 0xff, 0xff]), /not decodable CBOR/);
	});

	it('rejects a 3-element array', async () => {
		await reject(cborEncode([new Uint8Array(1), new Map(), new Uint8Array(1)]), /4-array/);
	});

	it('rejects a non-bstr protected header', async () => {
		await reject(
			cborEncode(['nope', new Map(), new Uint8Array(1), new Uint8Array(65)]),
			/byte strings/
		);
	});

	it('rejects a 64-byte signature', async () => {
		await reject(
			cborEncode([new Uint8Array(1), new Map(), new Uint8Array(1), new Uint8Array(64)]),
			/65 bytes/
		);
	});

	it('rejects a non-KS256 alg', async () => {
		const header = new Map<number, unknown>([[1, -7]]);
		await reject(
			cborEncode([cborEncode(header as never), new Map(), new Uint8Array(1), new Uint8Array(65)]),
			/alg must be KS256/
		);
	});

	it('rejects a 32-byte kid', async () => {
		const header = new Map<number, unknown>([
			[1, COSE_ALG_KS256],
			[4, new Uint8Array(32)]
		]);
		await reject(
			cborEncode([cborEncode(header as never), new Map(), new Uint8Array(1), new Uint8Array(65)]),
			/20-byte signer address/
		);
	});

	it('rejects an EIP-155 style v of 27', async () => {
		const decoded = cborDecode(buildUserEnvelope(CLAIMS, KEY)) as unknown[];
		const signature = new Uint8Array(decoded[3] as Uint8Array);
		signature[64] = 27;
		decoded[3] = signature;
		await reject(cborEncode(decoded as never), /v must be raw 0\.\.3/);
	});

	it('rejects a flipped payload byte — kid no longer matches the signer', async () => {
		const decoded = cborDecode(buildUserEnvelope(CLAIMS, KEY)) as unknown[];
		const payload = new Uint8Array(decoded[2] as Uint8Array);
		payload[0] ^= 0x01;
		decoded[2] = payload;
		await reject(cborEncode(decoded as never), /does not match recovered signer/);
	});

	it('rejects claims missing a required field', async () => {
		const partial = { ...CLAIMS } as Partial<EnvelopeClaims>;
		delete partial.nonce;
		await reject(
			buildUserEnvelope(partial as EnvelopeClaims, KEY),
			/claims must be \{input, sessionId, issuedAt, nonce\}/
		);
	});
});
