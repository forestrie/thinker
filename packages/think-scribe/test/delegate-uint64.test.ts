/**
 * Delegation MMR range as uint64 (FOR-613, plan-2611-01 D1): the certificate
 * carries the range as CBOR major type 0 (`bigint` in delegation-cose ≥0.5),
 * and the coordinator's JSON contract carries every range bound as a
 * canonical decimal string — a JSON number loses precision above 2^53.
 * These tests drive `delegateSealing` (ES256, K(L) in the provider) against a
 * mock coordinator and check both encodings round-trip a range end above
 * 2^53 exactly.
 */
import { describe, expect, it } from 'vitest';
import {
	encodeCborDeterministic,
	encodeCoseSign1Raw,
	encodeSigStructure
} from '@forestrie/encoding';
import {
	parseDelegationCertificate,
	verifyOnchainDelegationSignatureEs256
} from '@forestrie/delegation-cose';
import { delegateSealing } from '../src/forestrie/delegate.ts';
import type { KeyProvider } from '../src/keys/provider.ts';

const LOG_ID = '0d1f2e3c-4b5a-6978-8796-a5b4c3d2e1f0';
const LOG_ID_HEX = LOG_ID.replaceAll('-', '');
/** 2^53 + 7: not representable as a JS number (rounds to 2^53 + 8). */
const ABOVE_2_53 = 2n ** 53n + 7n;
const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/;

async function generateKeyPair(): Promise<CryptoKeyPair> {
	return (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
		'sign',
		'verify'
	])) as CryptoKeyPair;
}

async function exportXy(publicKey: CryptoKey): Promise<Uint8Array> {
	const raw = new Uint8Array((await crypto.subtle.exportKey('raw', publicKey)) as ArrayBuffer);
	return raw.slice(1, 65);
}

function bytesToB64(bytes: Uint8Array): string {
	let bin = '';
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
}

function b64ToBytes(b64: string): Uint8Array {
	return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/** Registrar voucher: plain ES256 COSE Sign1 over {1: sealerId, 2: epoch, 3: key}. */
async function buildVoucher(
	registrar: CryptoKeyPair,
	delegatedKeyCbor: Uint8Array
): Promise<Uint8Array> {
	const protectedBstr = encodeCborDeterministic(new Map<number, unknown>([[1, -7]]));
	const payload = encodeCborDeterministic(
		new Map<number, unknown>([
			[1, 'sealer-1'],
			[2, 3],
			[3, delegatedKeyCbor]
		])
	);
	const sigStructure = encodeSigStructure(protectedBstr, new Uint8Array(0), payload);
	const signature = new Uint8Array(
		await crypto.subtle.sign(
			{ name: 'ECDSA', hash: 'SHA-256' },
			registrar.privateKey,
			sigStructure as BufferSource
		)
	);
	return encodeCoseSign1Raw(protectedBstr, new Map(), payload, signature);
}

/**
 * Mock coordinator. The pending-delegation response carries, beside the
 * standing entry, a range-bearing pending entry in the D1 shape (decimal
 * strings) that `delegateSealing` must skip.
 */
async function fixture() {
	const root = await generateKeyPair();
	const registrar = await generateKeyPair();
	const delegatedXY = await exportXy((await generateKeyPair()).publicKey);
	const delegated = { x: delegatedXY.slice(0, 32), y: delegatedXY.slice(32, 64) };
	const delegatedCbor = encodeCborDeterministic(
		new Map<number, unknown>([
			[1, 2],
			[-1, 1],
			[-2, delegated.x],
			[-3, delegated.y]
		])
	);
	const standing = {
		delegatedPublicKey: bytesToB64(delegatedCbor),
		suggestedTtlSeconds: 3600,
		voucher: bytesToB64(await buildVoucher(registrar, delegatedCbor)),
		sealerId: 'sealer-1',
		epoch: 3
	};
	const rangePending = {
		id: 'p-1',
		logIdHex32: LOG_ID_HEX,
		mmrStart: '0',
		mmrEnd: ABOVE_2_53.toString(10),
		delegatedPublicKey: bytesToB64(delegatedCbor),
		requestedAt: 1
	};
	const submitted: Record<string, unknown>[] = [];
	const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = String(input);
		if (url.endsWith(`/api/logs/${LOG_ID}/pending-delegation`))
			return Response.json({ entries: [rangePending, standing] });
		if (url.endsWith('/api/delegations/certificate')) {
			submitted.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
			return Response.json({ stored: true });
		}
		throw new Error(`unexpected fetch ${url}`);
	}) as typeof fetch;
	const keys = { signingKeyPair: async () => root } as unknown as KeyProvider;
	const params = {
		coordinatorUrl: 'https://coordinator.example',
		logId: LOG_ID,
		knownSealerKeyB64: bytesToB64(await exportXy(registrar.publicKey))
	};
	return { root, delegated, submitted, fetchImpl, keys, params };
}

describe('delegateSealing — uint64 MMR range (FOR-613)', () => {
	it('round-trips mmrEnd > 2^53 through the certificate and the coordinator JSON', async () => {
		const f = await fixture();
		const result = await delegateSealing(
			f.keys,
			{ ...f.params, horizonMmrEnd: ABOVE_2_53 },
			f.fetchImpl
		);

		expect(f.submitted.length).toBe(1);
		const body = f.submitted[0]!;
		// D1: canonical decimal strings on the wire, never JSON numbers.
		expect(body.mmrStart).toBe('0');
		expect(body.mmrEnd).toBe('9007199254740999');
		expect(String(body.mmrEnd)).toMatch(CANONICAL_DECIMAL);

		// The certificate's range is the exact uint64, not a rounded double.
		const info = parseDelegationCertificate(b64ToBytes(String(body.certificate)));
		expect(info.mmrStart).toBe(0n);
		expect(info.mmrEnd).toBe(ABOVE_2_53);

		// The on-chain proof signs the same exact range.
		const rootXY = await exportXy(f.root.publicKey);
		expect(
			await verifyOnchainDelegationSignatureEs256(
				{
					logIdHex: LOG_ID_HEX,
					mmrStart: BigInt(String(body.mmrStart)),
					mmrEnd: BigInt(String(body.mmrEnd)),
					delegatedKeyX: f.delegated.x,
					delegatedKeyY: f.delegated.y
				},
				b64ToBytes(String(body.onchainSignature)),
				rootXY.slice(0, 32),
				rootXY.slice(32, 64)
			)
		).toBe(true);

		// The result is spread into a JSON response by the DO route: its range
		// end is the same canonical decimal string, and it serialises.
		expect(result.mmrEnd).toBe('9007199254740999');
		expect(() => JSON.stringify(result)).not.toThrow();
	});

	it('defaults the horizon to 2^53-1 (the CLI default) as a decimal string', async () => {
		const f = await fixture();
		await delegateSealing(f.keys, f.params, f.fetchImpl);
		const body = f.submitted[0]!;
		expect(body.mmrStart).toBe('0');
		expect(body.mmrEnd).toBe(String(Number.MAX_SAFE_INTEGER));
		const info = parseDelegationCertificate(b64ToBytes(String(body.certificate)));
		expect(info.mmrEnd).toBe(BigInt(Number.MAX_SAFE_INTEGER));
	});
});
