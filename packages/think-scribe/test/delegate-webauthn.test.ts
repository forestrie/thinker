/**
 * delegateSealingWebauthn (plan-2608-13 Phase 4.2, ADR-0063): the passkey
 * root authorizes the lane's sealer with TWO assertion gestures — the
 * certificate's own envelope and the on-chain proof's assertion fields —
 * against the coordinator's #238 intake shape. A synthetic authenticator
 * stands in for `navigator.credentials.get`; the registrar voucher and
 * standing entry mirror the coordinator's pending-delegation response.
 */
import { describe, expect, it } from 'vitest';
import {
	base64UrlEncode,
	encodeCborDeterministic,
	encodeCoseSign1Raw,
	encodeSigStructure,
	verifyCoseSign1WithParsedKey
} from '@forestrie/encoding';
import {
	assembleWebauthnDelegationAlgData,
	normalizeEs256SignatureLowS,
	verifyOnchainDelegationSignatureWebauthn,
	type WebauthnAssertionResult
} from '@forestrie/delegation-cose';
import { delegateSealingWebauthn, DelegateError } from '../src/forestrie/delegate.ts';

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
}

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
	const bin = atob(b64);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

/** Synthetic passkey: one assertion ceremony per 32-byte challenge. */
function syntheticAuthenticator(root: CryptoKeyPair) {
	const challenges: Uint8Array[] = [];
	const getAssertion = async (challenge: Uint8Array): Promise<WebauthnAssertionResult> => {
		challenges.push(challenge);
		const clientDataJSON = new TextEncoder().encode(
			`{"type":"webauthn.get","challenge":"${base64UrlEncode(challenge)}","origin":"https://thinker.example","crossOrigin":false}`
		);
		const authenticatorData = new Uint8Array(37);
		authenticatorData.fill(0xa1, 0, 32);
		authenticatorData[32] = FLAG_UP | FLAG_UV;
		const cdjHash = await sha256(clientDataJSON);
		const signedBytes = new Uint8Array(authenticatorData.length + 32);
		signedBytes.set(authenticatorData, 0);
		signedBytes.set(cdjHash, authenticatorData.length);
		const signature = normalizeEs256SignatureLowS(
			new Uint8Array(
				await crypto.subtle.sign(
					{ name: 'ECDSA', hash: 'SHA-256' },
					root.privateKey,
					signedBytes as BufferSource
				)
			)
		);
		return { authenticatorData, clientDataJSON, signature };
	};
	return { getAssertion, challenges };
}

/** COSE key map for a delegated P-256 key, as the coordinator serves it. */
async function delegatedPublicKeyCbor(): Promise<{
	cbor: Uint8Array;
	x: Uint8Array;
	y: Uint8Array;
}> {
	const pair = await generateKeyPair();
	const xy = await exportXy(pair.publicKey);
	const x = xy.slice(0, 32);
	const y = xy.slice(32, 64);
	const cbor = encodeCborDeterministic(
		new Map<number, unknown>([
			[1, 2],
			[-1, 1],
			[-2, x],
			[-3, y]
		])
	);
	return { cbor, x, y };
}

/** Registrar voucher: plain ES256 COSE Sign1 over {1: sealerId, 2: epoch, 3: key}. */
async function buildVoucher(
	registrar: CryptoKeyPair,
	sealerId: string,
	epoch: number,
	delegatedKeyCbor: Uint8Array
): Promise<Uint8Array> {
	const protectedBstr = encodeCborDeterministic(new Map<number, unknown>([[1, -7]]));
	const payload = encodeCborDeterministic(
		new Map<number, unknown>([
			[1, sealerId],
			[2, epoch],
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

const LOG_ID = '0d1f2e3c-4b5a-6978-8796-a5b4c3d2e1f0';

async function fixture() {
	const passkey = await generateKeyPair();
	const registrar = await generateKeyPair();
	const delegated = await delegatedPublicKeyCbor();
	const voucher = await buildVoucher(registrar, 'sealer-1', 3, delegated.cbor);
	const standing = {
		delegatedPublicKey: bytesToB64(delegated.cbor),
		suggestedTtlSeconds: 3600,
		voucher: bytesToB64(voucher),
		sealerId: 'sealer-1',
		epoch: 3
	};
	const submitted: Record<string, unknown>[] = [];
	const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = String(input);
		if (url.endsWith(`/api/logs/${LOG_ID}/pending-delegation`))
			return Response.json({ entries: [standing] });
		if (url.endsWith('/api/delegations/certificate')) {
			submitted.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
			return Response.json({ stored: true });
		}
		throw new Error(`unexpected fetch ${url}`);
	}) as typeof fetch;
	return { passkey, registrar, delegated, submitted, fetchImpl };
}

describe('delegateSealingWebauthn (4.2)', () => {
	it('runs two ceremonies and submits a verifiable certificate + assertion fields', async () => {
		const { passkey, submitted, fetchImpl } = await fixture();
		const rootXY = await exportXy(passkey.publicKey);
		const { getAssertion, challenges } = syntheticAuthenticator(passkey);

		const result = await delegateSealingWebauthn(
			rootXY,
			getAssertion,
			{
				coordinatorUrl: 'https://coordinator.example',
				logId: LOG_ID,
				knownSealerKeyB64: bytesToB64(await exportXy((await fixture()).registrar.publicKey))
			},
			fetchImpl
		).catch((err) => err);
		// The voucher above was built by THIS fixture's registrar; the pinned
		// key from a second fixture must fail closed.
		expect(result).toBeInstanceOf(DelegateError);
		expect(String(result)).toContain('registrar voucher signature failed');
		expect(submitted.length).toBe(0);
		expect(challenges.length).toBe(0);

		// Now with the matching registrar pin: the ceremony completes.
		const good = await fixture();
		const goodRootXY = await exportXy(good.passkey.publicKey);
		const auth = syntheticAuthenticator(good.passkey);
		const res = await delegateSealingWebauthn(
			goodRootXY,
			auth.getAssertion,
			{
				coordinatorUrl: 'https://coordinator.example',
				logId: LOG_ID,
				knownSealerKeyB64: bytesToB64(await exportXy(good.registrar.publicKey))
			},
			good.fetchImpl
		);
		expect(res.sealerId).toBe('sealer-1');
		expect(auth.challenges.length).toBe(2); // one gesture per artifact (Q1)
		expect(auth.challenges[0]).not.toEqual(auth.challenges[1]);

		expect(good.submitted.length).toBe(1);
		const body = good.submitted[0]!;
		expect(typeof body.onchainAuthenticatorData).toBe('string');
		expect(typeof body.onchainClientDataJSON).toBe('string');

		// The certificate verifies under the passkey root via the shared
		// -65800 envelope branch (challenge binding included).
		const certificate = b64ToBytes(String(body.certificate));
		expect(
			await verifyCoseSign1WithParsedKey(certificate, {
				x: goodRootXY.slice(0, 32),
				y: goodRootXY.slice(32, 64),
				curve: 'P-256'
			})
		).toBe(true);

		// The on-chain proof's assertion verifies via the contract mirror.
		const algData = assembleWebauthnDelegationAlgData(
			b64ToBytes(String(body.onchainAuthenticatorData)),
			b64ToBytes(String(body.onchainClientDataJSON))
		);
		expect(
			await verifyOnchainDelegationSignatureWebauthn(
				{
					logIdHex: LOG_ID.replaceAll('-', ''),
					mmrStart: Number(body.mmrStart),
					mmrEnd: Number(body.mmrEnd),
					delegatedKeyX: good.delegated.x,
					delegatedKeyY: good.delegated.y
				},
				b64ToBytes(String(body.onchainSignature)),
				algData,
				goodRootXY.slice(0, 32),
				goodRootXY.slice(32, 64)
			)
		).toBe(true);
	});
});
