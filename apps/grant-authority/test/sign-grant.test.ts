/**
 * Equivalence proof for the WebCrypto grant signer.
 *
 * This is the riskiest single change in the authority port: if the wire bytes
 * drift from what @forestrie/grant-builder produces, every grant this Worker
 * issues is rejected by the lane — or worse, accepted and unverifiable later.
 *
 * The obvious test — "sign the same payload both ways and compare bytes" —
 * CANNOT work. ECDSA draws a random `k` per signature (this is not the RFC 6979
 * deterministic signing used for the user envelope), so two signings never agree
 * on any implementation. So equivalence is proved in the two parts that
 * actually matter:
 *
 *   1. every byte of framing outside the signature is identical
 *   2. each implementation's signature verifies under the same public key over
 *      the same Sig_structure — including cross-wise, WebCrypto verifying
 *      Node's output and vice versa
 */
import { describe, expect, it } from 'vitest';
import { createPrivateKey, generateKeyPairSync } from 'node:crypto';
import { signGrantPayloadWithEs256Pem } from '@forestrie/grant-builder';
import { grantSigStructure, importAuthorityKey, signGrantPayload } from '../src/sign-grant.ts';

/** A P-256 keypair as both a PKCS#8 PEM (Node path) and a JWK (Worker path). */
function keyMaterial() {
	const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
	const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
	const jwk = createPrivateKey(pem).export({ format: 'jwk' });
	return { pem, jwk: JSON.stringify(jwk) };
}

/** A stand-in for canonical grant v0 CBOR — the signer treats it as opaque. */
const GRANT_PAYLOAD = new Uint8Array([
	0xa3,
	0x01,
	0x50,
	...new Uint8Array(16).fill(0xab),
	0x02,
	0x18,
	0x2a,
	0x03,
	0x41,
	0x07
]);

/**
 * The signature is the trailing bstr: 64 bytes plus its 2-byte CBOR header
 * (0x58 0x40). Everything before it is deterministic framing.
 */
const SIGNATURE_FIELD_BYTES = 66;

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

describe('wire framing matches @forestrie/grant-builder byte for byte', () => {
	it('agrees on everything outside the signature', async () => {
		const { pem, jwk } = keyMaterial();
		const { privateKey } = await importAuthorityKey(jwk);

		const fromNode = signGrantPayloadWithEs256Pem(GRANT_PAYLOAD, pem);
		const fromWorker = await signGrantPayload(GRANT_PAYLOAD, privateKey);

		expect(fromWorker.length).toBe(fromNode.length);
		expect(hex(fromWorker.subarray(0, -SIGNATURE_FIELD_BYTES))).toBe(
			hex(fromNode.subarray(0, -SIGNATURE_FIELD_BYTES))
		);
	});

	it('emits the ES256 protected header and both unprotected keys', async () => {
		const { jwk } = keyMaterial();
		const { privateKey } = await importAuthorityKey(jwk);
		const signed = await signGrantPayload(GRANT_PAYLOAD, privateKey);

		// 0x84 array(4), 0x43 bstr(3), then {1: -7}; 0xa2 opens the unprotected map(2)
		expect(hex(signed.subarray(0, 5))).toBe('8443a10126');
		expect(signed[5]).toBe(0xa2);
		// -65538 (grant v0 CBOR) and -65537 (idtimestamp) both present
		expect(hex(signed)).toContain('3a00010001');
		expect(hex(signed)).toContain('3a00010000');
	});

	it('carries the grant payload verbatim in the unprotected header', async () => {
		const { jwk } = keyMaterial();
		const { privateKey } = await importAuthorityKey(jwk);
		const signed = await signGrantPayload(GRANT_PAYLOAD, privateKey);
		expect(hex(signed)).toContain(hex(GRANT_PAYLOAD));
	});

	it('emits a raw 64-byte r‖s signature, not DER', async () => {
		const { jwk } = keyMaterial();
		const { privateKey } = await importAuthorityKey(jwk);
		const signed = await signGrantPayload(GRANT_PAYLOAD, privateKey);
		// bstr(64) header is 0x58 0x40; a DER signature would be ~70-72 bytes
		// behind a different header.
		expect(hex(signed.subarray(-SIGNATURE_FIELD_BYTES, -64))).toBe('5840');
	});
});

describe('signatures verify across implementations', () => {
	it('WebCrypto verifies a signature the Node implementation produced', async () => {
		const { pem, jwk } = keyMaterial();
		const { publicKey } = await importAuthorityKey(jwk);

		const fromNode = signGrantPayloadWithEs256Pem(GRANT_PAYLOAD, pem);
		const signature = fromNode.subarray(-64);
		const sigStructure = await grantSigStructure(GRANT_PAYLOAD);

		await expect(
			crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, sigStructure)
		).resolves.toBe(true);
	});

	it('WebCrypto verifies its own signature', async () => {
		const { jwk } = keyMaterial();
		const { privateKey, publicKey } = await importAuthorityKey(jwk);

		const signed = await signGrantPayload(GRANT_PAYLOAD, privateKey);
		const sigStructure = await grantSigStructure(GRANT_PAYLOAD);

		await expect(
			crypto.subtle.verify(
				{ name: 'ECDSA', hash: 'SHA-256' },
				publicKey,
				signed.subarray(-64),
				sigStructure
			)
		).resolves.toBe(true);
	});

	it('rejects a signature over a different payload', async () => {
		const { jwk } = keyMaterial();
		const { privateKey, publicKey } = await importAuthorityKey(jwk);

		const signed = await signGrantPayload(GRANT_PAYLOAD, privateKey);
		const otherStructure = await grantSigStructure(new Uint8Array([0x01, 0x02]));

		await expect(
			crypto.subtle.verify(
				{ name: 'ECDSA', hash: 'SHA-256' },
				publicKey,
				signed.subarray(-64),
				otherStructure
			)
		).resolves.toBe(false);
	});

	it('rejects a signature made by a different key', async () => {
		const a = await importAuthorityKey(keyMaterial().jwk);
		const b = await importAuthorityKey(keyMaterial().jwk);

		const signed = await signGrantPayload(GRANT_PAYLOAD, a.privateKey);
		const sigStructure = await grantSigStructure(GRANT_PAYLOAD);

		await expect(
			crypto.subtle.verify(
				{ name: 'ECDSA', hash: 'SHA-256' },
				b.publicKey,
				signed.subarray(-64),
				sigStructure
			)
		).resolves.toBe(false);
	});
});

describe('importAuthorityKey', () => {
	it('derives the 64-byte x‖y that becomes grantData', async () => {
		const { pem, jwk } = keyMaterial();
		const { publicKeyXY } = await importAuthorityKey(jwk);

		expect(publicKeyXY.length).toBe(64);
		// Same coordinates the Node helper would read off the PEM.
		const nodeJwk = createPrivateKey(pem).export({ format: 'jwk' });
		const b64u = (s: string) => {
			const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
			const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
			return [...bin].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
		};
		expect(hex(publicKeyXY)).toBe(b64u(nodeJwk.x!) + b64u(nodeJwk.y!));
	});

	it('imports the private half as NON-extractable', async () => {
		const { privateKey } = await importAuthorityKey(keyMaterial().jwk);
		expect(privateKey.extractable).toBe(false);
		await expect(crypto.subtle.exportKey('jwk', privateKey)).rejects.toThrow();
	});

	it('imports the public half as extractable — delegation-cose exports it to raw', async () => {
		const { publicKey } = await importAuthorityKey(keyMaterial().jwk);
		expect(publicKey.extractable).toBe(true);
		await expect(crypto.subtle.exportKey('raw', publicKey)).resolves.toBeTruthy();
	});

	it.each([
		['not JSON at all', /not valid JSON/],
		['{"kty":"RSA"}', /must be a P-256 EC key/],
		['{"kty":"EC","crv":"P-384"}', /must be a P-256 EC key/],
		['{"kty":"EC","crv":"P-256","x":"a","y":"b"}', /must carry a private scalar/],
		['{"kty":"EC","crv":"P-256","d":"a"}', /must carry both public coordinates/]
	])('rejects %s', async (jwk, pattern) => {
		await expect(importAuthorityKey(jwk)).rejects.toThrow(pattern);
	});
});
