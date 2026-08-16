/**
 * WebCrypto reimplementation of `signGrantPayloadWithEs256Pem` from
 * @forestrie/grant-builder.
 *
 * That module is explicitly Node-only: it uses `createPrivateKey` (which imports
 * SEC1 or PKCS#8 EC PEMs) and `nodeSign(..., { dsaEncoding: "ieee-p1363" })`,
 * neither of which exists in workerd. This produces the identical Custodian
 * transparent-statement profile that arbor univocity verifies:
 *
 *   - COSE Sign1, untagged array of 4
 *   - protected header {1: -7} (ES256), wire 0xa10126
 *   - payload = 32-byte SHA-256 of the grant v0 CBOR
 *   - signature = ECDSA P-256 over SHA-256(CBOR(["Signature1", protected, h'',
 *     payload])), raw IEEE P1363 r‖s (64 bytes)
 *   - unprotected header carries the grant v0 CBOR (-65538) and an 8-byte zero
 *     idtimestamp (-65537)
 *
 * The wire output is byte-identical to the Node version except for the 64
 * signature bytes, which cannot match: ECDSA draws a random `k`, so no two
 * signings agree even on one implementation. `test/sign-grant.test.ts` proves
 * the equivalence the right way — identical framing, and both signatures verify
 * under the same public key.
 *
 * WebCrypto's ECDSA sign already emits raw r‖s, so no DER unwrapping is needed;
 * that is exactly what `dsaEncoding: "ieee-p1363"` asks Node for.
 */
import { appendCborBstr, appendCborText } from '@forestrie/encoding';

/** COSE protected header `{1: -7}` (ES256), canonical wire bytes. */
const ES256_PROTECTED_HEADER = new Uint8Array([0xa1, 0x01, 0x26]);
const IDTIMESTAMP_BYTES = 8;
const ES256_RAW_SIG_BYTES = 64;
// CBOR negative-int keys (major type 1): -65538 and -65537.
const CBOR_KEY_FORESTRIE_GRANT_V0 = [0x3a, 0x00, 0x01, 0x00, 0x01];
const CBOR_KEY_IDTIMESTAMP = [0x3a, 0x00, 0x01, 0x00, 0x00];

const ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ECDSA_SHA256 = { name: 'ECDSA', hash: 'SHA-256' } as const;

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
}

/**
 * The Sig_structure the signature is computed over — exposed so tests (and any
 * future verifier) can check a signature without rebuilding the framing.
 */
export async function grantSigStructure(grantPayloadBytes: Uint8Array): Promise<Uint8Array> {
	const payload = await sha256(grantPayloadBytes);
	const sig: number[] = [0x84]; // array(4)
	appendCborText(sig, 'Signature1');
	appendCborBstr(sig, ES256_PROTECTED_HEADER);
	appendCborBstr(sig, new Uint8Array(0));
	appendCborBstr(sig, payload);
	return new Uint8Array(sig);
}

/**
 * Sign a grant v0 payload, returning the Custodian-profile COSE Sign1 wire
 * bytes.
 *
 * @param grantPayloadBytes canonical grant v0 CBOR (keys 1-6)
 * @param privateKey a non-extractable P-256 signing handle (see {@link importAuthorityKey})
 */
export async function signGrantPayload(
	grantPayloadBytes: Uint8Array,
	privateKey: CryptoKey
): Promise<Uint8Array> {
	const payload = await sha256(grantPayloadBytes);
	const sigStructure = await grantSigStructure(grantPayloadBytes);

	const signature = new Uint8Array(
		await crypto.subtle.sign(ECDSA_SHA256, privateKey, sigStructure as BufferSource)
	);
	if (signature.length !== ES256_RAW_SIG_BYTES)
		throw new Error(
			`ES256 signature must be ${ES256_RAW_SIG_BYTES}-byte raw r‖s; got ${signature.length}`
		);

	const out: number[] = [0x84]; // Sign1 array(4)
	appendCborBstr(out, ES256_PROTECTED_HEADER);
	out.push(0xa2); // unprotected map(2)
	out.push(...CBOR_KEY_FORESTRIE_GRANT_V0);
	appendCborBstr(out, grantPayloadBytes);
	out.push(...CBOR_KEY_IDTIMESTAMP);
	appendCborBstr(out, new Uint8Array(IDTIMESTAMP_BYTES));
	appendCborBstr(out, payload);
	appendCborBstr(out, signature);
	return new Uint8Array(out);
}

export interface AuthorityKeyPair {
	/** Non-extractable — the scalar never leaves WebCrypto after import. */
	privateKey: CryptoKey;
	/** Extractable, because @forestrie/delegation-cose exports it to raw. */
	publicKey: CryptoKey;
	/** 64-byte uncompressed x‖y — the grant `grantData` form. */
	publicKeyXY: Uint8Array;
}

/**
 * Import the authority signing key from a private JWK.
 *
 * JWK rather than PKCS#8 DER on purpose: the delegation path needs an
 * EXTRACTABLE public handle (`@forestrie/delegation-cose` calls
 * `exportKey("raw", publicKey)`), and importing PKCS#8 yields only the private
 * half — recovering the public half would mean re-deriving the point or hand-
 * assembling SPKI. A JWK carries both, and lets the private half be imported
 * non-extractable, which is strictly better custody than the PEM path it
 * replaces.
 *
 * This key is K(L) of BOTH authority logs. Possession is the authority to mint
 * arbitrary writer credentials under the demo's forest.
 */
export async function importAuthorityKey(jwkJson: string): Promise<AuthorityKeyPair> {
	let jwk: JsonWebKey;
	try {
		jwk = JSON.parse(jwkJson) as JsonWebKey;
	} catch {
		throw new Error('AUTHORITY_ES256_JWK is not valid JSON');
	}
	if (jwk.kty !== 'EC' || jwk.crv !== 'P-256')
		throw new Error('AUTHORITY_ES256_JWK must be a P-256 EC key');
	if (typeof jwk.d !== 'string') throw new Error('AUTHORITY_ES256_JWK must carry a private scalar');
	if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string')
		throw new Error('AUTHORITY_ES256_JWK must carry both public coordinates');

	const privateKey = await crypto.subtle.importKey('jwk', jwk, ECDSA_P256, false, ['sign']);
	const { d: _d, ...publicJwk } = jwk;
	const publicKey = await crypto.subtle.importKey('jwk', publicJwk, ECDSA_P256, true, ['verify']);

	const x = base64UrlToBytes(jwk.x);
	const y = base64UrlToBytes(jwk.y);
	if (x.length !== 32 || y.length !== 32)
		throw new Error('AUTHORITY_ES256_JWK coordinates must be 32 bytes each');
	const publicKeyXY = new Uint8Array(64);
	publicKeyXY.set(x, 0);
	publicKeyXY.set(y, 32);

	return { privateKey, publicKey, publicKeyXY };
}

/**
 * The authority key as a `KeyProvider`, which is what
 * `@forestrie/think-scribe/forestrie/delegate` takes.
 *
 * `delegateSealing` only reads `signingKeyPair()`, but the interface asks for
 * the whole surface and every part of it is genuinely available here — so this
 * implements it rather than casting past the type. `rotate` is the one honest
 * exception: rotating the authority key is a provisioning operation (it would
 * invalidate every grant already issued under the old key), so it throws rather
 * than pretending to be supported.
 */
export function authorityKeyProvider(keys: AuthorityKeyPair) {
	return {
		kid: () => keys.publicKeyXY.slice(0, 32),
		publicKeyXY: async () => keys.publicKeyXY,
		sign: async (bytes: Uint8Array) =>
			new Uint8Array(
				await crypto.subtle.sign(ECDSA_SHA256, keys.privateKey, bytes as BufferSource)
			),
		signingKeyPair: async () => ({ privateKey: keys.privateKey, publicKey: keys.publicKey }),
		rotate: async (): Promise<void> => {
			throw new Error(
				'the authority key cannot be rotated in-process — it is provisioned, and rotating it invalidates every grant already issued under it'
			);
		}
	};
}

function base64UrlToBytes(b64url: string): Uint8Array {
	const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
	const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
	const bin = atob(b64 + pad);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}
