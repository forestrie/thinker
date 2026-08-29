/**
 * Synthetic passkey + v2 session-key endorsement material for the ADR-0065
 * tests: a P-256 "authenticator" whose assertion signs
 * `authenticatorData ‖ sha256(clientDataJSON)` with the challenge bound to
 * the endorsement's Sig_structure — the same construction as canopy's
 * receipt-verify `endorsed-leaf-fixture` and this package's
 * delegate-webauthn test, so what verifies here verifies at admission.
 */
import { base64UrlEncode } from '@forestrie/encoding';
import { normalizeEs256SignatureLowS } from '@forestrie/delegation-cose';
import {
	assembleSessionKeyEndorsement,
	buildSessionKeyEndorsementTbs,
	type SessionKeyEndorsementTbs
} from '@forestrie/receipt-verify';
import type { Es256EnvelopeSigner } from '../../src/forestrie/envelope.ts';

export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;

/** A fixed 7-day window (unix ms) and an instant inside it. */
export const WINDOW = { notBefore: 1_790_000_000_000, notAfter: 1_790_604_800_000 };
export const INSIDE_MS = 1_790_300_000_000;

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
}

export async function generateP256(): Promise<CryptoKeyPair> {
	return (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
		'sign',
		'verify'
	])) as CryptoKeyPair;
}

export async function exportXy(publicKey: CryptoKey): Promise<Uint8Array> {
	const raw = new Uint8Array((await crypto.subtle.exportKey('raw', publicKey)) as ArrayBuffer);
	return raw.slice(1, 65);
}

/** The per-turn signer seam over a WebCrypto pair (what UserRootKey is in the browser). */
export async function es256Signer(
	pair: CryptoKeyPair
): Promise<Es256EnvelopeSigner & { xy: Uint8Array }> {
	const xy = await exportXy(pair.publicKey);
	return {
		xy,
		publicKeyXY: () => Promise.resolve(xy),
		sign: async (bytes) =>
			new Uint8Array(
				await crypto.subtle.sign(
					{ name: 'ECDSA', hash: 'SHA-256' },
					pair.privateKey,
					bytes as BufferSource
				)
			)
	};
}

/** Synthetic passkey gesture over an endorsement TBS. */
export async function synthesizeAssertion(
	root: CryptoKeyPair,
	sigStructureBytes: Uint8Array,
	opts?: { flags?: number }
): Promise<{ authenticatorData: Uint8Array; clientDataJSON: Uint8Array; signature: Uint8Array }> {
	const challenge = base64UrlEncode(await sha256(sigStructureBytes));
	const clientDataJSON = new TextEncoder().encode(
		`{"type":"webauthn.get","challenge":"${challenge}","origin":"https://thinker.example","crossOrigin":false}`
	);
	const authenticatorData = new Uint8Array(37);
	authenticatorData.fill(0xa1, 0, 32);
	authenticatorData[32] = opts?.flags ?? FLAG_UP | FLAG_UV;
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
}

/** `root` endorses `sessionPublicKeyXY` for `window` (ADR-0065 §3 v2). */
export async function buildEndorsement(
	root: CryptoKeyPair,
	sessionPublicKeyXY: Uint8Array,
	window: { notBefore: number; notAfter: number } = WINDOW,
	opts?: { flags?: number; tbsOverride?: SessionKeyEndorsementTbs }
): Promise<Uint8Array> {
	const rootXy = await exportXy(root.publicKey);
	const tbs =
		opts?.tbsOverride ??
		buildSessionKeyEndorsementTbs({
			rootPublicKeyX: rootXy.slice(0, 32),
			sessionPublicKeyXY,
			...window
		});
	const assertion = await synthesizeAssertion(root, tbs.sigStructureBytes, { flags: opts?.flags });
	return assembleSessionKeyEndorsement({ tbs, ...assertion });
}

export interface PasskeyCustody {
	root: CryptoKeyPair;
	rootXy: Uint8Array;
	session: CryptoKeyPair;
	sessionSigner: Es256EnvelopeSigner & { xy: Uint8Array };
	endorsement: Uint8Array;
}

/** A passkey root, an endorsed session key, and the v2 endorsement between them. */
export async function passkeyCustody(opts?: {
	window?: { notBefore: number; notAfter: number };
	flags?: number;
}): Promise<PasskeyCustody> {
	const root = await generateP256();
	const session = await generateP256();
	const sessionSigner = await es256Signer(session);
	const endorsement = await buildEndorsement(root, sessionSigner.xy, opts?.window, {
		flags: opts?.flags
	});
	return { root, rootXy: await exportXy(root.publicKey), session, sessionSigner, endorsement };
}
