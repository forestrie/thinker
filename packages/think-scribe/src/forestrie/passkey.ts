/**
 * Passkey onboarding helpers (plan-2608-13 Phase 4.1, devdocs ADR-0064).
 *
 * The passkey is the user LOG ROOT and signs ceremonies only; the 4a
 * non-extractable WebCrypto pair is demoted to a SESSION KEY that keeps
 * signing the plain-ES256 per-turn envelopes, endorsed once by the passkey
 * in the ADR-0063 envelope. The endorsement's byte-exact shape is owned by
 * `@forestrie/receipt-verify` (the same module every offline verifier
 * uses); this subpath re-exports it browser-safe for the UI — importing
 * the think-scribe package index drags workers-types into svelte-check
 * (the 4a `KeyProvider` lesson), so the UI imports from here.
 */

export {
	assembleSessionKeyEndorsement,
	buildSessionKeyEndorsementTbs,
	checkEndorsementWindow,
	DEFAULT_ENDORSEMENT_WINDOW_MS,
	extractLeafEndorsement,
	SESSION_KEY_ENDORSEMENT_CONTENT_TYPE,
	verifySessionKeyEndorsement
} from '@forestrie/receipt-verify';
export type {
	EndorsementWindow,
	SessionKeyEndorsementTbs,
	SessionKeyEndorsementVerifyResult,
	VerifySessionKeyEndorsementOptions
} from '@forestrie/receipt-verify';
export { derSignatureToP1363, normalizeEs256SignatureLowS } from '@forestrie/delegation-cose';

import { derSignatureToP1363, normalizeEs256SignatureLowS } from '@forestrie/delegation-cose';

/**
 * A WebAuthn assertion signature is ASN.1 DER and possibly high-s; the
 * endorsement wire form is 64-byte P1363 r‖s, low-s (ADR-0063 §2). One hop
 * for the `navigator.credentials.get` response.
 */
export function webauthnSignatureToP1363LowS(der: Uint8Array): Uint8Array {
	return normalizeEs256SignatureLowS(derSignatureToP1363(der));
}

/**
 * Extract the 64-byte x‖y from a credential-creation response's SPKI public
 * key (`AuthenticatorAttestationResponse.getPublicKey()`), which spares us
 * parsing the attestationObject CBOR. Returns null when the key is not an
 * uncompressed P-256 point (e.g. the authenticator negotiated a non-ES256
 * algorithm) — callers fall back to the 4a session-root shape.
 */
export async function spkiToPublicKeyXY(spki: Uint8Array): Promise<Uint8Array | null> {
	let key: CryptoKey;
	try {
		key = await crypto.subtle.importKey(
			'spki',
			spki as BufferSource,
			{ name: 'ECDSA', namedCurve: 'P-256' },
			true,
			['verify']
		);
	} catch {
		return null;
	}
	const raw = new Uint8Array((await crypto.subtle.exportKey('raw', key)) as ArrayBuffer);
	if (raw.length !== 65 || raw[0] !== 0x04) return null;
	return raw.slice(1);
}
