import {
	buildUserEnvelopeEs256,
	inputCommitment
} from '@forestrie/think-scribe/forestrie/envelope';
import { bytesToHex } from './utils.ts';
import type { UserRootKey } from './user-root.ts';

/**
 * The claims the user attests to for one turn (plan §7), redacted in Phase D:
 * the user's root key signs a COMMITMENT to the message, never the message.
 * The plaintext goes to the worker in the `POST /turn` body — it has to, the
 * model must read it — and stops there; what reaches the log is this envelope.
 */
export interface EnvelopeClaims {
	/** `H(nonce ‖ input)` — see the canonical `inputCommitment`. */
	inputHash: string;
	sessionId: string;
	issuedAt: string;
	/** Per-turn random nonce — the commitment's salt, and the user's opening. */
	nonce: string;
}

/**
 * The user input envelope, ES256 shape since plan-2608-13 Phase 4a: a COSE
 * Sign1 over the turn claims signed by the browser-held P-256 root (protected
 * {1: ES256, 3: content type, 4: the root's 32-byte x coordinate}) — built by
 * the canonical think-scribe encoder, not a browser mirror, because two
 * implementations of the envelope is two chances to produce receipts that
 * verify nowhere. Registered AS-IS as the user's own leaf in separate mode;
 * the DO verifies it against the pinned root and derives
 * workId = SHA-256(envelope) either way.
 */
export function buildUserEnvelope(claims: EnvelopeClaims, root: UserRootKey): Promise<Uint8Array> {
	return buildUserEnvelopeEs256(claims, {
		publicKeyXY: () => root.publicKeyXY(),
		sign: (bytes) => root.sign(bytes)
	});
}

/** workId = SHA-256(envelope) — the turn's identity everywhere (plan §7). */
export async function workIdOf(envelope: Uint8Array): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', envelope as BufferSource);
	return bytesToHex(new Uint8Array(digest));
}

/**
 * Claims for a new turn. The nonce is minted first and the commitment taken
 * over it with the SAME function the worker verifies with — imported, not
 * mirrored, because two implementations of this hash is two chances to produce
 * a signature that verifies nowhere.
 */
export function newTurnClaims(input: string, sessionId: string): EnvelopeClaims {
	const nonce = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
	return {
		inputHash: inputCommitment(nonce, input),
		sessionId,
		issuedAt: new Date().toISOString(),
		nonce
	};
}
