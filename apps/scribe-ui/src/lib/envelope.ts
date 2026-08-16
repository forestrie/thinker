import { keccak_256 } from '@noble/hashes/sha3.js';
import { inputCommitment } from '@forestrie/think-scribe/forestrie/envelope';
import { cborEncode } from './cbor.ts';
import { bytesToHex } from './utils.ts';
import type { DemoWallet } from './wallet.svelte.ts';

/**
 * The claims the user attests to for one turn (plan §7), redacted in Phase D:
 * the wallet signs a COMMITMENT to the message, never the message. The
 * plaintext goes to the worker in the `POST /turn` body — it has to, the model
 * must read it — and stops there; what reaches the log is this envelope.
 */
export interface EnvelopeClaims {
	/** `H(nonce ‖ input)` — see the canonical `inputCommitment`. */
	inputHash: string;
	sessionId: string;
	issuedAt: string;
	/** Per-turn random nonce — the commitment's salt, and the user's opening. */
	nonce: string;
}

const KS256_ALG = -65799;

/**
 * The user input envelope: a KS256 COSE Sign1 over the turn claims in the
 * canopy profile — protected {1: KS256, 3: content type, 4: the signer's
 * 20-byte address}, keccak over Sig_structure, 65-byte r‖s‖recovery
 * signature. Registered AS-IS as the user's own leaf in separate mode; the
 * DO verifies it and derives workId = SHA-256(envelope) either way.
 */
export function buildUserEnvelope(claims: EnvelopeClaims, wallet: DemoWallet): Uint8Array {
	const payload = new TextEncoder().encode(JSON.stringify(claims));
	const protectedMap = new Map<number, number | string | Uint8Array>([
		[1, KS256_ALG],
		[3, 'application/json'],
		[4, wallet.addressBytes()]
	]);
	const protectedBytes = cborEncode(protectedMap);
	const sigStructure = cborEncode(['Signature1', protectedBytes, new Uint8Array(0), payload]);
	const signature = wallet.signDigestKs256(keccak_256(sigStructure));
	return cborEncode([protectedBytes, new Map(), payload, signature]);
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
