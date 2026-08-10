import { keccak_256 } from '@noble/hashes/sha3.js';
import { cborEncode } from './cbor.ts';
import { bytesToHex } from './utils.ts';
import type { DemoWallet } from './wallet.svelte.ts';

/** The claims the user attests to for one turn (plan §7). */
export interface EnvelopeClaims {
	input: string;
	sessionId: string;
	issuedAt: string;
	/** Per-turn random nonce — salting is mandatory, the log is public. */
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
	const digest = await crypto.subtle.digest('SHA-256', envelope.buffer as ArrayBuffer);
	return bytesToHex(new Uint8Array(digest));
}

export function newTurnClaims(input: string, sessionId: string): EnvelopeClaims {
	return {
		input,
		sessionId,
		issuedAt: new Date().toISOString(),
		nonce: bytesToHex(crypto.getRandomValues(new Uint8Array(16)))
	};
}
