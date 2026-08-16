/**
 * User input envelope (plan §7, D3): the user attests their input by signing
 * a COSE Sign1 over `{ inputHash, sessionId, issuedAt, nonce }` with their
 * wcc-1 wallet key. `workId = SHA-256(envelope bytes)` names the work unit and
 * is passed as the turn's durable `submissionId`/`idempotencyKey`, so the agent
 * cannot begin work under a different id than it commits to.
 *
 * Phase D redaction: the envelope commits to `inputHash = H(nonce ‖ input)`,
 * never to the input itself. The plaintext travels to the worker (it has to —
 * the model must read it) but never to the lane, so the public log holds a
 * commitment whose opening the user alone keeps. That turns the demo from "a
 * public log with public contents" into selective disclosure: the user can
 * prove what they said, to whoever they choose, with the service switched off.
 *
 * The salt is mandatory. A bare `H(input)` is guessable for short prompts. The
 * nonce is already 16 random bytes inside the claims, so it travels with the
 * envelope and needs no separate custody — the user knows it because it is in
 * the envelope they keep.
 *
 * {@link verifyAttestedInput} is the load-bearing assertion of the whole
 * scheme: it re-derives `H(nonce ‖ input)` from the plaintext the worker was
 * handed and refuses the turn unless it equals the signed `inputHash`. Without
 * it the signature stops binding the text the agent actually runs, and the
 * causal claim collapses while every UI tick still shows green.
 *
 * Wire profile = canopy's KS256 COSE convention (grant/ks256-verify.ts):
 * protected `{1: -65799 (KS256), 3: content type, 4: 20-byte address}`;
 * signature = 65-byte eth-style r‖s‖v (raw recovery v ∈ 0..3) over
 * **keccak-256 of the COSE Sig_structure** — no EIP-191 prefix. Following
 * the canopy profile keeps O4's separate user-endorsed leaf a config flip:
 * this exact envelope is registrable under a KS256 grant (`grantData` = the
 * 20-byte address) in M5.
 *
 * Cut-1 caveat (same class as the wcc-1 deviations in auth.ts): browser
 * wallets only expose prefixed `personal_sign`, not raw keccak signing, so a
 * real-wallet client needs an EIP-191 wrapping variant or ERC-1271 — the
 * demo client holds its key directly and signs the canopy profile.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { cborDecode, cborEncode, type CborMap } from './cbor.ts';
import { saltedCommitmentHex } from '../attestation.ts';

const ALG = 1;
const CONTENT_TYPE = 3;
const KID = 4;
export const COSE_ALG_KS256 = -65799;

/**
 * Maximum user input, in UTF-8 bytes. Matches the demo's per-entry retention
 * budget, and is the only bound on the cost of one turn — see the check in
 * {@link verifyAttestedInput}.
 */
export const MAX_INPUT_BYTES = 4096;

/** Commitment domain for the user's input (salted by the envelope nonce). */
export const INPUT_COMMITMENT_DOMAIN = 'thinker/input/v1';

/**
 * The value the wallet signs in place of the input: `H(nonce ‖ input)`.
 *
 * The one and only definition — the browser mirror imports THIS function
 * rather than re-implementing it, because a redaction scheme with two
 * implementations of its commitment is a redaction scheme with a drift bug
 * waiting to produce receipts that verify nowhere.
 */
export function inputCommitment(nonce: string, input: string): string {
	return saltedCommitmentHex(INPUT_COMMITMENT_DOMAIN, nonce, input);
}

/** The signed claims inside the envelope payload (canonical JSON). */
export interface EnvelopeClaims {
	/** {@link inputCommitment} of the input — the plaintext is NOT in here. */
	inputHash: string;
	sessionId: string;
	issuedAt: string; // ISO 8601
	nonce: string; // client random, per-envelope — the commitment's salt
}

export interface VerifiedEnvelope {
	claims: EnvelopeClaims;
	/** Recovered signer, lowercase 0x hex — must match the wcc-1 principal. */
	address: string;
	/** SHA-256 of the envelope bytes, hex — the work unit id. */
	workId: string;
}

export class EnvelopeError extends Error {}

function sigStructure(protectedBytes: Uint8Array, payload: Uint8Array): Uint8Array {
	return cborEncode(['Signature1', protectedBytes, new Uint8Array(0), payload]);
}

/**
 * Build an envelope (client side — the smoke/demo client; a browser client
 * would do the same with its own key custody). `privateKey` is the 32-byte
 * secp256k1 wallet key.
 */
export function buildUserEnvelope(claims: EnvelopeClaims, privateKey: Uint8Array): Uint8Array {
	const pub = secp256k1.getPublicKey(privateKey, false);
	const address = keccak_256(pub.slice(1)).slice(-20);
	const payload = new TextEncoder().encode(JSON.stringify(claims));

	const protectedMap: CborMap = new Map();
	protectedMap.set(ALG, COSE_ALG_KS256);
	protectedMap.set(CONTENT_TYPE, 'application/json');
	protectedMap.set(KID, address);
	const protectedBytes = cborEncode(protectedMap);

	const hash = keccak_256(sigStructure(protectedBytes, payload));
	// noble "recovered" layout is recovery-byte-FIRST; canopy expects r‖s‖v.
	const recovered = secp256k1.sign(hash, privateKey, {
		format: 'recovered',
		prehash: false
	});
	const signature = new Uint8Array(65);
	signature.set(recovered.slice(1), 0);
	signature[64] = recovered[0]!; // raw recovery 0..3 (not +27)

	return cborEncode([protectedBytes, new Map(), payload, signature]);
}

/**
 * Verify an envelope and recover its signer (agent side, at turn admission).
 * Structural checks + KS256 recovery; binding the address to the bound
 * principal is the caller's job.
 */
export async function verifyUserEnvelope(envelope: Uint8Array): Promise<VerifiedEnvelope> {
	let decoded;
	try {
		decoded = cborDecode(envelope);
	} catch (err) {
		throw new EnvelopeError(`envelope is not decodable CBOR: ${err}`);
	}
	if (!Array.isArray(decoded) || decoded.length !== 4)
		throw new EnvelopeError('envelope is not a COSE Sign1 4-array');
	const [protectedBytes, , payload, signature] = decoded;
	if (!(protectedBytes instanceof Uint8Array) || !(payload instanceof Uint8Array))
		throw new EnvelopeError('envelope protected/payload must be byte strings');
	if (!(signature instanceof Uint8Array) || signature.length !== 65)
		throw new EnvelopeError('envelope signature must be 65 bytes r‖s‖v');

	const header = cborDecode(protectedBytes);
	if (!(header instanceof Map) || header.get(ALG) !== COSE_ALG_KS256)
		throw new EnvelopeError('envelope alg must be KS256 (-65799)');
	const kid = header.get(KID);
	if (!(kid instanceof Uint8Array) || kid.length !== 20)
		throw new EnvelopeError('envelope kid must be the 20-byte signer address');

	const hash = keccak_256(sigStructure(protectedBytes, payload));
	const v = signature[64]!;
	if (v > 3) throw new EnvelopeError('envelope signature v must be raw 0..3');
	let recoveredAddress: Uint8Array;
	try {
		const sig = secp256k1.Signature.fromBytes(signature.slice(0, 64), 'compact').addRecoveryBit(v);
		const pub = sig.recoverPublicKey(hash).toBytes(false);
		recoveredAddress = keccak_256(pub.slice(1)).slice(-20);
	} catch (err) {
		throw new EnvelopeError(`envelope signature recovery failed: ${err}`);
	}
	if (recoveredAddress.length !== 20 || !kid.every((b, i) => b === recoveredAddress[i]))
		throw new EnvelopeError('envelope kid does not match recovered signer');

	let claims: EnvelopeClaims;
	try {
		claims = JSON.parse(new TextDecoder().decode(payload)) as EnvelopeClaims;
	} catch {
		throw new EnvelopeError('envelope payload is not JSON');
	}
	if (
		typeof claims.inputHash !== 'string' ||
		typeof claims.sessionId !== 'string' ||
		typeof claims.issuedAt !== 'string' ||
		typeof claims.nonce !== 'string'
	)
		throw new EnvelopeError('envelope claims must be {inputHash, sessionId, issuedAt, nonce}');
	if (!/^[0-9a-f]{64}$/.test(claims.inputHash))
		throw new EnvelopeError('envelope inputHash must be 64 lowercase hex chars');

	// Hash the VIEW, not `envelope.buffer` — .buffer is the whole backing store,
	// so any Uint8Array with a non-zero byteOffset (or shorter than its buffer)
	// would hash the wrong bytes. Currently every caller passes an owned buffer,
	// which is what masked it.
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', envelope as BufferSource));
	let workId = '';
	for (const b of digest) workId += b.toString(16).padStart(2, '0');
	let address = '0x';
	for (const b of recoveredAddress) address += b.toString(16).padStart(2, '0');

	return { claims, address, workId };
}

/**
 * Turn admission's one non-negotiable check (Phase D1): the plaintext handed
 * to the worker is the plaintext the wallet signed a commitment to.
 *
 * ‼️ Every path that feeds the model MUST come through here, not through
 * {@link verifyUserEnvelope}. The envelope alone proves "this wallet asked for
 * *something*"; only `H(nonce ‖ input) === claims.inputHash` proves it asked
 * for THIS. Verify the envelope and skip this, and the receipts still verify,
 * the ticks still go green, and the statement no longer says anything true
 * about what the agent ran.
 *
 * The size bound is checked FIRST — before any signature recovery or hashing —
 * because it is what actually caps the cost of a turn: nothing downstream
 * limits prompt length, transcript growth or output length, so an unbounded
 * input is an unbounded bill. Measured in UTF-8 bytes, not JS characters, so
 * an emoji-heavy prompt cannot smuggle 4x past a length check.
 */
export async function verifyAttestedInput(
	envelope: Uint8Array,
	input: string
): Promise<VerifiedEnvelope & { input: string }> {
	if (typeof input !== 'string') throw new EnvelopeError('turn input must be a string');
	if (new TextEncoder().encode(input).length > MAX_INPUT_BYTES)
		throw new EnvelopeError(`turn input exceeds ${MAX_INPUT_BYTES} bytes`);
	const verified = await verifyUserEnvelope(envelope);
	if (inputCommitment(verified.claims.nonce, input) !== verified.claims.inputHash)
		throw new EnvelopeError(
			'submitted input does not open the envelope commitment H(nonce ‖ input)'
		);
	return { ...verified, input };
}
