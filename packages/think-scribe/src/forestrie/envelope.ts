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
 *
 * Since plan-2608-13 Phase 4a there is a second profile: the ES256 envelope
 * (see {@link buildUserEnvelopeEs256}) for user logs rooted in a browser-held
 * WebCrypto P-256 key rather than the wallet — the custody shape the WebAuthn
 * ceremony (Phase 4.1+) builds on. The KS256 profile stays for wallet-rooted
 * logs and the smoke harnesses.
 *
 * Under passkey custody (ADR-0065, plan-2608-14) the ES256 envelope is signed
 * by the endorsed SESSION key and carries the passkey's v2 session-key
 * endorsement in its UNPROTECTED header at label -65801
 * ({@link COSE_LABEL_SESSION_KEY_ENDORSEMENT}) — attached by the browser
 * BEFORE signing, so the registered leaf is self-describing: canopy
 * admission and any offline auditor resolve the signer from the leaf's own
 * bytes, and nothing verifies a session-signed leaf under the root.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { COSE_LABEL_SESSION_KEY_ENDORSEMENT } from '@forestrie/encoding';
import { cborDecode, cborEncode, type CborMap } from './cbor.ts';
import { saltedCommitmentHex } from '../attestation.ts';

const ALG = 1;
const CONTENT_TYPE = 3;
const KID = 4;
export const COSE_ALG_KS256 = -65799;
export const COSE_ALG_ES256 = -7;
export { COSE_LABEL_SESSION_KEY_ENDORSEMENT };

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

/**
 * ES256 variant (plan-2608-13 Phase 4a, Q4 option A): the user's log root is
 * a non-extractable WebCrypto P-256 key rather than the wallet, so the same
 * claims are signed on canopy's ES256 profile: protected
 * `{1: -7, 3: content type, 4: 32-byte x}` (kid = the x coordinate — the
 * first 32 bytes of the 64-byte grantData x‖y, ARC-0019 §6), signature =
 * 64-byte IEEE P1363 r‖s over SHA-256 of the Sig_structure. This exact
 * envelope registers under an ES256 `grant_user` whose `grantData` is the
 * root's x‖y. Verification cannot recover the signer (no ECDSA recovery on
 * the plain profile), so the verifier takes the trusted root key and checks
 * kid + signature against it — the binding to the wcc-1 principal is the
 * DO's pinned-root check, not an address recovery.
 */
export interface Es256EnvelopeSigner {
	/** 64-byte P-256 public key, x‖y — the log root / grantData. */
	publicKeyXY(): Promise<Uint8Array>;
	/** ECDSA P-256/SHA-256 over bytes → 64-byte IEEE P1363 r‖s. */
	sign(bytes: Uint8Array): Promise<Uint8Array>;
}

export interface VerifiedEnvelopeEs256 {
	claims: EnvelopeClaims;
	/** The envelope kid — the root key's x coordinate, lowercase hex. */
	kidHex: string;
	/** SHA-256 of the envelope bytes, hex — the work unit id. */
	workId: string;
}

export class EnvelopeError extends Error {}

function sigStructure(protectedBytes: Uint8Array, payload: Uint8Array): Uint8Array {
	return cborEncode(['Signature1', protectedBytes, new Uint8Array(0), payload]);
}

const hexOf = (bytes: Uint8Array): string => {
	let out = '';
	for (const b of bytes) out += b.toString(16).padStart(2, '0');
	return out;
};

/** Hash the VIEW (see the note in {@link verifyUserEnvelope}). */
async function workIdOf(envelope: Uint8Array): Promise<string> {
	return hexOf(new Uint8Array(await crypto.subtle.digest('SHA-256', envelope as BufferSource)));
}

function parseClaims(payload: Uint8Array): EnvelopeClaims {
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
	return claims;
}

/**
 * Peek an envelope's protected alg without verifying anything — the admission
 * dispatch (KS256 wallet root vs ES256 WebCrypto/passkey root) branches on
 * this before the alg-specific verifier runs.
 */
export function userEnvelopeAlg(envelope: Uint8Array): number {
	let decoded;
	try {
		decoded = cborDecode(envelope);
	} catch (err) {
		throw new EnvelopeError(`envelope is not decodable CBOR: ${err}`);
	}
	if (!Array.isArray(decoded) || decoded.length !== 4)
		throw new EnvelopeError('envelope is not a COSE Sign1 4-array');
	if (!(decoded[0] instanceof Uint8Array))
		throw new EnvelopeError('envelope protected header must be a byte string');
	const header = cborDecode(decoded[0]);
	const alg = header instanceof Map ? header.get(ALG) : undefined;
	if (typeof alg !== 'number') throw new EnvelopeError('envelope protected header has no alg');
	return alg;
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

	const claims = parseClaims(payload);

	// Hash the VIEW, not `envelope.buffer` — .buffer is the whole backing store,
	// so any Uint8Array with a non-zero byteOffset (or shorter than its buffer)
	// would hash the wrong bytes. Currently every caller passes an owned buffer,
	// which is what masked it.
	const workId = await workIdOf(envelope);
	return { claims, address: `0x${hexOf(recoveredAddress)}`, workId };
}

export interface BuildUserEnvelopeEs256Options {
	/**
	 * Passkey custody (ADR-0065 §2): the v2 session-key endorsement bytes to
	 * carry at unprotected label -65801. `signer` is then the endorsed SESSION
	 * key. Omit under 4a custody (the signer IS the root) — nothing is
	 * attached, and canopy binds the leaf to `grantData` as before.
	 */
	endorsement?: Uint8Array;
}

/**
 * Build an ES256 envelope with the user's P-256 key (Phase 4a), optionally
 * carrying the session-key endorsement (ADR-0065). The unprotected header is
 * outside the Sig_structure, so the endorsement does not change what the
 * session key signs — but it is committed by the leaf's content hash once
 * registered, so it cannot be swapped after the fact either (§5).
 */
export async function buildUserEnvelopeEs256(
	claims: EnvelopeClaims,
	signer: Es256EnvelopeSigner,
	opts?: BuildUserEnvelopeEs256Options
): Promise<Uint8Array> {
	const publicKeyXY = await signer.publicKeyXY();
	if (publicKeyXY.length !== 64) throw new EnvelopeError('root public key must be 64 bytes x‖y');
	const payload = new TextEncoder().encode(JSON.stringify(claims));

	const protectedMap: CborMap = new Map();
	protectedMap.set(ALG, COSE_ALG_ES256);
	protectedMap.set(CONTENT_TYPE, 'application/json');
	protectedMap.set(KID, publicKeyXY.slice(0, 32));
	const protectedBytes = cborEncode(protectedMap);

	const unprotected: CborMap = new Map();
	if (opts?.endorsement !== undefined) {
		if (!(opts.endorsement instanceof Uint8Array) || opts.endorsement.length === 0)
			throw new EnvelopeError('session-key endorsement must be a non-empty byte string');
		unprotected.set(COSE_LABEL_SESSION_KEY_ENDORSEMENT, opts.endorsement);
	}

	const signature = await signer.sign(sigStructure(protectedBytes, payload));
	if (signature.length !== 64)
		throw new EnvelopeError('ES256 signature must be 64 bytes P1363 r‖s');
	return cborEncode([protectedBytes, unprotected, payload, signature]);
}

/**
 * The session-key endorsement an envelope carries at unprotected -65801, or
 * null when absent. Throws {@link EnvelopeError} on an entry that is present
 * but not a byte string — present-but-unusable is never "absent" (ADR-0065
 * §4: no fallback to the root binding).
 */
export function envelopeEndorsement(envelope: Uint8Array): Uint8Array | null {
	let decoded;
	try {
		decoded = cborDecode(envelope);
	} catch (err) {
		throw new EnvelopeError(`envelope is not decodable CBOR: ${err}`);
	}
	if (!Array.isArray(decoded) || decoded.length !== 4)
		throw new EnvelopeError('envelope is not a COSE Sign1 4-array');
	const unprotected = decoded[1];
	if (!(unprotected instanceof Map)) return null;
	const entry = unprotected.get(COSE_LABEL_SESSION_KEY_ENDORSEMENT);
	if (entry === undefined) return null;
	if (!(entry instanceof Uint8Array) || entry.length === 0)
		throw new EnvelopeError('session-key endorsement (-65801) must be a non-empty byte string');
	return entry;
}

/**
 * Verify an ES256 envelope against the TRUSTED root key (agent side, at turn
 * admission — `rootPublicKeyXY` is the pinned root, never taken from the
 * envelope). Checks structure, kid = the root's x coordinate, and the
 * WebCrypto P-256 signature.
 */
export async function verifyUserEnvelopeEs256(
	envelope: Uint8Array,
	rootPublicKeyXY: Uint8Array
): Promise<VerifiedEnvelopeEs256> {
	if (rootPublicKeyXY.length !== 64)
		throw new EnvelopeError('root public key must be 64 bytes x‖y');
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
	if (!(signature instanceof Uint8Array) || signature.length !== 64)
		throw new EnvelopeError('envelope signature must be 64 bytes P1363 r‖s');

	const header = cborDecode(protectedBytes);
	if (!(header instanceof Map) || header.get(ALG) !== COSE_ALG_ES256)
		throw new EnvelopeError('envelope alg must be ES256 (-7)');
	const kid = header.get(KID);
	if (!(kid instanceof Uint8Array) || kid.length !== 32)
		throw new EnvelopeError("envelope kid must be the root key's 32-byte x coordinate");
	const rootX = rootPublicKeyXY.slice(0, 32);
	if (!kid.every((b, i) => b === rootX[i]))
		throw new EnvelopeError('envelope kid does not match the trusted root key');

	const point = new Uint8Array(65);
	point[0] = 0x04;
	point.set(rootPublicKeyXY, 1);
	const key = await crypto.subtle.importKey(
		'raw',
		point as BufferSource,
		{ name: 'ECDSA', namedCurve: 'P-256' },
		false,
		['verify']
	);
	const sigOk = await crypto.subtle.verify(
		{ name: 'ECDSA', hash: 'SHA-256' },
		key,
		signature as BufferSource,
		sigStructure(protectedBytes, payload) as BufferSource
	);
	if (!sigOk)
		throw new EnvelopeError('envelope signature does not verify under the trusted root key');

	const claims = parseClaims(payload);
	return { claims, kidHex: hexOf(kid), workId: await workIdOf(envelope) };
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
	checkInputBounds(input);
	const verified = await verifyUserEnvelope(envelope);
	checkCommitmentOpens(verified.claims, input);
	return { ...verified, input };
}

/**
 * ES256 counterpart of {@link verifyAttestedInput} (Phase 4a): identical
 * bounds + commitment checks, envelope verified against the PINNED root key.
 * Same non-negotiable rule — every path that feeds the model must come
 * through here, never through {@link verifyUserEnvelopeEs256} alone.
 */
export async function verifyAttestedInputEs256(
	envelope: Uint8Array,
	input: string,
	rootPublicKeyXY: Uint8Array
): Promise<VerifiedEnvelopeEs256 & { input: string }> {
	checkInputBounds(input);
	const verified = await verifyUserEnvelopeEs256(envelope, rootPublicKeyXY);
	checkCommitmentOpens(verified.claims, input);
	return { ...verified, input };
}

function checkInputBounds(input: string): void {
	if (typeof input !== 'string') throw new EnvelopeError('turn input must be a string');
	if (new TextEncoder().encode(input).length > MAX_INPUT_BYTES)
		throw new EnvelopeError(`turn input exceeds ${MAX_INPUT_BYTES} bytes`);
}

function checkCommitmentOpens(claims: EnvelopeClaims, input: string): void {
	if (inputCommitment(claims.nonce, input) !== claims.inputHash)
		throw new EnvelopeError(
			'submitted input does not open the envelope commitment H(nonce ‖ input)'
		);
}
