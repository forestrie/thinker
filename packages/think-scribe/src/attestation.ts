/**
 * The agent's per-turn work statement (plan §7, O3/O4): one statement per
 * turn, naming the user's work unit (`workId = H(envelope)`) plus the agent's
 * own choices and a salted hash of its output. Only this payload's HASH is
 * committed to the public log ("pipe not store"), but the payload itself is
 * what auditors eventually read, so it must be self-contained and salted.
 *
 * Salting is mandatory: the log is public and `H(text)` is guessable for short
 * texts — every statement carries a per-statement random salt (§7), and every
 * text commitment in the system is taken over that salt (Phase D).
 *
 * Phase D redaction: the statement no longer embeds `userEnvelopeB64`. That
 * costs zero verification strength — `workId ≡ SHA-256(envelope)` and the
 * statement names the workId, so the two surviving conjuncts already prove the
 * statement names exactly those bytes — and it removes the second of the two
 * routes by which the user's plaintext used to reach the lane.
 */
import { sha256 } from '@noble/hashes/sha2.js';

/**
 * A salted, domain-separated commitment to a text, as lowercase hex:
 *
 *     H( "<domain>:<salt byte length>:" ‖ salt ‖ text )
 *
 * The length prefix is not decoration. Without it `(salt "ab", text "cd")` and
 * `(salt "abc", text "d")` commit to the same digest, which would let the
 * holder of an opening equivocate about what they committed to — precisely the
 * property the commitment exists to deny. The domain keeps input and output
 * commitments in separate spaces so an opening for one can never be replayed
 * as an opening for the other.
 */
export function saltedCommitmentHex(domain: string, salt: string, text: string): string {
	const encoder = new TextEncoder();
	const saltBytes = encoder.encode(salt);
	const textBytes = encoder.encode(text);
	const header = encoder.encode(`${domain}:${saltBytes.length}:`);
	const preimage = new Uint8Array(header.length + saltBytes.length + textBytes.length);
	preimage.set(header, 0);
	preimage.set(saltBytes, header.length);
	preimage.set(textBytes, header.length + saltBytes.length);
	let out = '';
	for (const b of sha256(preimage)) out += b.toString(16).padStart(2, '0');
	return out;
}

/** Commitment domain for the agent's output text (salted by the statement salt). */
export const OUTPUT_COMMITMENT_DOMAIN = 'thinker/output/v1';

/**
 * The committed `outputHash`: `H(salt ‖ outputText)` under the statement's own
 * salt. A bare `sha256(outputText)` — what this was before Phase D — is
 * brute-forceable for short replies, the same weakness the input side fixes
 * with the envelope nonce.
 */
export function outputCommitment(salt: string, outputText: string): string {
	return saltedCommitmentHex(OUTPUT_COMMITMENT_DOMAIN, salt, outputText);
}

/** A fresh 32-byte statement salt, hex. */
export function newSaltHex(): string {
	let out = '';
	for (const b of crypto.getRandomValues(new Uint8Array(32)))
		out += b.toString(16).padStart(2, '0');
	return out;
}

/** One step's committed choices — a bounded projection of the AI-SDK step. */
export interface CommittedStep {
	stepNumber: number;
	finishReason: string;
	/** Tool name + hashed args/results; full IO stays in the DO transcript. */
	toolCalls: Array<{ toolName: string; argsHash: string }>;
	toolResults: Array<{ toolName: string; resultHash: string }>;
}

export interface WorkStatementInput {
	/** SHA-256 of the user envelope — the work unit id (causal binding). */
	workId: string;
	/** Per-step agent choices for the turn. */
	steps: CommittedStep[];
	/**
	 * The statement's random salt, hex — carried in the payload AND the salt
	 * `outputHash` is taken over, so it is assembled with the hash rather than
	 * minted here.
	 */
	salt: string;
	/** {@link outputCommitment} of the assistant's persisted output text. */
	outputHash: string;
	/**
	 * Persisted assistant message id — the leaf in Think's non-destructive
	 * message tree (branch-path refinement and post-compaction effective
	 * context are deferred, O3).
	 */
	leafId: string;
	/** Turn requestId (Think) — operational correlation, not attestation. */
	requestId: string;
}

/** Version tag for the work-statement payload schema. */
export const WORK_STATEMENT_TYPE = 'thinker/work-statement/v1';

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
	let out = '';
	for (const b of digest) out += b.toString(16).padStart(2, '0');
	return out;
}

/**
 * Build the work-statement payload (JSON bytes; the COSE payload).
 *
 * No plaintext, by construction: the user's words appear only as the workId
 * (`H(envelope)`, and the envelope itself now carries only `H(nonce ‖ input)`),
 * and the agent's words only as the salted `outputHash`.
 */
export function buildWorkStatementPayload(input: WorkStatementInput): Uint8Array {
	return new TextEncoder().encode(
		JSON.stringify({
			type: WORK_STATEMENT_TYPE,
			workId: input.workId,
			agentChoices: input.steps,
			outputHash: input.outputHash,
			leafId: input.leafId,
			requestId: input.requestId,
			salt: input.salt
		})
	);
}
