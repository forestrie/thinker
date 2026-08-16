/**
 * The agent's per-turn work statement (plan §7, O3/O4): one statement per
 * turn, embedding the user's signed input envelope (O4 embed default — the
 * separate user-endorsed leaf is the M5 flip) plus the agent's own choices
 * and a hash of its output. Only this payload's HASH is committed to the
 * public log ("pipe not store"), but the payload itself is what auditors
 * eventually read, so it must be self-contained and salted.
 *
 * Salting is mandatory: the log is public and `H(input)` is guessable —
 * every statement carries a per-statement random nonce (§7).
 */

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
	/** The user's signed input envelope, base64 (embedded whole — O4). */
	userEnvelopeB64: string;
	/** Per-step agent choices for the turn. */
	steps: CommittedStep[];
	/** SHA-256 hex of the assistant's persisted output text. */
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

/** Build the work-statement payload (JSON bytes; the COSE payload). */
export function buildWorkStatementPayload(input: WorkStatementInput): Uint8Array {
	const salt = crypto.getRandomValues(new Uint8Array(32));
	let saltHex = '';
	for (const b of salt) saltHex += b.toString(16).padStart(2, '0');
	return new TextEncoder().encode(
		JSON.stringify({
			type: WORK_STATEMENT_TYPE,
			workId: input.workId,
			userEnvelope: input.userEnvelopeB64,
			agentChoices: input.steps,
			outputHash: input.outputHash,
			leafId: input.leafId,
			requestId: input.requestId,
			salt: saltHex
		})
	);
}
