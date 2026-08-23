import { env } from '$env/dynamic/public';

/**
 * HTTP surface of the scribe-worker as the UI consumes it. In dev the vite
 * proxy makes everything same-origin; a deployed UI on another hostname
 * sets PUBLIC_SCRIBE_BASE to the worker origin.
 */
export function scribeBase(): string {
	return env.PUBLIC_SCRIBE_BASE ?? '';
}

export function agentPath(sub: string): string {
	return `${scribeBase()}/agents/scribe/user-${sub}`;
}

// --- wire types, mirrored from the worker (scribe.ts / auth.ts) ------------

export interface ChallengeResponse {
	challenge: string;
	message: string;
	expiresAt: string;
}

export interface SessionResponse {
	token: string;
	sub: string;
	exp: number;
}

/** One daily-cap counter: turns used against a ceiling. */
export interface DemoTurnStatus {
	used: number;
	cap: number;
}

/** Daily demo-turn counters: per-user (fairness) + global (the real spend bound). */
export interface DemoTurnCounters {
	/** UTC day the counters reset on (YYYY-MM-DD). */
	date: string;
	user: DemoTurnStatus;
	global: DemoTurnStatus;
}

export interface IdentityResponse {
	principal: string;
	alg: 'ES256';
	keyProvider: 'do-resident' | 'kms-seed';
	attestationMode: 'embed' | 'separate';
	epoch: number;
	kid: string;
	publicKeyXY: string;
	agentLogId: string | null;
	userLogId: string | null;
	userSealingDelegated?: boolean;
	/**
	 * A pending x402 `X-PAYMENT-REQUIRED` challenge (base64) the wallet must
	 * sign to buy the user grant (plan-2608-09 W4b); null on dark lanes and
	 * once paid.
	 */
	userGrantChallenge?: string | null;
	/** Why the last user-grant acquisition failed, if it did (plan-2608-11). */
	userGrantError?: string | null;
	/** Turns remaining in the purchased batch (W4c); null = unmetered. */
	prepaidTurns?: number | null;
	/** Daily demo-turn counters; pinned here at first fetch. */
	demoTurns?: DemoTurnCounters;
	/**
	 * W4d offline parent-policy proof artifacts: the completed user-authority
	 * creation grant (base64, receipt included) and the forest root public
	 * key (hex 64-byte x||y) that anchors its receipt.
	 */
	userAuthorityGrant?: string | null;
	rootPublicKeyXY?: string | null;
}

export interface TurnResponse {
	principal: string;
	workId: string;
	accepted: boolean;
	status: string;
}

/** One work unit as GET /receipts exports it (receipt.ts WorkExport + bookkeeping). */
export interface WorkExportWire {
	workId: string;
	state: 'submitted' | 'queued' | 'registered' | 'sequenced' | 'receipted' | 'error';
	submittedAt: number;
	envelopeB64: string;
	statementB64?: string;
	contentHash?: string;
	entryId?: string;
	receiptB64?: string;
	receiptedAt?: number;
	leafId?: string;
	error?: string;
	userLeaf: {
		state: 'held' | 'registered' | 'sequenced' | 'receipted' | 'error';
		contentHash?: string;
		entryId?: string;
		receiptB64?: string;
		receiptedAt?: number;
		error?: string;
	} | null;
	currentOutputText: string | null;
}

export interface ReceiptsExport {
	principal: string;
	attestationMode: 'embed' | 'separate';
	identity: { kid: string; publicKeyXY: string };
	forestrie: {
		agentLogId: string | null;
		userLogId: string | null;
		/** The pinned browser root (hex 64-byte x‖y) — user-leaf trust anchor (4a). */
		userRootPublicKeyXY?: string | null;
		userSealingDelegated?: boolean;
		/** Pending x402 challenge (W4b) to sign for the user grant; else null. */
		userGrantChallenge?: string | null;
		/** Turns remaining in the purchased batch (W4c); null = unmetered. */
		prepaidTurns?: number | null;
		/** Live daily demo-turn counters — polled every refresh. */
		demoTurns?: DemoTurnCounters;
	};
	works: WorkExportWire[];
}

// --- fetch helpers ---------------------------------------------------------

export class ScribeApiError extends Error {
	readonly status: number;
	constructor(status: number, message: string) {
		super(message);
		this.status = status;
	}
}

async function expectJson<T>(res: Response): Promise<T> {
	if (!res.ok) throw new ScribeApiError(res.status, (await res.text()).slice(0, 300));
	return res.json() as Promise<T>;
}

export async function fetchChallenge(): Promise<ChallengeResponse> {
	return expectJson(await fetch(`${scribeBase()}/auth/challenge`, { method: 'POST' }));
}

export async function fetchSession(challenge: string, signature: string): Promise<SessionResponse> {
	return expectJson(
		await fetch(`${scribeBase()}/auth/session`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ challenge, signature })
		})
	);
}

export async function fetchIdentity(sub: string, token: string): Promise<IdentityResponse> {
	return expectJson(
		await fetch(`${agentPath(sub)}/identity`, {
			headers: { Authorization: `Bearer ${token}` }
		})
	);
}

/**
 * Submit an attested turn. Two parts since Phase D: the envelope carries the
 * signed commitment `H(nonce ‖ input)` and goes on to the log; `input` is the
 * plaintext, which the worker needs to run the model and which stops there.
 * The DO refuses the turn unless the second opens the first.
 */
export async function postTurn(
	sub: string,
	token: string,
	envelopeB64: string,
	input: string
): Promise<TurnResponse> {
	return expectJson(
		await fetch(`${agentPath(sub)}/turn`, {
			method: 'POST',
			headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
			body: JSON.stringify({ envelopeB64, input })
		})
	);
}

export async function fetchReceipts(sub: string, token: string): Promise<ReceiptsExport> {
	return expectJson(
		await fetch(`${agentPath(sub)}/receipts`, {
			headers: { Authorization: `Bearer ${token}` }
		})
	);
}

export async function kickReceiptCollection(sub: string, token: string): Promise<void> {
	await expectJson(
		await fetch(`${agentPath(sub)}/collect-receipts`, {
			method: 'POST',
			headers: { Authorization: `Bearer ${token}` }
		})
	);
}

/**
 * Register (or re-assert) the browser-held user root key with the DO (Phase
 * 4a): the first key posted is pinned TOFU under the wcc-1 session and
 * becomes the user log's grantData; the same key is idempotent; a different
 * key is refused with 409 (reset identity to re-root). Called right after
 * session establishment, BEFORE any turn, so grant-at-bind issues the grant
 * over the root.
 */
export async function postUserRoot(sub: string, token: string, publicKeyXY: string): Promise<void> {
	await expectJson(
		await fetch(`${agentPath(sub)}/user-root`, {
			method: 'POST',
			headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
			body: JSON.stringify({ publicKeyXY })
		})
	);
}

/** Tell the DO the user's root key authorized sealing — releases held user leaves. */
export async function confirmUserSealingDelegated(sub: string, token: string): Promise<void> {
	await expectJson(
		await fetch(`${agentPath(sub)}/user-sealing-delegated`, {
			method: 'POST',
			headers: { Authorization: `Bearer ${token}` }
		})
	);
}

export interface PayUserGrantResponse {
	principal: string;
	paid: boolean;
	userLogId: string;
}

/**
 * Complete the x402 user-grant purchase (plan-2608-09 W4b): hand the DO the
 * wallet-signed `X-PAYMENT`; it forwards to the authority, which resubmits
 * register-grant and returns the issued grant. Resolves with the new log id.
 */
export async function payUserGrant(
	sub: string,
	token: string,
	xPayment: string
): Promise<PayUserGrantResponse> {
	return expectJson(
		await fetch(`${agentPath(sub)}/pay-user-grant`, {
			method: 'POST',
			headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
			body: JSON.stringify({ xPayment })
		})
	);
}
