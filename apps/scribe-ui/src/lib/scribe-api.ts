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
		userSealingDelegated?: boolean;
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

export async function postTurn(
	sub: string,
	token: string,
	envelopeB64: string
): Promise<TurnResponse> {
	return expectJson(
		await fetch(`${agentPath(sub)}/turn`, {
			method: 'POST',
			headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
			body: JSON.stringify({ envelopeB64 })
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

/** Tell the DO the wallet authorized sealing — releases held user leaves. */
export async function confirmUserSealingDelegated(sub: string, token: string): Promise<void> {
	await expectJson(
		await fetch(`${agentPath(sub)}/user-sealing-delegated`, {
			method: 'POST',
			headers: { Authorization: `Bearer ${token}` }
		})
	);
}
