/**
 * Durable state for the authority, behind a narrow interface.
 *
 * The local service kept all of this on disk (`.provision/issued/*.json`,
 * `books.jsonl`, an in-process Map of lease expiries). A Worker has no disk, so
 * it moves to KV — with one honest caveat recorded here rather than discovered
 * later:
 *
 * **KV has no compare-and-set.** Two concurrent `/grants/user` calls for the
 * same address can both miss the cache and both issue — two logs, two payments.
 * The file cache had exactly the same race (`existsSync` then write), so this is
 * not a regression, but it is not a fix either. The real fix is a Durable Object
 * keyed per subject, which serialises by construction; this interface exists so
 * that swap is one file rather than a rewrite.
 */

/** A completed, receipted grant as the client consumes it. */
export interface IssuedGrant {
	kind: 'agent' | 'user';
	/** kid hex (agent) or 0x-prefixed address (user). */
	subject: string;
	logId: string;
	grantB64: string;
	/** Present on user grants: the purchased batch ceiling (W4a). */
	maxHeight?: number;
	/**
	 * User grants, ES256 shape (plan-2608-13 Phase 4a): the 64-byte P-256
	 * root (hex x‖y) the grantData endorses. Absent = legacy grant over the
	 * 20-byte wallet address. Cached responses are only reused when the
	 * requested shape matches — a changed root is a NEW log.
	 */
	publicKeyXY?: string;
}

/**
 * A registration that was accepted by the lane but whose receipt had not
 * arrived before the request deadline.
 *
 * Persisting this is what makes a timeout safe. Without it, the retry builds a
 * BRAND NEW grant on a BRAND NEW log — orphaning the one already registered and,
 * for user grants on a paid lane, burning the payment. With it, the next call
 * resumes polling the same statusUrl.
 */
export interface InFlightRegistration {
	logId: string;
	/** The signed-but-not-yet-completed COSE Sign1, base64. */
	sign1B64: string;
	statusUrl: string;
	startedAt: number;
	maxHeight?: number;
}

export interface IssuerStore {
	getIssued(kind: 'agent' | 'user', subject: string): Promise<IssuedGrant | null>;
	putIssued(grant: IssuedGrant): Promise<void>;
	deleteIssued(kind: 'agent' | 'user', subject: string): Promise<void>;

	getInFlight(kind: 'agent' | 'user', subject: string): Promise<InFlightRegistration | null>;
	putInFlight(kind: 'agent' | 'user', subject: string, record: InFlightRegistration): Promise<void>;
	deleteInFlight(kind: 'agent' | 'user', subject: string): Promise<void>;

	/** Sealing-lease expiry (unix seconds) for one auth log, or 0 if unknown. */
	getLeaseExpiry(logId: string): Promise<number>;
	putLeaseExpiry(logId: string, expiresAt: number): Promise<void>;
}

const issuedKey = (kind: string, subject: string) => `issued:${kind}:${subject}`;
const inFlightKey = (kind: string, subject: string) => `inflight:${kind}:${subject}`;
const leaseKey = (logId: string) => `lease:${logId}`;

export function kvIssuerStore(kv: KVNamespace): IssuerStore {
	return {
		async getIssued(kind, subject) {
			return kv.get<IssuedGrant>(issuedKey(kind, subject), 'json');
		},
		async putIssued(grant) {
			await kv.put(issuedKey(grant.kind, grant.subject), JSON.stringify(grant));
		},
		async deleteIssued(kind, subject) {
			await kv.delete(issuedKey(kind, subject));
		},

		async getInFlight(kind, subject) {
			return kv.get<InFlightRegistration>(inFlightKey(kind, subject), 'json');
		},
		async putInFlight(kind, subject, record) {
			// A stuck in-flight record must not wedge a subject forever: after an
			// hour the lane has long since given up, and a fresh grant is correct.
			await kv.put(inFlightKey(kind, subject), JSON.stringify(record), {
				expirationTtl: 3600
			});
		},
		async deleteInFlight(kind, subject) {
			await kv.delete(inFlightKey(kind, subject));
		},

		async getLeaseExpiry(logId) {
			const raw = await kv.get(leaseKey(logId));
			const parsed = raw === null ? Number.NaN : Number(raw);
			return Number.isFinite(parsed) ? parsed : 0;
		},
		async putLeaseExpiry(logId, expiresAt) {
			await kv.put(leaseKey(logId), String(expiresAt));
		}
	};
}

/** In-memory store for tests. Same semantics, no KV binding required. */
export function memoryIssuerStore(): IssuerStore {
	const map = new Map<string, string>();
	return {
		async getIssued(kind, subject) {
			const raw = map.get(issuedKey(kind, subject));
			return raw ? (JSON.parse(raw) as IssuedGrant) : null;
		},
		async putIssued(grant) {
			map.set(issuedKey(grant.kind, grant.subject), JSON.stringify(grant));
		},
		async deleteIssued(kind, subject) {
			map.delete(issuedKey(kind, subject));
		},
		async getInFlight(kind, subject) {
			const raw = map.get(inFlightKey(kind, subject));
			return raw ? (JSON.parse(raw) as InFlightRegistration) : null;
		},
		async putInFlight(kind, subject, record) {
			map.set(inFlightKey(kind, subject), JSON.stringify(record));
		},
		async deleteInFlight(kind, subject) {
			map.delete(inFlightKey(kind, subject));
		},
		async getLeaseExpiry(logId) {
			return Number(map.get(leaseKey(logId)) ?? 0);
		},
		async putLeaseExpiry(logId, expiresAt) {
			map.set(leaseKey(logId), String(expiresAt));
		}
	};
}
