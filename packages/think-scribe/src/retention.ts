/**
 * Bounded, expiring per-user retention (plan §D3).
 *
 * The demo's honesty depends on this being real: after Phase D the lane holds
 * only commitments, but the per-user Durable Object still holds the turn
 * records and the Think transcript — the actual words. Nothing was ever
 * deleted before this; every `work:` record and every message accumulated for
 * the life of the instance.
 *
 * Pure planning logic, kept out of `scribe.ts` so it can be unit-tested
 * without standing up Durable Object storage (this package's tests are
 * node-env, not workerd). The Scribe applies the plan; the DemoBudget DO
 * decides *when* — an interval schedule on `Scribe` itself would wake every
 * idle user's DO forever.
 */

/** Work records kept per user. Belt-and-braces: expiry is the real bound. */
export const MAX_WORK_RECORDS = 1000;

/**
 * How long a turn's record and its plaintext survive in the DO.
 *
 * Floor: this MUST stay well above the receipt-collection budget (max polls ×
 * poll interval, ~20 min today). The sweep deletes a record by age without
 * checking its state, so a window shorter than that budget could drop a turn
 * whose receipt is still being collected. A week clears it by orders of
 * magnitude — keep that margin if this is ever tuned down.
 */
export const RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Time-ordered index key. `work:<workId>` sorts by HASH, so a time-ordered
 * sweep (and a bounded "oldest first" trim) needs its own key. Zero-padded to
 * 13 digits so lexical order is chronological order until the year 33658.
 */
export function workIndexKey(submittedAt: number, workId: string): string {
	return `idx:${String(submittedAt).padStart(13, '0')}:${workId}`;
}

export const WORK_INDEX_PREFIX = 'idx:';

/** Read a `idx:<submittedAt>:<workId>` key back into its parts. */
export function parseWorkIndexKey(key: string): { submittedAt: number; workId: string } | null {
	const parts = key.split(':');
	if (parts.length !== 3 || parts[0] !== 'idx') return null;
	const submittedAt = Number(parts[1]);
	if (!Number.isFinite(submittedAt) || !parts[2]) return null;
	return { submittedAt, workId: parts[2] };
}

export interface RetentionPlan {
	/** Work units to delete, oldest first. */
	workIds: string[];
	/** How many were dropped for age vs for the record ceiling. */
	expired: number;
	trimmed: number;
	/**
	 * Cutoff the transcript is pruned to: messages and submissions older than
	 * this go with the records that named them.
	 */
	cutoff: number;
}

/**
 * Decide what a sweep should delete.
 *
 * Both bounds are applied: anything past the expiry window goes, and if what
 * survives still exceeds the record ceiling the oldest of those go too. Input
 * need not be sorted; the plan is emitted oldest-first so a caller that fails
 * part-way through has still deleted the most stale records.
 */
export function planRetentionSweep(
	index: Array<{ submittedAt: number; workId: string }>,
	now: number,
	limits: { maxRecords?: number; retentionMs?: number } = {}
): RetentionPlan {
	const maxRecords = limits.maxRecords ?? MAX_WORK_RECORDS;
	const retentionMs = limits.retentionMs ?? RETENTION_MS;
	const cutoff = now - retentionMs;

	const ordered = [...index].sort((a, b) => a.submittedAt - b.submittedAt);
	const expired = ordered.filter((e) => e.submittedAt < cutoff);
	const surviving = ordered.slice(expired.length);
	const trimmed = surviving.slice(0, Math.max(0, surviving.length - maxRecords));

	return {
		workIds: [...expired, ...trimmed].map((e) => e.workId),
		expired: expired.length,
		trimmed: trimmed.length,
		cutoff
	};
}
