/**
 * Plain-language receipt status for a turn — the mapping between the wire's
 * work states and the two-word vocabulary the page speaks (receipting… /
 * receipted / verified / check failed). Pure module: no runes, no $env, so
 * vitest covers it (vitest.config.ts scope).
 */

import type { WorkExportWire } from './scribe-api.ts';

export type TurnStatus = 'receipting' | 'receipted' | 'error';

/** The agent's side of the turn: the work record itself. */
export function agentTurnStatus(work: WorkExportWire): TurnStatus {
	if (work.state === 'receipted') return 'receipted';
	if (work.state === 'error') return 'error';
	return 'receipting';
}

/**
 * The user's side of the turn. In separate mode the user leaf has its own
 * lifecycle ("held" until sealing is authorized); in embed mode there is no
 * user leaf and the work record covers the whole turn.
 */
export function userTurnStatus(work: WorkExportWire): TurnStatus {
	const leaf = work.userLeaf;
	if (leaf === null) return agentTurnStatus(work);
	if (leaf.state === 'receipted') return 'receipted';
	if (leaf.state === 'error') return 'error';
	return 'receipting';
}

/**
 * The caption under a bubble (and the status column of a receipt row).
 * "verified" is the strongest claim the page makes, so a verification result
 * may only speak for a side that actually reached "receipted" — verifyAll
 * runs per WORK and reports ok while a held user leaf is merely SKIPPED, and
 * captioning that "verified" would overclaim about an unsealed leaf. A failed
 * check, conversely, must never be softened.
 */
export function captionLabel(status: TurnStatus, verification?: { ok: boolean }): string {
	if (verification && status === 'receipted') return verification.ok ? 'verified' : 'check failed';
	if (verification && !verification.ok) return 'check failed';
	switch (status) {
		case 'receipted':
			return 'receipted';
		case 'error':
			return 'failed';
		default:
			return 'receipting…';
	}
}

/** 1-based turn number by submission order — "Turn 12" in the drawer. */
export function turnNumber(works: readonly WorkExportWire[], workId: string): number | null {
	const ordered = [...works].sort((a, b) => a.submittedAt - b.submittedAt);
	const index = ordered.findIndex((w) => w.workId === workId);
	return index === -1 ? null : index + 1;
}
