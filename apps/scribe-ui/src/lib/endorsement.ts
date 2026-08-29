/**
 * Session-key endorsement window state (plan-2608-14 3.2, ADR-0065 §3): the
 * passkey's endorsement of this browser's per-turn signing key is no longer
 * "one gesture, ever" — it carries a validity window (default 7 days) that
 * canopy admission and every offline verifier enforce against the leaf's
 * receipted time. So, like the sealing lease, the countdown is surfaced and
 * re-endorsement is scheduled BEFORE the window lapses: a turn signed inside
 * the last day of the window would still be admitted, but a re-endorsement
 * costs one passkey gesture and the turn itself is a user activation, so
 * the gesture rides on the click that sends it.
 *
 * Pure functions of numbers — the tripwire is the same as `lease.ts`: never
 * let receipts silently stall at expiry.
 */
import { DEFAULT_ENDORSEMENT_WINDOW_MS } from '@forestrie/think-scribe/forestrie/passkey';

export { DEFAULT_ENDORSEMENT_WINDOW_MS };

/**
 * `notBefore` is back-dated by this much so a browser clock slightly BEHIND
 * canopy's still produces an endorsement canopy sees as already valid
 * (canopy tolerates 5 minutes the OTHER way — a fast browser — via its
 * notBefore skew, ADR-0065 §4).
 */
export const ENDORSEMENT_NOT_BEFORE_BACKDATE_MS = 60 * 1000;

/** Re-endorse when less than this remains (1 day of a 7-day window). */
export const ENDORSEMENT_RENEW_WINDOW_MS = 24 * 60 * 60 * 1000;

export interface EndorsementWindowMs {
	notBefore: number;
	notAfter: number;
}

/** The window for a fresh endorsement minted now. */
export function newEndorsementWindow(
	nowMs: number,
	windowMs: number = DEFAULT_ENDORSEMENT_WINDOW_MS
): EndorsementWindowMs {
	if (!Number.isSafeInteger(windowMs) || windowMs <= 0)
		throw new Error('endorsement window must be a positive integer number of milliseconds');
	return {
		notBefore: Math.max(0, nowMs - ENDORSEMENT_NOT_BEFORE_BACKDATE_MS),
		notAfter: nowMs + windowMs
	};
}

export type EndorsementPhase =
	/** No endorsement recorded (never endorsed, or a pre-ADR-0065 record). */
	| 'unknown'
	/** Comfortable runway. */
	| 'active'
	/** Inside the renewal window — the next turn re-endorses. */
	| 'expiring'
	/** Past notAfter: canopy refuses leaves until re-endorsed. */
	| 'expired';

export function endorsementPhase(notAfterMs: number | null, nowMs: number): EndorsementPhase {
	if (notAfterMs === null || !Number.isFinite(notAfterMs)) return 'unknown';
	const remaining = notAfterMs - nowMs;
	// The window is inclusive of notAfter (ADR-0065 §3).
	if (remaining < 0) return 'expired';
	if (remaining <= ENDORSEMENT_RENEW_WINDOW_MS) return 'expiring';
	return 'active';
}

/** Should the next turn carry a FRESH endorsement (one passkey gesture)? */
export function needsReendorsement(notAfterMs: number | null, nowMs: number): boolean {
	return endorsementPhase(notAfterMs, nowMs) !== 'active';
}

/** "6d 5h" / "5h 59m" / "12m" / "under a minute" — coarse on purpose. */
export function endorsementRemainingLabel(notAfterMs: number, nowMs: number): string {
	const remaining = Math.max(0, notAfterMs - nowMs) / 1000;
	const days = Math.floor(remaining / 86_400);
	const hours = Math.floor((remaining % 86_400) / 3600);
	const minutes = Math.floor((remaining % 3600) / 60);
	if (days > 0) return `${days}d ${hours}h`;
	if (hours > 0) return `${hours}h ${minutes}m`;
	if (minutes > 0) return `${minutes}m`;
	return 'under a minute';
}
