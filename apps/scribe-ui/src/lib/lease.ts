/**
 * Sealing-lease display state (plan-2608-13 4.3): the delegation certificate
 * is a LEASE (~6h on the demo lane), and renewing it under passkey custody is
 * a two-gesture WebAuthn ceremony — so the countdown is surfaced, never
 * hidden, and the renewal prompt escalates as the expiry approaches.
 */
export type LeasePhase =
	/** No lease on record (never delegated, or a pre-4.3 confirmation). */
	| 'unknown'
	/** Comfortable runway. */
	| 'active'
	/** Inside the renewal window — prompt, before leaves start waiting. */
	| 'expiring'
	/** Past expiry: new leaves sequence but wait on a renewed delegation. */
	| 'expired';

/** Prompt renewal when less than this much lease remains (30 min). */
export const LEASE_RENEW_WINDOW_S = 30 * 60;

export function leasePhase(expiresAtSeconds: number | null, nowMs: number): LeasePhase {
	if (expiresAtSeconds === null || !Number.isFinite(expiresAtSeconds)) return 'unknown';
	const remaining = expiresAtSeconds - nowMs / 1000;
	if (remaining <= 0) return 'expired';
	if (remaining <= LEASE_RENEW_WINDOW_S) return 'expiring';
	return 'active';
}

/** "5h 59m" / "12m" / "under a minute" — coarse on purpose, it is a lease. */
export function leaseRemainingLabel(expiresAtSeconds: number, nowMs: number): string {
	const remaining = Math.max(0, expiresAtSeconds - nowMs / 1000);
	const hours = Math.floor(remaining / 3600);
	const minutes = Math.floor((remaining % 3600) / 60);
	if (hours > 0) return `${hours}h ${minutes}m`;
	if (minutes > 0) return `${minutes}m`;
	return 'under a minute';
}
