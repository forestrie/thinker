/**
 * Should the Scribe ask the authority for the user's grant again?
 *
 * Grant-at-bind fires once, when the principal first binds. If that single
 * attempt fails the user log never appears, the UI's "Authorize sealing" step
 * stays disabled, and — because the only fallback was the turn drain — the
 * user is deadlocked: the onboarding flow puts *Authorize sealing* BEFORE
 * chatting, so following it means never triggering the retry. Smoke scripts
 * never saw it because they always take a turn (plan-2608-11 D1).
 *
 * This is the predicate for retrying on the request path instead. It is a
 * separate pure module rather than a branch inside the Durable Object because
 * the DO is not unit-testable here and this is precisely the logic that failed
 * in production — see test/user-grant-retry.test.ts.
 */

/** Default gap between attempts. See plan-2608-11 Q1. */
export const USER_GRANT_RETRY_COOLDOWN_MS = 30_000;

export interface UserGrantRetryState {
	/** Attestation mode: only `separate` mints a user grant at all. */
	attestationMode: string;
	/** Is the authority reachable — by URL or by service binding? */
	authorityReachable: boolean;
	/** A user grant is already stored: nothing to do. */
	hasGrant: boolean;
	/** An x402 challenge is parked, awaiting the browser wallet's signature. */
	hasParkedChallenge: boolean;
	/** When the last acquisition was attempted (epoch ms), or null if never. */
	lastAttemptAt: number | null;
	/** Now, epoch ms. */
	now: number;
	/** Minimum gap between attempts. */
	cooldownMs?: number;
}

export function shouldRetryUserGrant(state: UserGrantRetryState): boolean {
	if (state.attestationMode !== 'separate') return false;
	if (!state.authorityReachable) return false;
	if (state.hasGrant) return false;

	// NOT a failure, and NOT our move: canopy already answered 402 and the
	// wallet has to sign. Re-asking would leave a second registration in
	// flight against the same subject (plan-2608-11 D3).
	if (state.hasParkedChallenge) return false;

	// Every HTTP route passes through the principal check and the UI polls
	// /receipts every ~7s, so an uncooled retry would hit the authority — which
	// holds K(L) and registers to the lane — several times a minute per idle
	// tab (D2).
	const cooldown = state.cooldownMs ?? USER_GRANT_RETRY_COOLDOWN_MS;
	if (state.lastAttemptAt === null) return true;

	// A clock that went backwards (or a stamp from the future) must not wedge
	// the retry shut forever — that would recreate the very deadlock this
	// exists to fix. Treat any non-positive elapsed time as "cooldown over".
	const elapsed = state.now - state.lastAttemptAt;
	if (elapsed <= 0) return true;
	return elapsed >= cooldown;
}
