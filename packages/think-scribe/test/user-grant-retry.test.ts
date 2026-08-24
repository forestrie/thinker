/**
 * The predicate behind plan-2608-11. A fresh funded wallet on deployed dev sat
 * on a permanently disabled "Authorize sealing" button because grant-at-bind
 * fired once, failed, and nothing on the request path ever tried again. These
 * tests pin the two halves that make a retry safe as well as present.
 */
import { describe, expect, it } from 'vitest';
import {
	USER_GRANT_RETRY_COOLDOWN_MS,
	shouldRetryUserGrant,
	type UserGrantRetryState
} from '../src/user-grant-retry.ts';

/** The state that SHOULD retry; each test perturbs one field. */
const STUCK: UserGrantRetryState = {
	attestationMode: 'separate',
	authorityReachable: true,
	hasGrant: false,
	hasParkedChallenge: false,
	custodyPending: false,
	lastAttemptAt: null,
	now: 1_000_000
};

describe('the case this exists for', () => {
	it('retries a bound principal that has no grant and no challenge', () => {
		expect(shouldRetryUserGrant(STUCK)).toBe(true);
	});

	it('retries once the cooldown has elapsed', () => {
		expect(
			shouldRetryUserGrant({
				...STUCK,
				lastAttemptAt: STUCK.now - USER_GRANT_RETRY_COOLDOWN_MS
			})
		).toBe(true);
	});
});

describe('a parked challenge is not our move', () => {
	// canopy already 402'd; the browser wallet must sign. Asking again would
	// leave a second registration in flight for the same subject.
	it('does not retry while an x402 challenge is parked', () => {
		expect(shouldRetryUserGrant({ ...STUCK, hasParkedChallenge: true })).toBe(false);
	});

	it('still declines even after the cooldown', () => {
		expect(
			shouldRetryUserGrant({
				...STUCK,
				hasParkedChallenge: true,
				lastAttemptAt: STUCK.now - 10 * USER_GRANT_RETRY_COOLDOWN_MS
			})
		).toBe(false);
	});
});

describe('the cooldown', () => {
	// /receipts is polled every ~7s and every route passes the principal check,
	// so without this the authority takes several calls a minute per idle tab.
	it('suppresses a retry one poll after an attempt', () => {
		expect(shouldRetryUserGrant({ ...STUCK, lastAttemptAt: STUCK.now - 7_000 })).toBe(false);
	});

	it('suppresses right up to the boundary and fires on it', () => {
		const at = (elapsed: number) =>
			shouldRetryUserGrant({ ...STUCK, lastAttemptAt: STUCK.now - elapsed });
		expect(at(USER_GRANT_RETRY_COOLDOWN_MS - 1)).toBe(false);
		expect(at(USER_GRANT_RETRY_COOLDOWN_MS)).toBe(true);
	});

	it('is overridable', () => {
		expect(shouldRetryUserGrant({ ...STUCK, lastAttemptAt: STUCK.now - 100, cooldownMs: 50 })).toBe(
			true
		);
	});

	// A backwards clock must not wedge the retry shut — that would recreate the
	// deadlock this module exists to fix.
	it('treats a future timestamp as cooldown-elapsed rather than wedging', () => {
		expect(shouldRetryUserGrant({ ...STUCK, lastAttemptAt: STUCK.now + 60_000 })).toBe(true);
	});
});

describe('a pending custody choice is not our move either', () => {
	// The browser declared it may still create a passkey (plan-2608-13 4.3).
	// Issuing now would mint a wallet-address grant whose grantData the
	// activation ceremony can never re-root; the root pin re-kicks acquisition.
	it('does not acquire while the custody choice is pending', () => {
		expect(shouldRetryUserGrant({ ...STUCK, custodyPending: true })).toBe(false);
	});

	it('still declines even after the cooldown', () => {
		expect(
			shouldRetryUserGrant({
				...STUCK,
				custodyPending: true,
				lastAttemptAt: STUCK.now - 10 * USER_GRANT_RETRY_COOLDOWN_MS
			})
		).toBe(false);
	});
});

describe('cases with nothing to acquire', () => {
	it('does nothing in embed mode', () => {
		expect(shouldRetryUserGrant({ ...STUCK, attestationMode: 'embed' })).toBe(false);
	});

	it('does nothing when the authority is unreachable', () => {
		expect(shouldRetryUserGrant({ ...STUCK, authorityReachable: false })).toBe(false);
	});

	it('does nothing once the grant is stored', () => {
		expect(shouldRetryUserGrant({ ...STUCK, hasGrant: true })).toBe(false);
	});

	it('prefers the stored grant even if a stale challenge lingers', () => {
		expect(shouldRetryUserGrant({ ...STUCK, hasGrant: true, hasParkedChallenge: true })).toBe(
			false
		);
	});
});
