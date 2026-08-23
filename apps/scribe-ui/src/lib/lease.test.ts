import { describe, expect, it } from 'vitest';
import { LEASE_RENEW_WINDOW_S, leasePhase, leaseRemainingLabel } from './lease.ts';

const NOW_MS = 1_700_000_000_000;
const nowS = NOW_MS / 1000;

describe('leasePhase', () => {
	it('is unknown with no recorded expiry', () => {
		expect(leasePhase(null, NOW_MS)).toBe('unknown');
		expect(leasePhase(Number.NaN, NOW_MS)).toBe('unknown');
	});

	it('is active with comfortable runway (~6h lease, fresh)', () => {
		expect(leasePhase(nowS + 6 * 3600, NOW_MS)).toBe('active');
	});

	it('enters the renewal window before expiry, not after', () => {
		expect(leasePhase(nowS + LEASE_RENEW_WINDOW_S + 1, NOW_MS)).toBe('active');
		expect(leasePhase(nowS + LEASE_RENEW_WINDOW_S, NOW_MS)).toBe('expiring');
		expect(leasePhase(nowS + 60, NOW_MS)).toBe('expiring');
	});

	it('is expired at and past the boundary', () => {
		expect(leasePhase(nowS, NOW_MS)).toBe('expired');
		expect(leasePhase(nowS - 1, NOW_MS)).toBe('expired');
	});
});

describe('leaseRemainingLabel', () => {
	it('renders hours and minutes', () => {
		expect(leaseRemainingLabel(nowS + 6 * 3600 - 60, NOW_MS)).toBe('5h 59m');
	});

	it('renders bare minutes inside an hour', () => {
		expect(leaseRemainingLabel(nowS + 12 * 60, NOW_MS)).toBe('12m');
	});

	it('never goes negative', () => {
		expect(leaseRemainingLabel(nowS - 500, NOW_MS)).toBe('under a minute');
	});
});
