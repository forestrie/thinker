import { describe, expect, it } from 'vitest';
import {
	DEFAULT_ENDORSEMENT_WINDOW_MS,
	ENDORSEMENT_NOT_BEFORE_BACKDATE_MS,
	ENDORSEMENT_RENEW_WINDOW_MS,
	endorsementPhase,
	endorsementRemainingLabel,
	needsReendorsement,
	newEndorsementWindow
} from './endorsement.ts';

const NOW = 1_700_000_000_000;
const DAY = 24 * 3600 * 1000;

describe('newEndorsementWindow', () => {
	it('defaults to a 7-day window (ADR-0065 §3), back-dated slightly for a slow browser clock', () => {
		const w = newEndorsementWindow(NOW);
		expect(w.notBefore).toBe(NOW - ENDORSEMENT_NOT_BEFORE_BACKDATE_MS);
		expect(w.notAfter).toBe(NOW + DEFAULT_ENDORSEMENT_WINDOW_MS);
		expect(DEFAULT_ENDORSEMENT_WINDOW_MS).toBe(7 * DAY);
	});

	it('is configurable and refuses a non-positive or non-integer window', () => {
		expect(newEndorsementWindow(NOW, 2 * DAY).notAfter).toBe(NOW + 2 * DAY);
		expect(() => newEndorsementWindow(NOW, 0)).toThrow(/window/);
		expect(() => newEndorsementWindow(NOW, -1)).toThrow(/window/);
		expect(() => newEndorsementWindow(NOW, 1.5)).toThrow(/window/);
	});

	it('never back-dates before the epoch and always leaves notAfter > notBefore', () => {
		const w = newEndorsementWindow(10, 1000);
		expect(w.notBefore).toBe(0);
		expect(w.notAfter).toBeGreaterThan(w.notBefore);
	});
});

describe('endorsementPhase', () => {
	it('is unknown with no recorded window', () => {
		expect(endorsementPhase(null, NOW)).toBe('unknown');
		expect(endorsementPhase(Number.NaN, NOW)).toBe('unknown');
	});

	it('is active with comfortable runway', () => {
		expect(endorsementPhase(NOW + 6 * DAY, NOW)).toBe('active');
	});

	it('enters the renewal window (1 day) before lapse, not after', () => {
		expect(endorsementPhase(NOW + ENDORSEMENT_RENEW_WINDOW_MS + 1, NOW)).toBe('active');
		expect(endorsementPhase(NOW + ENDORSEMENT_RENEW_WINDOW_MS, NOW)).toBe('expiring');
		expect(endorsementPhase(NOW + 60_000, NOW)).toBe('expiring');
		expect(ENDORSEMENT_RENEW_WINDOW_MS).toBe(DAY);
	});

	it('is expired past the boundary — notAfter itself is still inside (inclusive, ADR-0065 §3)', () => {
		expect(endorsementPhase(NOW, NOW)).toBe('expiring');
		expect(endorsementPhase(NOW - 1, NOW)).toBe('expired');
	});
});

describe('needsReendorsement — the per-turn decision', () => {
	it('is true with no endorsement, or one that is expiring or expired', () => {
		expect(needsReendorsement(null, NOW)).toBe(true);
		expect(needsReendorsement(NOW + ENDORSEMENT_RENEW_WINDOW_MS, NOW)).toBe(true);
		expect(needsReendorsement(NOW - 1, NOW)).toBe(true);
	});

	it('is false while the endorsement has runway — no gesture on an ordinary turn', () => {
		expect(needsReendorsement(NOW + 3 * DAY, NOW)).toBe(false);
	});
});

describe('endorsementRemainingLabel', () => {
	it('renders days, hours, minutes coarsely', () => {
		expect(endorsementRemainingLabel(NOW + 6 * DAY + 5 * 3600 * 1000, NOW)).toBe('6d 5h');
		expect(endorsementRemainingLabel(NOW + 5 * 3600 * 1000 + 59 * 60 * 1000, NOW)).toBe('5h 59m');
		expect(endorsementRemainingLabel(NOW + 12 * 60 * 1000, NOW)).toBe('12m');
		expect(endorsementRemainingLabel(NOW + 10_000, NOW)).toBe('under a minute');
		expect(endorsementRemainingLabel(NOW - 10_000, NOW)).toBe('under a minute');
	});
});
