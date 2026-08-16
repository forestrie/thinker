/**
 * Retention planning (D3). The sweep is the only thing that ever deletes
 * anything in this system, so its arithmetic gets tested directly rather than
 * inferred from a live Durable Object.
 */
import { describe, expect, it } from 'vitest';
import {
	MAX_WORK_RECORDS,
	RETENTION_MS,
	parseWorkIndexKey,
	planRetentionSweep,
	workIndexKey
} from '../src/retention.ts';

const NOW = Date.UTC(2026, 7, 16, 12, 0, 0);
const at = (msAgo: number) => ({ submittedAt: NOW - msAgo, workId: `w${msAgo}` });

describe('index keys', () => {
	it('sorts chronologically as strings — work: keys sort by hash', () => {
		const early = workIndexKey(1_000, 'ffff');
		const late = workIndexKey(2_000_000_000_000, '0000');
		expect(early < late).toBe(true);
	});

	it('round-trips', () => {
		expect(parseWorkIndexKey(workIndexKey(1755000000000, 'abc'))).toEqual({
			submittedAt: 1755000000000,
			workId: 'abc'
		});
	});

	it('refuses keys it did not write', () => {
		expect(parseWorkIndexKey('work:abc')).toBeNull();
		expect(parseWorkIndexKey('idx:notanumber:abc')).toBeNull();
		expect(parseWorkIndexKey('idx:123')).toBeNull();
	});
});

describe('planRetentionSweep', () => {
	it('keeps everything inside the window and under the ceiling', () => {
		const plan = planRetentionSweep([at(0), at(RETENTION_MS - 1)], NOW);
		expect(plan.workIds).toEqual([]);
		expect(plan.expired).toBe(0);
	});

	it('expires anything past the window', () => {
		const plan = planRetentionSweep([at(0), at(RETENTION_MS + 1), at(RETENTION_MS * 3)], NOW);
		// Oldest first, so a partial failure still removes the stalest records.
		expect(plan.workIds).toEqual([`w${RETENTION_MS * 3}`, `w${RETENTION_MS + 1}`]);
		expect(plan.expired).toBe(2);
		expect(plan.trimmed).toBe(0);
	});

	it('trims the oldest survivors past the record ceiling', () => {
		const entries = Array.from({ length: 12 }, (_, i) => ({
			submittedAt: NOW - i * 1000,
			workId: `w${i}`
		}));
		const plan = planRetentionSweep(entries, NOW, { maxRecords: 10 });
		expect(plan.expired).toBe(0);
		expect(plan.trimmed).toBe(2);
		expect(plan.workIds).toEqual(['w11', 'w10']);
	});

	it('applies both bounds together, and never double-counts a record', () => {
		const entries = [
			...Array.from({ length: 5 }, (_, i) => ({
				submittedAt: NOW - i * 1000,
				workId: `fresh${i}`
			})),
			// Strictly past the cutoff: a record landing exactly ON it survives.
			...Array.from({ length: 3 }, (_, i) => ({
				submittedAt: NOW - RETENTION_MS - (i + 1) * 1000,
				workId: `stale${i}`
			}))
		];
		const plan = planRetentionSweep(entries, NOW, { maxRecords: 3 });
		expect(plan.expired).toBe(3);
		expect(plan.trimmed).toBe(2);
		expect(new Set(plan.workIds).size).toBe(5);
		// The three newest survive.
		expect(plan.workIds).not.toContain('fresh0');
		expect(plan.workIds).not.toContain('fresh1');
		expect(plan.workIds).not.toContain('fresh2');
	});

	it('reports the cutoff the transcript is pruned to', () => {
		expect(planRetentionSweep([], NOW).cutoff).toBe(NOW - RETENTION_MS);
	});

	it('ships the numbers the plan chose', () => {
		expect(MAX_WORK_RECORDS).toBe(1000);
		expect(RETENTION_MS).toBe(7 * 24 * 60 * 60 * 1000);
	});
});
