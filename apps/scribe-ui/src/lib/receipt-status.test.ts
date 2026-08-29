import { describe, expect, it } from 'vitest';
import { agentTurnStatus, captionLabel, turnNumber, userTurnStatus } from './receipt-status.ts';
import type { WorkExportWire } from './scribe-api.ts';

function work(overrides: Partial<WorkExportWire> = {}): WorkExportWire {
	return {
		workId: 'w1',
		state: 'submitted',
		submittedAt: 1,
		envelopeB64: '',
		userLeaf: null,
		currentOutputText: null,
		...overrides
	};
}

describe('agentTurnStatus', () => {
	it('maps every in-flight state to receipting', () => {
		for (const state of ['submitted', 'queued', 'registered', 'sequenced'] as const) {
			expect(agentTurnStatus(work({ state }))).toBe('receipting');
		}
	});

	it('maps receipted and error terminals', () => {
		expect(agentTurnStatus(work({ state: 'receipted' }))).toBe('receipted');
		expect(agentTurnStatus(work({ state: 'error' }))).toBe('error');
	});
});

describe('userTurnStatus', () => {
	it('falls back to the work state in embed mode (no user leaf)', () => {
		expect(userTurnStatus(work({ state: 'receipted', userLeaf: null }))).toBe('receipted');
		expect(userTurnStatus(work({ state: 'queued', userLeaf: null }))).toBe('receipting');
	});

	it('reads the user leaf in separate mode, including held', () => {
		for (const state of ['held', 'registered', 'sequenced'] as const) {
			expect(userTurnStatus(work({ userLeaf: { state } }))).toBe('receipting');
		}
		expect(userTurnStatus(work({ userLeaf: { state: 'receipted' } }))).toBe('receipted');
		expect(userTurnStatus(work({ userLeaf: { state: 'error' } }))).toBe('error');
	});

	it('leaf state wins over work state', () => {
		expect(userTurnStatus(work({ state: 'receipted', userLeaf: { state: 'held' } }))).toBe(
			'receipting'
		);
	});
});

describe('captionLabel', () => {
	it('labels raw statuses', () => {
		expect(captionLabel('receipting')).toBe('receipting…');
		expect(captionLabel('receipted')).toBe('receipted');
		expect(captionLabel('error')).toBe('failed');
	});

	it('a completed verification wins over a receipted status', () => {
		expect(captionLabel('receipted', { ok: true })).toBe('verified');
		expect(captionLabel('receipted', { ok: false })).toBe('check failed');
	});

	it('never claims verified for a side that has not receipted', () => {
		// verifyAll reports work-level ok while a held user leaf is merely
		// skipped — that must not read as "verified" on the user's bubble.
		expect(captionLabel('receipting', { ok: true })).toBe('receipting…');
		expect(captionLabel('error', { ok: true })).toBe('failed');
	});

	it('a failed check is never softened, receipted or not', () => {
		expect(captionLabel('receipting', { ok: false })).toBe('check failed');
	});
});

describe('turnNumber', () => {
	const works = [
		work({ workId: 'b', submittedAt: 20 }),
		work({ workId: 'a', submittedAt: 10 }),
		work({ workId: 'c', submittedAt: 30 })
	];

	it('numbers by submission order, 1-based', () => {
		expect(turnNumber(works, 'a')).toBe(1);
		expect(turnNumber(works, 'b')).toBe(2);
		expect(turnNumber(works, 'c')).toBe(3);
	});

	it('returns null for an unknown workId', () => {
		expect(turnNumber(works, 'nope')).toBeNull();
	});
});
