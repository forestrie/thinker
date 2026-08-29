import { describe, expect, it } from 'vitest';
import { matchWorkIds, type MatchableMessage } from './transcript-match.ts';
import type { KeptTurn } from './vault.svelte.ts';

function kept(workId: string, input: string, at: number): KeptTurn {
	return { workId, input, envelopeB64: '', at };
}

function msg(
	id: string,
	role: MatchableMessage['role'],
	text: string,
	workId?: string
): MatchableMessage {
	return { id, role, text, workId };
}

describe('matchWorkIds', () => {
	it('passes local-echo workIds through untouched', () => {
		const map = matchWorkIds([msg('local-abc', 'user', 'hello', 'w-echo')], {});
		expect(map.get('local-abc')).toBe('w-echo');
	});

	it('recovers resynced user messages by exact vault text', () => {
		const map = matchWorkIds([msg('uuid-1', 'user', 'hello')], {
			'w-1': kept('w-1', 'hello', 100)
		});
		expect(map.get('uuid-1')).toBe('w-1');
	});

	it('matches duplicate texts oldest-first, in message order', () => {
		const map = matchWorkIds([msg('m1', 'user', 'again'), msg('m2', 'user', 'again')], {
			'w-late': kept('w-late', 'again', 200),
			'w-early': kept('w-early', 'again', 100)
		});
		expect(map.get('m1')).toBe('w-early');
		expect(map.get('m2')).toBe('w-late');
	});

	it('never reuses a workId already claimed by an echo', () => {
		const map = matchWorkIds([msg('local-1', 'user', 'hi', 'w-1'), msg('uuid-2', 'user', 'hi')], {
			'w-1': kept('w-1', 'hi', 100)
		});
		expect(map.get('local-1')).toBe('w-1');
		expect(map.has('uuid-2')).toBe(false);
	});

	it('assistant messages inherit the nearest preceding user match', () => {
		const map = matchWorkIds(
			[
				msg('u1', 'user', 'first', 'w-1'),
				msg('a1', 'assistant', 'reply one'),
				msg('u2', 'user', 'second', 'w-2'),
				msg('a2', 'assistant', 'reply two')
			],
			{}
		);
		expect(map.get('a1')).toBe('w-1');
		expect(map.get('a2')).toBe('w-2');
	});

	it('leaves unmatched messages absent (no caption)', () => {
		const map = matchWorkIds(
			[msg('a0', 'assistant', 'greeting first'), msg('u1', 'user', 'unknown text')],
			{}
		);
		expect(map.size).toBe(0);
	});

	it('skips system messages entirely', () => {
		const map = matchWorkIds(
			[msg('u1', 'user', 'hi', 'w-1'), msg('s1', 'system', 'notice'), msg('a1', 'assistant', 'yo')],
			{}
		);
		expect(map.has('s1')).toBe(false);
		expect(map.get('a1')).toBe('w-1');
	});
});
