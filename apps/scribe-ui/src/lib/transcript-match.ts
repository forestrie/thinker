/**
 * Recover workIds for a resynced transcript. Only local echoes carry a
 * `workId` (`local-${workId.slice(0, 12)}`); the DO persists user messages
 * under fresh UUIDs with no work reference. The vault, though, keeps
 * `{workId, input}` per turn in localStorage — so an exact text match
 * recovers the association for messages this browser sent. Best-effort by
 * design: an unmatched message simply renders no caption, and the receipts
 * drawer remains the complete record. Pure module (no runes) so vitest
 * covers it.
 */

import type { KeptTurn } from './vault.svelte.ts';

export interface MatchableMessage {
	id: string;
	role: 'user' | 'assistant' | 'system';
	workId?: string;
	/** Concatenated text parts (see textOf in ChatPanel). */
	text: string;
}

/**
 * messageId → workId. User messages match first (echo workId, else exact
 * vault text, oldest entry first so duplicate texts keep submission order);
 * each assistant message then inherits the nearest preceding user match —
 * the reply is part of the same attested turn.
 */
export function matchWorkIds(
	messages: readonly MatchableMessage[],
	vault: Readonly<Record<string, KeptTurn>>
): Map<string, string> {
	const out = new Map<string, string>();
	const claimed = new Set<string>();

	for (const m of messages) {
		if (m.role === 'user' && m.workId) {
			out.set(m.id, m.workId);
			claimed.add(m.workId);
		}
	}

	const unclaimed = Object.values(vault)
		.filter((t) => !claimed.has(t.workId))
		.sort((a, b) => a.at - b.at);

	for (const m of messages) {
		if (m.role !== 'user' || out.has(m.id)) continue;
		const idx = unclaimed.findIndex((t) => t.input === m.text);
		if (idx === -1) continue;
		const [turn] = unclaimed.splice(idx, 1);
		out.set(m.id, turn.workId);
	}

	let lastUserWorkId: string | null = null;
	for (const m of messages) {
		if (m.role === 'user') {
			lastUserWorkId = out.get(m.id) ?? null;
		} else if (m.role === 'assistant' && lastUserWorkId !== null) {
			out.set(m.id, lastUserWorkId);
		}
	}

	return out;
}
