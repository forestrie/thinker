import { describe, expect, it, vi } from 'vitest';
import {
	admit,
	applyDailyCaps,
	counterKey,
	GLOBAL_TURNS_PREFIX,
	parseCap,
	readDailyCaps,
	USER_TURNS_PREFIX,
	utcDay,
	type AdmitResult,
	type CounterStore
} from '../src/demo-cap.ts';

/**
 * Daily demo-turn caps bound how much the shared demo can spend on Anthropic in
 * a day. The global cap is the real bound (identities are free, so a per-user
 * cap alone can't stop spend); the per-user cap is only fairness. This suite
 * drives the pure cap logic with an in-memory counter store — the same
 * interface the DemoBudget and Scribe Durable Objects back with `ctx.storage`.
 */

/** A CounterStore backed by a Map, so tests need no Durable Object storage. */
function memStore(
	initial: Record<string, number> = {}
): CounterStore & { map: Map<string, number> } {
	const map = new Map<string, number>(Object.entries(initial));
	return {
		map,
		get: (key) => Promise.resolve(map.get(key)),
		put: (key, value) => {
			map.set(key, value);
			return Promise.resolve();
		}
	};
}

// A fixed instant so the UTC-day key is deterministic across the suite.
const NOW = Date.UTC(2026, 7, 16, 12, 0, 0);
const DAY = utcDay(NOW);

describe('utcDay / parseCap', () => {
	it('keys the counter by UTC calendar day', () => {
		expect(utcDay(Date.UTC(2026, 7, 16, 23, 59))).toBe('2026-08-16');
		expect(utcDay(Date.UTC(2026, 7, 17, 0, 0))).toBe('2026-08-17');
	});

	it('accepts only positive integers, else falls back', () => {
		expect(parseCap('500', 10)).toBe(500);
		expect(parseCap(undefined, 10)).toBe(10);
		expect(parseCap('', 10)).toBe(10);
		expect(parseCap('0', 10)).toBe(10);
		expect(parseCap('-3', 10)).toBe(10);
		expect(parseCap('1.5', 10)).toBe(10);
		expect(parseCap('nope', 10)).toBe(10);
	});
});

describe('admit — atomic check-and-increment', () => {
	it('admits up to the cap, then refuses without incrementing', async () => {
		const store = memStore();
		const key = counterKey(GLOBAL_TURNS_PREFIX, DAY);
		expect(await admit(store, key, 2)).toEqual({ allowed: true, used: 1, cap: 2 });
		expect(await admit(store, key, 2)).toEqual({ allowed: true, used: 2, cap: 2 });
		// At the cap: refused, and the counter stays at 2 (a rejected turn spends
		// no budget).
		expect(await admit(store, key, 2)).toEqual({ allowed: false, used: 2, cap: 2 });
		expect(store.map.get(key)).toBe(2);
	});

	it('a second wallet shares the one global counter — it does not reset the cap', async () => {
		// The global counter is a single instance keyed only by the day, so turns
		// from any identity land on the same key. One wallet exhausting the cap
		// leaves nothing for the next.
		const store = memStore();
		const key = counterKey(GLOBAL_TURNS_PREFIX, DAY);
		const cap = 3;
		// Wallet A takes all three turns.
		for (let i = 0; i < cap; i++) expect((await admit(store, key, cap)).allowed).toBe(true);
		// Wallet B — a different identity, same day, same global counter — is
		// refused. Free identities cannot buy the demo a fresh global budget.
		expect((await admit(store, key, cap)).allowed).toBe(false);
	});
});

describe('applyDailyCaps', () => {
	const config = { userCap: 2, globalCap: 5 };
	const globalAlways = (): ((cap: number) => Promise<AdmitResult>) =>
		vi.fn(async (cap: number) => ({ allowed: true, used: 1, cap }));

	it('does nothing for a re-submitted envelope, so a retry is never double-counted', async () => {
		const userStore = memStore();
		const admitGlobal = vi.fn(async (cap: number) => ({ allowed: true, used: 1, cap }));
		const decision = await applyDailyCaps({
			isNewTurn: false,
			now: NOW,
			userStore,
			admitGlobal,
			config
		});
		expect(decision).toEqual({ ok: true });
		// Neither counter moved: the global DO was never called and the per-user
		// key is absent.
		expect(admitGlobal).not.toHaveBeenCalled();
		expect(userStore.map.size).toBe(0);
	});

	it('admits a new turn under both caps, consuming one global and one per-user slot', async () => {
		const userStore = memStore();
		const admitGlobal = globalAlways();
		const decision = await applyDailyCaps({
			isNewTurn: true,
			now: NOW,
			userStore,
			admitGlobal,
			config
		});
		expect(decision).toEqual({ ok: true });
		expect(admitGlobal).toHaveBeenCalledOnce();
		expect(admitGlobal).toHaveBeenCalledWith(config.globalCap);
		expect(userStore.map.get(counterKey(USER_TURNS_PREFIX, DAY))).toBe(1);
	});

	it('rejects on the per-user cap before ever touching the global counter', async () => {
		// A user already at their own cap must not reach the global admit — that
		// is what stops one identity draining the global budget by hammering past
		// its per-user limit.
		const userStore = memStore({ [counterKey(USER_TURNS_PREFIX, DAY)]: config.userCap });
		const admitGlobal = globalAlways();
		const decision = await applyDailyCaps({
			isNewTurn: true,
			now: NOW,
			userStore,
			admitGlobal,
			config
		});
		expect(decision).toEqual({
			ok: false,
			scope: 'user',
			used: config.userCap,
			cap: config.userCap
		});
		expect(admitGlobal).not.toHaveBeenCalled();
		// The per-user counter is unchanged by a rejected turn.
		expect(userStore.map.get(counterKey(USER_TURNS_PREFIX, DAY))).toBe(config.userCap);
	});

	it('rejects on the global cap and consumes no per-user slot', async () => {
		// The caller runs this before decrementing the prepaid batch, so a turn
		// refused by the global cap burns nothing — not a per-user slot, and not
		// a prepaid turn.
		const userStore = memStore();
		const admitGlobal = vi.fn(async (cap: number) => ({ allowed: false, used: cap, cap }));
		const decision = await applyDailyCaps({
			isNewTurn: true,
			now: NOW,
			userStore,
			admitGlobal,
			config
		});
		expect(decision).toEqual({
			ok: false,
			scope: 'global',
			used: config.globalCap,
			cap: config.globalCap
		});
		// The per-user counter was never incremented.
		expect(userStore.map.get(counterKey(USER_TURNS_PREFIX, DAY))).toBeUndefined();
	});

	it('enforces the per-user cap without a global DO bound', async () => {
		// A bare dev shell has no DemoBudget binding; the per-user cap still holds.
		const userStore = memStore();
		const cfg = { userCap: 1, globalCap: 99 };
		expect(
			(
				await applyDailyCaps({
					isNewTurn: true,
					now: NOW,
					userStore,
					admitGlobal: null,
					config: cfg
				})
			).ok
		).toBe(true);
		const second = await applyDailyCaps({
			isNewTurn: true,
			now: NOW,
			userStore,
			admitGlobal: null,
			config: cfg
		});
		expect(second).toEqual({ ok: false, scope: 'user', used: 1, cap: 1 });
	});
});

describe('readDailyCaps', () => {
	it('reports both counters without mutating them', async () => {
		const userStore = memStore({ [counterKey(USER_TURNS_PREFIX, DAY)]: 3 });
		const counters = await readDailyCaps(
			NOW,
			userStore,
			{ userCap: 50, globalCap: 500 },
			async (cap) => ({
				used: 120,
				cap
			})
		);
		expect(counters).toEqual({
			date: DAY,
			user: { used: 3, cap: 50 },
			global: { used: 120, cap: 500 }
		});
		// Read-only: the per-user counter is untouched.
		expect(userStore.map.get(counterKey(USER_TURNS_PREFIX, DAY))).toBe(3);
	});

	it('reports a zero global when no budget DO is bound', async () => {
		const counters = await readDailyCaps(NOW, memStore(), { userCap: 50, globalCap: 500 }, null);
		expect(counters.global).toEqual({ used: 0, cap: 500 });
	});
});
