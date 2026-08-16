/**
 * Daily demo-turn caps.
 *
 * Pure logic over a minimal async counter store so both the global `DemoBudget`
 * DO and the per-user `Scribe` DO share one implementation — and so the Node
 * unit tests can drive it with an in-memory `Map` instead of standing up
 * Durable Object storage (this package's tests are node-env, not workerd).
 *
 * The cap is the demo's only real spend bound: DEMO_PASSWORD gating plus free
 * identities mean the GLOBAL daily cap is what actually limits Anthropic spend.
 * The per-user cap is fairness, not a spend control.
 */

/**
 * The slice of Durable Object storage the caps need: a UTC-date-scoped counter.
 * `Scribe`/`DemoBudget` back this with `this.ctx.storage`; tests back it with a
 * `Map`.
 */
export interface CounterStore {
	get(key: string): Promise<number | undefined>;
	put(key: string, value: number): Promise<void>;
}

export interface CapStatus {
	/** Turns admitted so far on the current UTC day. */
	used: number;
	/** The configured daily ceiling. */
	cap: number;
}

export interface AdmitResult extends CapStatus {
	/** True iff this call was admitted (and the counter incremented). */
	allowed: boolean;
}

/** Per-user daily counter key prefix (Scribe-local storage). */
export const USER_TURNS_PREFIX = 'demo:userTurns';
/** Global daily counter key prefix (DemoBudget storage). */
export const GLOBAL_TURNS_PREFIX = 'demo:globalTurns';

/** UTC calendar day (`YYYY-MM-DD`) for `nowMs` — the counter's reset boundary. */
export function utcDay(nowMs: number): string {
	return new Date(nowMs).toISOString().slice(0, 10);
}

/** Storage key for a day's counter under a namespace prefix. */
export function counterKey(prefix: string, day: string): string {
	return `${prefix}:${day}`;
}

/** Parse a cap var (a positive integer string); fall back on anything else. */
export function parseCap(value: string | undefined, fallback: number): number {
	const n = Number(value);
	return Number.isInteger(n) && n > 0 ? n : fallback;
}

/**
 * Atomic check-and-increment against a day's counter. Refuses — WITHOUT
 * incrementing — once `used >= cap`, so a rejected turn never consumes budget.
 * Atomic because a DO instance processes one request at a time: nothing
 * interleaves the get and the put on the same instance, which is exactly why
 * the global cap lives in a single-named DO rather than eventually-consistent
 * KV (KV would leak under the burst the cap exists to stop).
 */
export async function admit(store: CounterStore, key: string, cap: number): Promise<AdmitResult> {
	const used = (await store.get(key)) ?? 0;
	if (used >= cap) return { allowed: false, used, cap };
	await store.put(key, used + 1);
	return { allowed: true, used: used + 1, cap };
}

/** Read-only view of a day's counter (for surfacing on /identity and /receipts). */
export async function peek(store: CounterStore, key: string, cap: number): Promise<CapStatus> {
	return { used: (await store.get(key)) ?? 0, cap };
}

export interface CapConfig {
	/** Per-user daily cap (fairness). */
	userCap: number;
	/** Global daily cap (the actual spend bound). */
	globalCap: number;
}

export type CapDecision =
	{ ok: true } | { ok: false; scope: 'user' | 'global'; used: number; cap: number };

export interface CapContext {
	/**
	 * Whether this is a genuinely new turn. The caller passes `false` for a
	 * re-submitted envelope (same workId) so an idempotent retry is never
	 * double-counted.
	 */
	isNewTurn: boolean;
	now: number;
	/** Per-user counter store (Scribe-local). */
	userStore: CounterStore;
	/**
	 * The global cap's atomic check-and-increment (DemoBudget.admit over RPC),
	 * or null when no budget DO is bound (a bare dev shell) — then only the
	 * per-user cap applies.
	 */
	admitGlobal: ((cap: number) => Promise<AdmitResult>) | null;
	config: CapConfig;
}

/**
 * Gate a turn against the daily caps.
 *
 * Order matters. The per-user cap is checked FIRST and read-only; only if it
 * passes is the global cap consumed (atomic check-and-increment); only once
 * BOTH pass is the per-user slot finally incremented. Consequences:
 *
 *  - a turn refused by either cap mutates no counter it wasn't admitted
 *    against (so a capped turn burns nothing, including — because the caller
 *    runs this before the prepaid decrement — a prepaid turn);
 *  - a user who has hit their OWN cap can never reach the global counter, so a
 *    single free identity cannot drain the global budget by hammering past its
 *    per-user limit.
 *
 * The per-user "check then later increment" is deliberately not atomic: a
 * same-user burst is still hard-bounded by the atomic GLOBAL cap, and the
 * per-user cap is only fairness, so a little looseness there is fine.
 */
export async function applyDailyCaps(ctx: CapContext): Promise<CapDecision> {
	if (!ctx.isNewTurn) return { ok: true };
	const day = utcDay(ctx.now);
	const userKey = counterKey(USER_TURNS_PREFIX, day);

	const userUsed = (await ctx.userStore.get(userKey)) ?? 0;
	if (userUsed >= ctx.config.userCap)
		return { ok: false, scope: 'user', used: userUsed, cap: ctx.config.userCap };

	if (ctx.admitGlobal) {
		const g = await ctx.admitGlobal(ctx.config.globalCap);
		if (!g.allowed) return { ok: false, scope: 'global', used: g.used, cap: g.cap };
	}

	await ctx.userStore.put(userKey, userUsed + 1);
	return { ok: true };
}

export interface DailyCapCounters {
	date: string;
	user: CapStatus;
	global: CapStatus;
}

/** Read both counters for surfacing on /identity and /receipts (no mutation). */
export async function readDailyCaps(
	now: number,
	userStore: CounterStore,
	config: CapConfig,
	peekGlobal: ((cap: number) => Promise<CapStatus>) | null
): Promise<DailyCapCounters> {
	const day = utcDay(now);
	const userUsed = (await userStore.get(counterKey(USER_TURNS_PREFIX, day))) ?? 0;
	const global = peekGlobal
		? await peekGlobal(config.globalCap)
		: { used: 0, cap: config.globalCap };
	return { date: day, user: { used: userUsed, cap: config.userCap }, global };
}
