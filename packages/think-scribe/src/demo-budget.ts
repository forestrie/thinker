import { Agent, getAgentByName } from 'agents';
import {
	admit,
	counterKey,
	GLOBAL_TURNS_PREFIX,
	peek,
	utcDay,
	type AdmitResult,
	type CapStatus,
	type CounterStore
} from './demo-cap.ts';
import { RETENTION_MS } from './retention.ts';

/** The retention RPC the per-user Scribe exposes to the sweep (D3). */
interface ScribeRetentionRpc {
	sweepRetention(): Promise<{
		expired: number;
		trimmed: number;
		remaining: number;
		transcriptPruned: boolean;
	}>;
}

/** Registry prefix: one row per per-user Scribe instance the sweep must visit. */
const USER_PREFIX = 'user:';

/** Sweep cadence. Retention is a week; a daily pass is ample and cheap. */
const SWEEP_INTERVAL_S = 24 * 60 * 60;

/**
 * DemoBudget — the demo's single global spend bound, and the clock behind
 * per-user retention.
 *
 * One named instance (`idFromName('global')`, reached over the DEMO_BUDGET
 * binding from the Scribe DO, NOT through the agent lobby — that gate rejects
 * any name that isn't `user-<sub>`) holds a global daily turn counter keyed by
 * UTC date. DO storage is strongly consistent, so the cap is a hard bound under
 * exactly the burst it exists to stop.
 *
 * It holds NO message text — plaintext stays in the per-user Scribe DOs; this
 * class only ever sees an integer counter and a set of principal addresses (the
 * same pseudonymous wallet addresses that name the per-user DOs).
 *
 * The retention sweep (plan §D3) hangs off here rather than off `Scribe`
 * because an interval schedule on `Scribe` would wake every idle user's DO
 * forever, and because a DO cannot expire what it is not awake to notice: the
 * instances that most need sweeping are exactly the ones nobody is visiting.
 * `scheduleEvery` is idempotent, so calling it on every wake creates one row.
 */
export class DemoBudget<Env extends Cloudflare.Env = Cloudflare.Env> extends Agent<Env> {
	#store(): CounterStore {
		return {
			get: (key) => this.ctx.storage.get<number>(key),
			put: (key, value) => this.ctx.storage.put(key, value)
		};
	}

	async onStart(): Promise<void> {
		await this.scheduleEvery(SWEEP_INTERVAL_S, 'sweepRetention');
	}

	/**
	 * Atomic check-and-increment of today's global counter (RPC from Scribe).
	 *
	 * `sub` (the wcc-1 principal) registers the calling instance for the
	 * retention sweep. Every admitted turn re-stamps it, so the registry doubles
	 * as a last-activity index. Optional so a caller that predates D3 — or a
	 * test — still meters correctly; it just goes unswept.
	 */
	async admit(cap: number, sub?: string): Promise<AdmitResult> {
		if (sub) await this.ctx.storage.put(`${USER_PREFIX}${sub}`, Date.now());
		return admit(this.#store(), counterKey(GLOBAL_TURNS_PREFIX, utcDay(Date.now())), cap);
	}

	/** Today's global counter, read-only (RPC from Scribe for /identity, /receipts). */
	async counters(cap: number): Promise<CapStatus & { date: string }> {
		const date = utcDay(Date.now());
		return { date, ...(await peek(this.#store(), counterKey(GLOBAL_TURNS_PREFIX, date), cap)) };
	}

	/**
	 * The daily retention pass (D3): ask every registered per-user Scribe to
	 * drop what is past its window, and forget the ones with nothing left.
	 *
	 * A user whose instance is fully swept AND who has not taken a turn within
	 * the retention window is dropped from the registry — otherwise the sweep
	 * would wake every identity the demo has ever seen, daily, forever. If they
	 * come back, the next admitted turn re-registers them.
	 *
	 * Per-user failures are logged and skipped: one unreachable instance must
	 * not stop the sweep for the rest.
	 */
	async sweepRetention(): Promise<{ visited: number; swept: number; dropped: number }> {
		const namespace = (this.env as { Scribe?: DurableObjectNamespace }).Scribe;
		if (!namespace) {
			console.warn('retention sweep skipped — no Scribe namespace bound to DemoBudget');
			return { visited: 0, swept: 0, dropped: 0 };
		}
		const registered = await this.ctx.storage.list<number>({ prefix: USER_PREFIX });
		const idleCutoff = Date.now() - RETENTION_MS;
		let visited = 0;
		let swept = 0;
		let dropped = 0;
		for (const [key, lastSeen] of registered) {
			const sub = key.slice(USER_PREFIX.length);
			visited++;
			try {
				// Addressed the way the lobby addresses it (`idFromName('user-<sub>')`,
				// with the SDK's own init handshake), then narrowed to the one method
				// this sweep calls — resolving the full Agent generic through a
				// Durable Object stub blows TypeScript's instantiation depth.
				const stub = (await getAgentByName(
					namespace as unknown as DurableObjectNamespace<Agent<Cloudflare.Env>>,
					`user-${sub}`
				)) as unknown as ScribeRetentionRpc;
				const result = await stub.sweepRetention();
				if (result.expired > 0 || result.trimmed > 0) swept++;
				if (result.remaining === 0 && lastSeen < idleCutoff) {
					await this.ctx.storage.delete(key);
					dropped++;
				}
			} catch (err) {
				console.warn(`retention sweep failed for ${sub}`, err);
			}
		}
		console.log(`retention sweep: visited ${visited}, swept ${swept}, dropped ${dropped}`);
		return { visited, swept, dropped };
	}
}
