import { Agent } from 'agents';
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

/**
 * DemoBudget — the demo's single global spend bound.
 *
 * One named instance (`idFromName('global')`, reached over the DEMO_BUDGET
 * binding from the Scribe DO, NOT through the agent lobby — that gate rejects
 * any name that isn't `user-<sub>`) holds a global daily turn counter keyed by
 * UTC date. DO storage is strongly consistent, so the cap is a hard bound under
 * exactly the burst it exists to stop.
 *
 * It holds NO message text — plaintext stays in the per-user Scribe DOs; this
 * class only ever sees an integer counter.
 *
 * It extends the agents SDK `Agent` so a periodic retention sweep can later be
 * hosted here via `scheduleEvery` (idempotent by construction), rather than on
 * `Scribe` where an interval schedule would wake every idle user's DO forever.
 * Today it wires only the counter.
 */
export class DemoBudget<Env extends Cloudflare.Env = Cloudflare.Env> extends Agent<Env> {
	#store(): CounterStore {
		return {
			get: (key) => this.ctx.storage.get<number>(key),
			put: (key, value) => this.ctx.storage.put(key, value)
		};
	}

	/** Atomic check-and-increment of today's global counter (RPC from Scribe). */
	async admit(cap: number): Promise<AdmitResult> {
		return admit(this.#store(), counterKey(GLOBAL_TURNS_PREFIX, utcDay(Date.now())), cap);
	}

	/** Today's global counter, read-only (RPC from Scribe for /identity, /receipts). */
	async counters(cap: number): Promise<CapStatus & { date: string }> {
		const date = utcDay(Date.now());
		return { date, ...(await peek(this.#store(), counterKey(GLOBAL_TURNS_PREFIX, date), cap)) };
	}
}
