/**
 * The user's own copy (plan §D4) — the half of redaction that makes it a
 * feature rather than a loss.
 *
 * Once the envelope commits to `H(nonce ‖ input)` instead of the input, the
 * agent's instance holds no readable prompt, and what it does hold expires. So
 * the browser keeps the opening: `{workId, input, envelopeB64}` in
 * localStorage, beside the wallet key that already lives there. With it the
 * user can (a) read their own history back, and (b) export a proof bundle that
 * verifies offline, forever, with the service switched off.
 *
 * Local text only. The lane's receipts are permanent by design — nothing here
 * can or should delete those, and the UI must not pretend otherwise.
 */

export interface KeptTurn {
	workId: string;
	/** The plaintext the wallet committed to. */
	input: string;
	/** The signed envelope, base64 — the commitment the opening opens. */
	envelopeB64: string;
	/** When this browser kept it (epoch ms). */
	at: number;
}

/**
 * Ceiling on kept turns. localStorage is a few MB and an input is up to 4 KB,
 * so this cannot be unbounded; eviction is oldest-first, and a quota error
 * evicts and retries rather than losing the turn being written.
 */
export const MAX_KEPT_TURNS = 500;

/** One key per wallet address: a fresh identity starts with a fresh vault. */
function storageKey(address: string): string {
	return `scribe:turns:${address.toLowerCase()}`;
}

function load(address: string): Record<string, KeptTurn> {
	if (typeof localStorage === 'undefined') return {};
	try {
		const raw = localStorage.getItem(storageKey(address));
		const parsed: unknown = raw ? JSON.parse(raw) : {};
		return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
			? (parsed as Record<string, KeptTurn>)
			: {};
	} catch {
		return {};
	}
}

export class TurnVault {
	#address: string;
	/** workId → the kept turn. Reactive: WorkCard reads its prompt from here. */
	entries = $state<Record<string, KeptTurn>>({});

	constructor(address: string) {
		this.#address = address;
		this.entries = load(address);
	}

	get count(): number {
		return Object.keys(this.entries).length;
	}

	input(workId: string): string | null {
		return this.entries[workId]?.input ?? null;
	}

	/** Keep a turn. Evicts oldest-first past the ceiling, and again on quota. */
	keep(turn: KeptTurn): void {
		const next = { ...this.entries, [turn.workId]: turn };
		this.entries = this.#persist(this.#evictTo(next, MAX_KEPT_TURNS));
	}

	/**
	 * Forget every locally-kept message for this identity. LOCAL ONLY — the log
	 * entries this browser already caused are permanent, which is the property
	 * the whole demo exists to show.
	 */
	clear(): void {
		this.entries = {};
		try {
			localStorage?.removeItem(storageKey(this.#address));
		} catch {
			// A browser that refuses to remove it will refuse to write it too.
		}
	}

	#evictTo(entries: Record<string, KeptTurn>, limit: number): Record<string, KeptTurn> {
		const kept = Object.values(entries).sort((a, b) => a.at - b.at);
		if (kept.length <= limit) return entries;
		return Object.fromEntries(kept.slice(kept.length - limit).map((t) => [t.workId, t]));
	}

	#persist(entries: Record<string, KeptTurn>): Record<string, KeptTurn> {
		let candidate = entries;
		for (let attempt = 0; attempt < 4; attempt++) {
			try {
				localStorage?.setItem(storageKey(this.#address), JSON.stringify(candidate));
				return candidate;
			} catch {
				// Quota (or a private-mode refusal): halve and retry. Losing the
				// oldest openings is strictly better than losing the newest.
				const size = Object.keys(candidate).length;
				if (size <= 1) return candidate;
				candidate = this.#evictTo(candidate, Math.floor(size / 2));
			}
		}
		return candidate;
	}
}
