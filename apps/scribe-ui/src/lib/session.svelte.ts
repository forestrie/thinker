import { fetchChallenge, fetchSession } from './scribe-api.ts';
import type { DemoWallet } from './wallet.svelte.ts';

/** Renew when the session has less runway than this (worker TTL is 10 min). */
const RENEW_MARGIN_MS = 60_000;

/**
 * The wcc-1 session (plan §4): challenge → wallet personal_sign → short-lived
 * bearer. The demo wallet signs silently, so renewal is automatic — `ensure`
 * is called before every authed request and re-mints when the token is close
 * to expiry. The principal `sub` is the wallet address, which is also the DO
 * instance name suffix (`user-<sub>`).
 */
export class ScribeSession {
	#wallet: DemoWallet;
	#minting: Promise<string> | null = null;

	token = $state<string | null>(null);
	sub = $state<string | null>(null);
	exp = $state(0);
	error = $state<string | null>(null);

	constructor(wallet: DemoWallet) {
		this.#wallet = wallet;
	}

	get active(): boolean {
		return this.token !== null && this.exp - Date.now() > 0;
	}

	/** A valid bearer, minting or renewing if needed. Single-flight. */
	async ensure(): Promise<string> {
		if (this.token && this.exp - Date.now() > RENEW_MARGIN_MS) return this.token;
		this.#minting ??= this.#mint().finally(() => {
			this.#minting = null;
		});
		return this.#minting;
	}

	async #mint(): Promise<string> {
		try {
			const challenge = await fetchChallenge();
			const signature = this.#wallet.signPersonal(challenge.message);
			const session = await fetchSession(challenge.challenge, signature);
			if (session.sub.toLowerCase() !== this.#wallet.address.toLowerCase())
				throw new Error(`session principal ${session.sub} is not the wallet address`);
			this.token = session.token;
			this.sub = session.sub;
			this.exp = session.exp;
			this.error = null;
			return session.token;
		} catch (err) {
			this.error = String(err);
			throw err;
		}
	}

	/** Drop the session (wallet reset / sign-out). */
	clear(): void {
		this.token = null;
		this.sub = null;
		this.exp = 0;
	}
}
