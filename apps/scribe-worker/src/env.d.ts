/**
 * App Env, declared by hand instead of `wrangler types`: the generated
 * interface types every `.dev.vars` key as a REQUIRED string, which fights
 * ScribeEnv's contract that the Forestrie wiring is optional (an
 * unprovisioned dev shell still chats) and drifts every time a var is
 * added. The library owns the optional/required split; this file adds only
 * what the app itself contributes.
 */
import type { Scribe, ScribeEnv } from '@forestrie/think-scribe';

declare global {
	interface Env extends ScribeEnv {
		/** wcc-1 session HMAC secret (auth.ts). */
		SESSION_HMAC_SECRET: string;
		/** "1" enables `dev:` bearer tokens — local dev only. */
		DEV_AUTH?: string;
		/**
		 * Shared demo password (demo-gate.ts). Unset leaves the gate open, which
		 * is what makes `wrangler dev` work with no ceremony; deploy.yml's
		 * preflight requires it for every deployed environment.
		 */
		DEMO_PASSWORD?: string;
		/**
		 * `off` disables the demo gate outright, even with DEMO_PASSWORD set —
		 * the explicit switch for local dev and integration tests. Only the exact
		 * string `off` counts; anything else leaves the gate up. Not on
		 * deploy.yml's --var allowlist, and its preflight rejects it.
		 */
		DEMO_GATE?: string;
		/**
		 * The SvelteKit UI, service-bound. Absent in local `wrangler dev` (vite
		 * serves the UI there), so every use must be guarded.
		 */
		UI?: Fetcher;
		/**
		 * The grant authority, service-bound. Absent in local `wrangler dev`
		 * (scripts/authority.sh runs it on :8799 there), so guard every use.
		 */
		AUTHORITY?: Fetcher;
		Scribe: DurableObjectNamespace<Scribe>;
		// DEMO_BUDGET (the global spend-bound DO) is declared on ScribeEnv —
		// optional there so a bare dev shell still chats — and inherited here.
	}
}

export {};
