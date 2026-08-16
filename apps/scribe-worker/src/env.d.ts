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
		Scribe: DurableObjectNamespace<Scribe>;
	}
}

export {};
