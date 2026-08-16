/**
 * Deliberately NOT vite.config.ts: vitest prefers vitest.config.ts and does not
 * merge the two, which is what we want — the SvelteKit plugin and the
 * ../scribe-worker/.dev.vars lift are dev-server concerns with no place in a
 * unit run.
 *
 * Tests are colocated in src/ rather than test/: SvelteKit's generated
 * .svelte-kit/tsconfig.json includes ../src/**\/*.ts but not ../test/**, so
 * colocating is what gets them typechecked by `pnpm --filter scribe-ui check`.
 * It also leaves test/ as the unambiguous home of mu-smoke.mjs.
 *
 * Scope: modules with no runes and no $env import. Components and the
 * .svelte.ts stores need a browser-ish environment and are out of scope here.
 */
import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		environment: 'node',
		include: ['src/**/*.test.ts'],
		exclude: ['**/node_modules/**', '**/.svelte-kit/**', '**/*-smoke.mjs']
	}
});
