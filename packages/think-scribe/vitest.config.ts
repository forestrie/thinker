/**
 * Node-environment unit tests. Deliberately NOT @cloudflare/vitest-pool-workers:
 * nothing here imports `cloudflare:workers` or touches Durable Object storage,
 * and the crypto these modules use (crypto.subtle, TextEncoder, btoa/atob) is
 * identical on Node 22 — so workerd would be install cost with no coverage.
 *
 * The day a test needs DO storage, this one config switches to
 * defineWorkersConfig and the other packages stay as they are. That is why the
 * configs are per-package rather than a single root `projects` block.
 */
import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		environment: 'node',
		include: ['test/**/*.test.ts'],
		exclude: [
			'**/node_modules/**',
			'**/dist/**',
			'**/.wrangler/**',
			// The live smoke scripts need wrangler dev + a real Forestrie lane +
			// .provision/ private keys + an ANTHROPIC_API_KEY. They are operator
			// tooling, not CI. Belt and braces — they are .mjs and would not match
			// `include` anyway.
			'**/*-smoke.mjs',
			'**/test/.out/**'
		]
	}
});
