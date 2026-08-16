/**
 * Node-environment unit tests — see the rationale in
 * packages/think-scribe/vitest.config.ts. `src/auth.ts` uses only crypto.subtle,
 * Request/Response and @noble, so it runs unmodified on Node 22.
 *
 * The `include`/`exclude` pair is what keeps m{1..5}-smoke.mjs — which live in
 * this same test/ directory — out of the run.
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
			'**/*-smoke.mjs',
			'**/test/.out/**'
		]
	}
});
