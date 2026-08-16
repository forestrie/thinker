/**
 * Node-environment unit tests — same rationale as the other packages. The
 * signer under test is pure WebCrypto, which Node 22 provides identically, and
 * the equivalence test additionally needs `node:crypto` to run the reference
 * implementation it is being compared against.
 */
import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		environment: 'node',
		include: ['test/**/*.test.ts'],
		exclude: ['**/node_modules/**', '**/dist/**', '**/.wrangler/**']
	}
});
