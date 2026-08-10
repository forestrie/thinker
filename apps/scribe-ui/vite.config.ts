import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// In dev the UI fronts the scribe-worker (`pnpm dev` in apps/scribe-worker,
// :8787): /auth and /agents proxy through, so the browser talks same-origin
// and the WebSocket upgrade rides the proxy too. In production either deploy
// behind the same hostname or set PUBLIC_SCRIBE_BASE to the worker origin.
const SCRIBE = process.env.SCRIBE_DEV_URL ?? 'http://localhost:8787';

// Dev convenience: lift the delegation-coordinator settings from the
// worker's .dev.vars so the browser-side KS256 sealing delegation works
// against the same lane with zero extra configuration. The coordinator is
// reached via the /coordinator proxy (it has no CORS surface), and the
// pinned registrar voucher key rides in as a PUBLIC_ env default.
const devVarsPath = fileURLToPath(new URL('../scribe-worker/.dev.vars', import.meta.url));
let coordinatorTarget = process.env.COORDINATOR_DEV_URL;
if (existsSync(devVarsPath)) {
	const devVars = Object.fromEntries(
		readFileSync(devVarsPath, 'utf8')
			.split('\n')
			.filter((l) => l.includes('=') && !l.startsWith('#'))
			.map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1).trim()])
	);
	coordinatorTarget ??= devVars.DELEGATION_COORDINATOR_URL;
	process.env.PUBLIC_KNOWN_SEALER_KEY ??= devVars.KNOWN_SEALER_KEY;
}

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	server: {
		proxy: {
			'/auth': { target: SCRIBE, changeOrigin: true },
			'/agents': { target: SCRIBE, changeOrigin: true, ws: true },
			...(coordinatorTarget
				? {
						'/coordinator': {
							target: coordinatorTarget,
							changeOrigin: true,
							rewrite: (path: string) => path.replace(/^\/coordinator/, '')
						}
					}
				: {})
		}
	}
});
