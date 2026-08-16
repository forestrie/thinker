import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// In dev the UI fronts the scribe-worker (`pnpm dev` in apps/scribe-worker,
// :8787): /auth and /agents proxy through, so the browser talks same-origin
// and the WebSocket upgrade rides the proxy too.
//
// DEPLOYED, the direction is inverted: the scribe-worker is the single public
// origin and forwards non-API paths to this app over a service binding. Either
// way the browser only ever sees one origin, which is why PUBLIC_SCRIBE_BASE
// stays unset (scribe-api.ts returns '' → same-origin) and there is no CORS
// surface anywhere.
const SCRIBE = process.env.SCRIBE_DEV_URL ?? 'http://localhost:8787';

/**
 * Dev-server-only convenience: lift the delegation-coordinator settings from
 * the worker's .dev.vars so browser-side KS256 sealing delegation works against
 * the same lane with zero extra configuration.
 *
 * Scoped to `command === 'serve'` deliberately. A BUILD must never inherit
 * values from a gitignored local file: deployed PUBLIC_* come from the Worker's
 * runtime vars via $env/dynamic/public, so reading .dev.vars at build time
 * could only ever mislead — it made a local `vite build` behave differently
 * from CI, which is how people get fooled.
 */
function devVarsLift(): { coordinatorTarget: string | undefined } {
	let coordinatorTarget = process.env.COORDINATOR_DEV_URL;
	const devVarsPath = fileURLToPath(new URL('../scribe-worker/.dev.vars', import.meta.url));
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
	return { coordinatorTarget };
}

export default defineConfig(({ command }) => {
	const { coordinatorTarget } =
		command === 'serve' ? devVarsLift() : { coordinatorTarget: undefined };

	return {
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
	};
});
