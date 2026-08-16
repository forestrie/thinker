import { routeAgentRequest } from 'agents';
import { PRINCIPAL_HEADER, Scribe } from '@forestrie/think-scribe';
import { handleAuth, verifySession } from './auth.ts';
import { demoGate, withoutDemoCredential } from './demo-gate.ts';

// The DO class the wrangler binding + migration refer to.
export { Scribe };

/**
 * This worker is the demo's SINGLE PUBLIC ORIGIN. Everything the browser talks
 * to is same-origin, which is what removes the CORS surface entirely and gives
 * the demo password one place to live.
 *
 *   /auth/*, /turn, /receipts, /identity, /pay-user-grant  → handled here
 *   /agents/*                → handled here, natively; the WebSocket upgrade
 *                              belongs to the worker that owns the Scribe DO,
 *                              so it is never proxied
 *   /coordinator/*           → proxied to the delegation coordinator, which
 *                              serves no CORS headers of its own
 *   everything else          → the SvelteKit UI, over a service binding
 *
 * The UI and the grant authority are deployed with `workers_dev: false` and are
 * reachable only through their service bindings. If either is publicly
 * addressable, the demo gate is decoration.
 *
 * (The obvious alternative — UI in front, proxying to here — is not buildable:
 * @sveltejs/adapter-cloudflare overwrites whatever `main` points at on every
 * build, so there is nowhere to put a custom entry, and routing the WebSocket
 * through SvelteKit's `handle` hook would rely on `respond()` preserving a
 * `webSocket`-bearing Response, which it does not promise.)
 */

/**
 * Option B per-user routing (plan §4): the instance name is `user-<sub>`
 * where `sub` is the wcc-1-verified principal. partyserver computes the DO
 * id from the URL segment BEFORE onBeforeConnect/onBeforeRequest run, so
 * the gate cannot rewrite the name — instead the client addresses
 * `/agents/scribe/user-<sub>` itself and the gate ENFORCES that the name
 * matches the verified session (403 otherwise). Nobody can reach an
 * instance they don't own; the DO additionally binds the principal on
 * first touch. Never put "/" in a name (agents#379 silently truncates).
 */
function gate(env: Env) {
	return async (req: Request, lobby: { name: string }) => {
		const sub = await verifySession(req, env);
		if (!sub) return new Response('Unauthorized', { status: 401 });
		if (lobby.name !== `user-${sub}`)
			return new Response('Forbidden: instance is not yours', { status: 403 });
		// Forward the verified principal; drop the credentials so they don't
		// outlive the edge (the ?token= variant is also stripped from the URL).
		const url = new URL(req.url);
		url.searchParams.delete('token');
		const fwd = new Request(url, req);
		fwd.headers.set(PRINCIPAL_HEADER, sub);
		fwd.headers.delete('authorization');
		return fwd;
	};
}

/**
 * Same-origin passthrough to the delegation coordinator. The browser cannot
 * call it directly — canopy's coordinator serves no CORS headers — so the
 * sealing-delegation step needs this hop. `vite.config.ts` does the identical
 * rewrite for `vite dev`, so dev and deployed behave the same.
 *
 * The target comes from config, never from the request, so this is not an open
 * proxy.
 */
async function proxyCoordinator(request: Request, env: Env, url: URL): Promise<Response> {
	const base = env.DELEGATION_COORDINATOR_URL;
	if (!base) return new Response('coordinator not configured', { status: 503 });
	const target = new URL(
		`${url.pathname.slice('/coordinator'.length)}${url.search}`,
		base.endsWith('/') ? base : `${base}/`
	);
	return fetch(new Request(target, withoutDemoCredential(request)));
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		// Before anything else, and before any Anthropic token can be spent.
		const challenge = await demoGate(request, env);
		if (challenge) return challenge;

		const authResponse = await handleAuth(request, env);
		if (authResponse) return authResponse;

		const url = new URL(request.url);
		if (url.pathname === '/coordinator' || url.pathname.startsWith('/coordinator/'))
			return proxyCoordinator(request, env, url);

		const g = gate(env);
		const agentResponse = await routeAgentRequest(request, env, {
			onBeforeConnect: g,
			onBeforeRequest: g
		});
		if (agentResponse) return agentResponse;

		// Not an API route — hand it to the UI. Service binding, so the UI never
		// needs a public hostname of its own.
		if (env.UI) return env.UI.fetch(withoutDemoCredential(request));
		return new Response('Not found', { status: 404 });
	}
} satisfies ExportedHandler<Env>;
