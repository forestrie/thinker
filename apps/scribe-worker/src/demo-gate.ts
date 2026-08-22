/**
 * Demo gate — one shared, well-known password in front of the whole demo.
 *
 * This is NOT authentication and is not a security control. It exists to keep
 * bots and drive-by traffic off a public endpoint that spends Anthropic tokens.
 * The password will leak; the daily turn caps and the Anthropic workspace spend
 * limit are what actually bound the damage. Do not add anything to this file
 * that assumes otherwise.
 *
 * ## Why it passes on "Basic OR a valid session"
 *
 * A browser sends exactly ONE `Authorization` header, and an explicit header on
 * a `fetch()` overrides the credentials the browser would otherwise attach. In
 * this app that splits cleanly:
 *
 *   navigation + assets  → no explicit header → browser attaches `Basic`
 *   /auth/challenge|session → fetch with no header → browser attaches `Basic`
 *   /turn, /receipts, …  → fetch sets `Bearer <session>` → Basic is DROPPED
 *   /agents/… WebSocket  → no header at all; carries `?token=` instead
 *
 * So demanding Basic everywhere would break every authenticated API call, and
 * demanding it on the WebSocket handshake is not even possible from a browser.
 * Accepting *either* credential is what makes the gate coherent — and it loses
 * nothing, because a session can only be minted through `/auth/*`, which is
 * itself reachable only with the Basic credential.
 *
 * ## Turning it off
 *
 * Two ways, and the difference matters:
 *
 *   `DEMO_PASSWORD` unset   → open by absence. This is what makes a bare
 *                             `wrangler dev` work with no ceremony.
 *   `DEMO_GATE=off`         → open by INTENT, even with a password configured.
 *
 * The second exists because "unset" is not a statement — an integration test
 * cannot assert it, and a stray `DEMO_PASSWORD` in the ambient environment (a
 * copied `.dev.vars`, an exported shell var) silently closes the gate again and
 * the failure looks like a broken test rather than a config accident. `off` is
 * something a harness can set positively and a reader can grep for.
 *
 * Only the exact string `off` (trimmed, case-insensitive) disables the gate.
 * Anything else — `0`, `false`, a typo — is ignored and the gate stays up: the
 * unrecognised-value case must fail CLOSED, because this sits in front of an
 * endpoint that spends Anthropic tokens.
 *
 * `DEMO_GATE` is deliberately NOT on `deploy.yml`'s `--var` allowlist, so it
 * cannot reach a deployed Worker; the preflight also rejects it explicitly.
 * Deployed environments must set `DEMO_PASSWORD` — the preflight requires it.
 */
import { verifySession, type AuthEnv } from './auth.ts';

export interface DemoGateEnv extends AuthEnv {
	/** The shared demo password. Unset = gate open (local dev only). */
	DEMO_PASSWORD?: string;
	/**
	 * `off` disables the gate outright, even when DEMO_PASSWORD is set. Local
	 * dev and integration tests only — never set in a deployed environment.
	 */
	DEMO_GATE?: string;
}

/** True only for an explicit, unambiguous `off`. Everything else fails closed. */
function gateDisabled(env: DemoGateEnv): boolean {
	return env.DEMO_GATE?.trim().toLowerCase() === 'off';
}

const REALM = 'thinker demo';

/** Length-independent compare, so a wrong password leaks no timing signal. */
function constantTimeEquals(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return diff === 0;
}

/**
 * The password out of an `Authorization: Basic` header, or null. The username
 * half is ignored — there is only one credential and no notion of a user here.
 */
function basicPassword(request: Request): string | null {
	const encoded = request.headers.get('authorization')?.match(/^Basic\s+(.+)$/i)?.[1];
	if (!encoded) return null;
	let decoded: string;
	try {
		decoded = atob(encoded);
	} catch {
		return null;
	}
	const colon = decoded.indexOf(':');
	return colon < 0 ? decoded : decoded.slice(colon + 1);
}

/**
 * Returns a 401 challenge when the request should be turned away, or null to
 * let it through.
 */
export async function demoGate(request: Request, env: DemoGateEnv): Promise<Response | null> {
	if (gateDisabled(env)) return null;

	const password = env.DEMO_PASSWORD;
	if (!password) return null;

	const supplied = basicPassword(request);
	if (supplied !== null && constantTimeEquals(supplied, password)) return null;

	// Already inside: an unexpired session can only have come from /auth/*,
	// which is itself behind the Basic credential.
	if (await verifySession(request, env)) return null;

	return new Response('This demo is password protected.\n', {
		status: 401,
		headers: {
			'WWW-Authenticate': `Basic realm="${REALM}", charset="UTF-8"`,
			'Content-Type': 'text/plain; charset=utf-8'
		}
	});
}

/**
 * Strip the demo credential before a request is forwarded onward (to the UI
 * worker or the coordinator). The gate consumes it; nothing downstream should
 * ever see it, and leaving it on would collide with the session bearer.
 */
export function withoutDemoCredential(request: Request): Request {
	if (!request.headers.get('authorization')?.match(/^Basic\s/i)) return request;
	const forwarded = new Request(request);
	forwarded.headers.delete('authorization');
	return forwarded;
}
