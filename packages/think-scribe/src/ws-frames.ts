/**
 * Which frames a client may send over the agent WebSocket.
 *
 * A leaf module on purpose: `scribe.ts` transitively imports
 * `cloudflare:workers`, which cannot load outside workerd, so keeping this
 * dependency-free is what lets it be unit-tested on plain Node.
 *
 * Think accepts `cf_agent_use_chat_request` over the socket and feeds the
 * client's `messages` array straight to the model, bypassing the signed
 * envelope, `workId`, the prepaid-turn decrement, the daily cap and the whole
 * attestation path — an unmetered, unattested turn from a browser console.
 * `cf_agent_chat_clear` wipes the transcript that `GET /receipts` checks the
 * committed `outputHash` against, which is the exact check the tamper beat
 * demonstrates. Neither is on the list below.
 */

/**
 * The browser client sends exactly these two: a resume probe on connect and its
 * ACK (`apps/scribe-ui/src/lib/chat.svelte.ts:168, :228`). Turns enter via
 * `POST /turn` with a signed envelope. An allowlist rather than a denylist
 * because that surface is small and known, and because a denylist silently
 * fails open every time the SDK adds a frame type.
 */
export const PERMITTED_CLIENT_FRAMES: ReadonlySet<string> = new Set([
	'cf_agent_stream_resume_request',
	'cf_agent_stream_resume_ack'
]);

/**
 * True when a raw socket frame is one the client is allowed to send.
 *
 * A frame that is not JSON, or carries no string `type`, is not a protocol
 * event — Think's own `parseProtocolMessage` returns null for it and falls
 * through to the base handler — so it passes rather than being dropped. Only
 * well-formed protocol frames are held to the allowlist.
 */
export function isPermittedClientFrame(message: string): boolean {
	let parsed: unknown;
	try {
		parsed = JSON.parse(message);
	} catch {
		return true;
	}
	if (!parsed || typeof parsed !== 'object') return true;
	const type = (parsed as { type?: unknown }).type;
	if (typeof type !== 'string') return true;
	return PERMITTED_CLIENT_FRAMES.has(type);
}
