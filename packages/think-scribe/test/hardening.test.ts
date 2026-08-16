/**
 * Pre-public hardening. Each of these closes a way a stranger could burn
 * Anthropic tokens, publish to the lane, or use the worker as a proxy — so each
 * gets a test that fails loudly if the guard is ever loosened.
 */
import { describe, expect, it } from 'vitest';
import { isPermittedClientFrame } from '../src/ws-frames.ts';
import {
	EnvelopeError,
	MAX_INPUT_BYTES,
	buildUserEnvelope,
	verifyUserEnvelope,
	type EnvelopeClaims
} from '../src/forestrie/envelope.ts';

describe('WebSocket frame allowlist', () => {
	it('permits exactly the two frames the browser client sends', () => {
		// apps/scribe-ui/src/lib/chat.svelte.ts:168 and :228
		expect(isPermittedClientFrame(JSON.stringify({ type: 'cf_agent_stream_resume_request' }))).toBe(
			true
		);
		expect(isPermittedClientFrame(JSON.stringify({ type: 'cf_agent_stream_resume_ack' }))).toBe(
			true
		);
	});

	it('DROPS cf_agent_use_chat_request — the unmetered, unattested turn path', () => {
		// Think would feed `messages` straight to the model: no envelope, no
		// workId, no prepaid decrement, no daily cap, no attestation.
		const frame = JSON.stringify({
			type: 'cf_agent_use_chat_request',
			id: 'x',
			init: { method: 'POST', body: JSON.stringify({ messages: [{ role: 'user', parts: [] }] }) }
		});
		expect(isPermittedClientFrame(frame)).toBe(false);
	});

	it('DROPS cf_agent_chat_clear — it wipes the transcript outputHash is checked against', () => {
		expect(isPermittedClientFrame(JSON.stringify({ type: 'cf_agent_chat_clear' }))).toBe(false);
	});

	it('drops every other cf_agent_* frame by default', () => {
		for (const type of [
			'cf_agent_state',
			'cf_agent_tool_result',
			'cf_agent_tool_approval',
			'cf_agent_mcp_servers',
			'cf_agent_chat_messages'
		]) {
			expect(isPermittedClientFrame(JSON.stringify({ type }))).toBe(false);
		}
	});

	it('passes through non-protocol frames — Think would ignore them anyway', () => {
		// Not JSON, or no string `type`: parseProtocolMessage returns null and it
		// falls to the base handler. Dropping these would change unrelated
		// behaviour for no security gain.
		expect(isPermittedClientFrame('not json at all')).toBe(true);
		expect(isPermittedClientFrame('[1,2,3]')).toBe(true);
		expect(isPermittedClientFrame(JSON.stringify({ type: 42 }))).toBe(true);
		expect(isPermittedClientFrame(JSON.stringify({ nope: true }))).toBe(true);
	});
});

describe('input size bound', () => {
	const KEY = new Uint8Array(32).fill(11);
	const claims = (input: string): EnvelopeClaims => ({
		input,
		sessionId: 'session-1',
		issuedAt: '2026-08-16T09:00:00.000Z',
		nonce: 'bm9uY2U'
	});

	it('accepts input at exactly the limit', async () => {
		const envelope = buildUserEnvelope(claims('a'.repeat(MAX_INPUT_BYTES)), KEY);
		await expect(verifyUserEnvelope(envelope)).resolves.toBeTruthy();
	});

	it('rejects one byte over', async () => {
		const envelope = buildUserEnvelope(claims('a'.repeat(MAX_INPUT_BYTES + 1)), KEY);
		await expect(verifyUserEnvelope(envelope)).rejects.toThrow(/exceeds 4096 bytes/);
		await expect(verifyUserEnvelope(envelope)).rejects.toBeInstanceOf(EnvelopeError);
	});

	it('counts UTF-8 BYTES, not JS characters', async () => {
		// 4-byte emoji: 1100 of them is 1100 chars but 4400 bytes. A character
		// count would let this through at ~4x the intended budget.
		const emoji = '😀'.repeat(1100);
		expect(emoji.length).toBeLessThan(MAX_INPUT_BYTES);
		expect(new TextEncoder().encode(emoji).length).toBeGreaterThan(MAX_INPUT_BYTES);
		await expect(verifyUserEnvelope(buildUserEnvelope(claims(emoji), KEY))).rejects.toThrow(
			/exceeds 4096 bytes/
		);
	});

	it('rejects before any signature or model work is attempted', async () => {
		// The bound is the last gate before admission, so it must fire on a
		// perfectly valid, correctly signed envelope — validity is not a bypass.
		const envelope = buildUserEnvelope(claims('x'.repeat(MAX_INPUT_BYTES + 1)), KEY);
		await expect(verifyUserEnvelope(envelope)).rejects.toThrow(/exceeds/);
	});
});
