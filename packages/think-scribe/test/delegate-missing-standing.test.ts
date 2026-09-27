/**
 * When the coordinator's pending-delegation offers no standing sealer entry,
 * the helper explains WHICH of the two C3 preconditions is missing instead
 * of the combined "register a public root and a sealer delegate key first":
 * one public GET of the log's public-root separates a log the coordinator
 * has never seen (404 — the demo's stale-forest case) from a lane whose
 * sealer key is not registered yet (root present). A failed probe keeps the
 * combined message, so the diagnosis never masks the original failure.
 */
import { describe, expect, it } from 'vitest';
import { delegateSealing, DelegateError } from '../src/forestrie/delegate.ts';
import type { KeyProvider } from '../src/keys/provider.ts';

const LOG_ID = '6a00599c-5942-4bf7-8c58-c5a4e3b360cd';
const COORDINATOR = 'https://coordinator.test';
// Any 64 bytes: the voucher check is never reached without a standing entry.
const KNOWN_SEALER_KEY_B64 = btoa(String.fromCharCode(...new Uint8Array(64)));

async function keys(): Promise<KeyProvider> {
	const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
		'sign',
		'verify'
	])) as CryptoKeyPair;
	return {
		kid: () => new Uint8Array(16),
		publicKeyXY: async () => new Uint8Array(64),
		signingKeyPair: async () => pair
	} as unknown as KeyProvider;
}

/** A coordinator with no standing entry whose public-root answers `rootStatus`. */
function coordinator(rootStatus: number | 'throw') {
	const calls: string[] = [];
	const fetchImpl = (async (input: RequestInfo | URL) => {
		const url = String(input);
		calls.push(url);
		if (url === `${COORDINATOR}/api/logs/${LOG_ID}/pending-delegation`)
			return Response.json({ entries: [], limit: 32 });
		if (url === `${COORDINATOR}/api/logs/${LOG_ID}/public-root`) {
			if (rootStatus === 'throw') throw new TypeError('network down');
			return new Response(rootStatus === 200 ? new Uint8Array([0xa0]) : 'not found', {
				status: rootStatus
			});
		}
		throw new Error(`unexpected fetch ${url}`);
	}) as typeof fetch;
	return { calls, fetchImpl };
}

async function failure(
	rootStatus: number | 'throw'
): Promise<{ err: DelegateError; calls: string[] }> {
	const { calls, fetchImpl } = coordinator(rootStatus);
	try {
		await delegateSealing(
			await keys(),
			{ coordinatorUrl: COORDINATOR, logId: LOG_ID, knownSealerKeyB64: KNOWN_SEALER_KEY_B64 },
			fetchImpl
		);
	} catch (err) {
		expect(err).toBeInstanceOf(DelegateError);
		return { err: err as DelegateError, calls };
	}
	throw new Error('delegateSealing resolved without a standing entry');
}

describe('resolveStanding without a standing entry', () => {
	it('names the log as unregistered when the coordinator has no public root (404)', async () => {
		const { err, calls } = await failure(404);
		expect(err.message).toContain(`log ${LOG_ID} is not registered with the coordinator`);
		expect(err.message).toContain('no public root');
		expect(err.message).not.toContain('sealer delegate key first');
		expect(err.httpStatus).toBe(404);
		// Exactly one extra request, and only after pending-delegation came back empty.
		expect(calls).toEqual([
			`${COORDINATOR}/api/logs/${LOG_ID}/pending-delegation`,
			`${COORDINATOR}/api/logs/${LOG_ID}/public-root`
		]);
	});

	it('blames the missing sealer key when the public root is registered', async () => {
		const { err } = await failure(200);
		expect(err.message).toContain('has a public root');
		expect(err.message).toContain('no live sealer delegate key');
		expect(err.httpStatus).toBeUndefined();
	});

	it('keeps the combined message when the public-root probe fails', async () => {
		for (const status of [500, 'throw'] as const) {
			const { err } = await failure(status);
			expect(err.message).toBe(
				'delegate: no standing delegate-key entry for log — register a public root and a sealer delegate key first'
			);
		}
	});
});
