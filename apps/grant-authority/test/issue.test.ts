/**
 * Issuance, driven entirely through a stub fetch — no lane, no network.
 *
 * The resume path is the point of these tests. It is the only genuinely NEW
 * logic in the authority port (everything else is a translation), and its
 * failure mode is expensive and silent: time out after the lane accepted a
 * registration, retry naively, and you have orphaned a log and — on a paid lane
 * — burned a payment, while the client sees only a slow grant.
 */
import { describe, expect, it, vi } from 'vitest';
import { createPrivateKey, generateKeyPairSync } from 'node:crypto';
import {
	IssuancePending,
	PaymentRequired,
	issueCreationGrant,
	type IssuanceAuthority,
	type IssueContext
} from '../src/issue.ts';
import { importAuthorityKey } from '../src/sign-grant.ts';
import { memoryIssuerStore, type IssuerStore } from '../src/state.ts';

const BASE = 'https://api-a.example.test';
const ROOT = '3d7188d0-94a0-5560-965c-eaf2d1d683f0';
const ENTRY = 'ab'.repeat(16);
const AUTHORITY: IssuanceAuthority = {
	logId: 'f72af27c-8a0a-4ff6-ae99-b48862c8954d',
	grantB64: btoa('parent-grant-bytes')
};

async function makeContext(
	fetchImpl: typeof fetch,
	store: IssuerStore = memoryIssuerStore()
): Promise<IssueContext> {
	const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
	const jwk = createPrivateKey(
		privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
	).export({ format: 'jwk' });
	const keys = await importAuthorityKey(JSON.stringify(jwk));
	return { baseUrl: BASE, rootLogId: ROOT, privateKey: keys.privateKey, store, fetchImpl };
}

const registerAccepted = () =>
	new Response(null, { status: 303, headers: { Location: `${BASE}/status/xyz` } });
// Shape dictated by scrapi-client's RECEIPT_LOCATION_RE:
//   /logs/<log>/<store>/<massifHeight>/entries/<32 hex>/receipt
const RECEIPT_URL = `${BASE}/logs/${ROOT}/mmrs/14/entries/${ENTRY}/receipt`;
const sequenced = () => new Response(null, { status: 303, headers: { Location: RECEIPT_URL } });
const receiptReady = () =>
	new Response(new Uint8Array([0xd2, 0x84, 0x40]), {
		status: 200,
		headers: { 'Content-Type': 'application/cbor' }
	});

describe('happy path', () => {
	it('registers, waits out sequencing and the seal, and completes the grant', async () => {
		const fetchImpl = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(registerAccepted())
			.mockResolvedValueOnce(sequenced())
			.mockResolvedValueOnce(receiptReady());

		const ctx = await makeContext(fetchImpl);
		const issued = await issueCreationGrant(
			ctx,
			AUTHORITY,
			'agent',
			'kid-1',
			new Uint8Array(64).fill(3),
			0
		);

		expect(issued.logId).toMatch(/^[0-9a-f-]{36}$/);
		expect(issued.grantB64.length).toBeGreaterThan(0);

		const [url, init] = fetchImpl.mock.calls[0]!;
		expect(url).toBe(`${BASE}/register/${ROOT}/grants`);
		expect(init?.method).toBe('POST');
		expect(init?.redirect).toBe('manual');
		expect((init?.headers as Record<string, string>)['Content-Type']).toBe('application/cbor');
	});

	it('clears the in-flight record once the receipt is in hand', async () => {
		const store = memoryIssuerStore();
		const ctx = await makeContext(
			vi
				.fn<typeof fetch>()
				.mockResolvedValueOnce(registerAccepted())
				.mockResolvedValueOnce(sequenced())
				.mockResolvedValueOnce(receiptReady()),
			store
		);

		await issueCreationGrant(ctx, AUTHORITY, 'agent', 'kid-1', new Uint8Array(64), 0);
		expect(await store.getInFlight('agent', 'kid-1')).toBeNull();
	});

	it('stamps maxHeight on a user grant and leaves agent grants unbounded', async () => {
		const mk = () =>
			vi
				.fn<typeof fetch>()
				.mockResolvedValueOnce(registerAccepted())
				.mockResolvedValueOnce(sequenced())
				.mockResolvedValueOnce(receiptReady());

		const user = await issueCreationGrant(
			await makeContext(mk()),
			AUTHORITY,
			'user',
			'0xabc',
			new Uint8Array(20),
			16
		);
		expect(user.maxHeight).toBe(16);

		const agent = await issueCreationGrant(
			await makeContext(mk()),
			AUTHORITY,
			'agent',
			'kid-2',
			new Uint8Array(64),
			0
		);
		expect(agent.maxHeight).toBe(0);
	});
});

describe('the x402 gate', () => {
	it('surfaces the challenge and does NOT record an in-flight registration', async () => {
		const store = memoryIssuerStore();
		const ctx = await makeContext(
			vi
				.fn<typeof fetch>()
				.mockResolvedValue(
					new Response(null, { status: 402, headers: { 'x-payment-required': 'CHALLENGE' } })
				),
			store
		);

		const error = await issueCreationGrant(
			ctx,
			AUTHORITY,
			'user',
			'0xabc',
			new Uint8Array(20),
			16
		).catch((e) => e);

		expect(error).toBeInstanceOf(PaymentRequired);
		expect(error.challengeB64).toBe('CHALLENGE');
		// Nothing was accepted by the lane, so there is nothing to resume — and a
		// stale record here would make the paid resubmit skip registration.
		expect(await store.getInFlight('user', '0xabc')).toBeNull();
	});

	it('throws when the 402 carries no challenge header', async () => {
		const ctx = await makeContext(
			vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 402 }))
		);
		await expect(
			issueCreationGrant(ctx, AUTHORITY, 'user', '0xabc', new Uint8Array(20), 16)
		).rejects.toThrow(/without X-PAYMENT-REQUIRED/);
	});

	it('forwards X-PAYMENT on the paid resubmit', async () => {
		const fetchImpl = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(registerAccepted())
			.mockResolvedValueOnce(sequenced())
			.mockResolvedValueOnce(receiptReady());

		const ctx = await makeContext(fetchImpl);
		await issueCreationGrant(ctx, AUTHORITY, 'user', '0xabc', new Uint8Array(20), 16, 'PAYMENT');

		expect((fetchImpl.mock.calls[0]![1]?.headers as Record<string, string>)['X-PAYMENT']).toBe(
			'PAYMENT'
		);
	});
});

describe('resume after a deadline', () => {
	it('persists the in-flight registration BEFORE polling', async () => {
		// Register succeeds, then sequencing never resolves — the deadline hits.
		const store = memoryIssuerStore();
		const ctx = await makeContext(
			vi
				.fn<typeof fetch>()
				.mockResolvedValueOnce(registerAccepted())
				.mockResolvedValue(new Response(null, { status: 303 })), // self-303, pending forever
			store
		);

		vi.useFakeTimers();
		const inflight = issueCreationGrant(ctx, AUTHORITY, 'agent', 'kid-1', new Uint8Array(64), 0);
		const settled = expect(inflight).rejects.toBeInstanceOf(IssuancePending);
		await vi.advanceTimersByTimeAsync(70_000);
		await settled;
		vi.useRealTimers();

		const record = await store.getInFlight('agent', 'kid-1');
		expect(record).not.toBeNull();
		expect(record!.statusUrl).toBe(`${BASE}/status/xyz`);
		expect(record!.logId).toMatch(/^[0-9a-f-]{36}$/);
	});

	it('a retry RESUMES the same registration instead of minting a second grant', async () => {
		const store = memoryIssuerStore();

		// First attempt: accepted, then times out waiting for sequencing.
		const first = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(registerAccepted())
			.mockResolvedValue(new Response(null, { status: 303 }));
		const ctxA = await makeContext(first, store);

		vi.useFakeTimers();
		const pending = issueCreationGrant(ctxA, AUTHORITY, 'user', '0xabc', new Uint8Array(20), 16);
		const settled = expect(pending).rejects.toBeInstanceOf(IssuancePending);
		await vi.advanceTimersByTimeAsync(70_000);
		await settled;
		vi.useRealTimers();

		const logIdBefore = (await store.getInFlight('user', '0xabc'))!.logId;

		// Second attempt: the lane has caught up.
		const second = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(sequenced())
			.mockResolvedValueOnce(receiptReady());
		const ctxB = await makeContext(second, store);

		const issued = await issueCreationGrant(
			ctxB,
			AUTHORITY,
			'user',
			'0xabc',
			new Uint8Array(20),
			16
		);

		// THE assertion: same log, and no second POST to /register.
		expect(issued.logId).toBe(logIdBefore);
		for (const [url] of second.mock.calls) {
			expect(String(url)).not.toContain('/register/');
		}
		expect(await store.getInFlight('user', '0xabc')).toBeNull();
	});

	it('keeps the purchased maxHeight across a resume', async () => {
		const store = memoryIssuerStore();
		const ctxA = await makeContext(
			vi
				.fn<typeof fetch>()
				.mockResolvedValueOnce(registerAccepted())
				.mockResolvedValue(new Response(null, { status: 303 })),
			store
		);

		vi.useFakeTimers();
		const pending = issueCreationGrant(ctxA, AUTHORITY, 'user', '0xabc', new Uint8Array(20), 16);
		const settled = expect(pending).rejects.toBeInstanceOf(IssuancePending);
		await vi.advanceTimersByTimeAsync(70_000);
		await settled;
		vi.useRealTimers();

		const ctxB = await makeContext(
			vi
				.fn<typeof fetch>()
				.mockResolvedValueOnce(sequenced())
				.mockResolvedValueOnce(receiptReady()),
			store
		);
		// Resume passes 0, but the purchased ceiling must survive from the record.
		const issued = await issueCreationGrant(
			ctxB,
			AUTHORITY,
			'user',
			'0xabc',
			new Uint8Array(20),
			0
		);
		expect(issued.maxHeight).toBe(16);
	});
});

describe('lane errors', () => {
	it('propagates a sequencing error rather than retrying forever', async () => {
		const ctx = await makeContext(
			vi
				.fn<typeof fetch>()
				.mockResolvedValueOnce(registerAccepted())
				.mockResolvedValueOnce(new Response(new TextEncoder().encode('rejected'), { status: 400 }))
		);
		await expect(
			issueCreationGrant(ctx, AUTHORITY, 'agent', 'kid-1', new Uint8Array(64), 0)
		).rejects.toThrow();
	});
});
