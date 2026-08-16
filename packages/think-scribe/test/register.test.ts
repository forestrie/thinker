/**
 * The SCRAPI 303 contract, driven entirely through the injectable `fetchImpl`.
 * No network, no lane — every wire fact the client depends on (the POST shape,
 * the Location/Retry-After handling, the 404-means-unsealed rule) is asserted
 * against a stub.
 */
import { describe, expect, it, vi } from 'vitest';
import {
	ScrapiError,
	fetchReceipt,
	queryRegistration,
	registerStatement
} from '../src/forestrie/register.ts';

const BASE = 'https://api-a.example.test';
const ROOT = '3d7188d0-94a0-5560-965c-eaf2d1d683f0';
const ENTRY = 'a'.repeat(32);
const STATEMENT = new Uint8Array([0xd2, 0x84, 0x41, 0xa0]);

/** A stub fetch returning one canned response, recording the call. */
function stub(response: Response) {
	return vi.fn<typeof fetch>().mockResolvedValue(response);
}

const problem = (status: number, body = 'boom') =>
	new Response(new TextEncoder().encode(body), { status });

describe('registerStatement', () => {
	it('POSTs the COSE bytes to /register/{R}/entries with the grant credential', async () => {
		const fetchImpl = stub(
			new Response(null, { status: 303, headers: { Location: `${BASE}/status/xyz` } })
		);
		await registerStatement(BASE, ROOT, STATEMENT, 'GRANTB64', fetchImpl);

		expect(fetchImpl).toHaveBeenCalledOnce();
		const [url, init] = fetchImpl.mock.calls[0]!;
		expect(url).toBe(`${BASE}/register/${ROOT}/entries`);
		expect(init?.method).toBe('POST');
		expect(init?.redirect).toBe('manual');
		expect((init?.headers as Record<string, string>)['Content-Type']).toBe('application/cose');
		expect((init?.headers as Record<string, string>).Authorization).toBe(
			'Forestrie-Grant GRANTB64'
		);
	});

	it('returns the Location as statusUrl and sha256(statement) as contentHash', async () => {
		const fetchImpl = stub(
			new Response(null, { status: 303, headers: { Location: `${BASE}/status/xyz` } })
		);
		const accepted = await registerStatement(BASE, ROOT, STATEMENT, 'g', fetchImpl);

		expect(accepted.statusUrl).toBe(`${BASE}/status/xyz`);
		const expected = [...new Uint8Array(await crypto.subtle.digest('SHA-256', STATEMENT))]
			.map((b) => b.toString(16).padStart(2, '0'))
			.join('');
		expect(accepted.contentHash).toBe(expected);
	});

	it('throws on a 303 with no Location header', async () => {
		const fetchImpl = stub(new Response(null, { status: 303 }));
		await expect(registerStatement(BASE, ROOT, STATEMENT, 'g', fetchImpl)).rejects.toThrow(
			/303 without Location/
		);
	});

	it('throws ScrapiError carrying the status and problem detail on a non-303', async () => {
		const fetchImpl = stub(problem(403, 'grant not accepted'));
		const error = await registerStatement(BASE, ROOT, STATEMENT, 'g', fetchImpl).catch((e) => e);

		expect(error).toBeInstanceOf(ScrapiError);
		expect(error.status).toBe(403);
		expect(error.detail).toBe('grant not accepted');
	});

	it('scrubs control bytes out of a problem+cbor body', async () => {
		const body = new Uint8Array([0xa1, 0x00, 0x65, ...new TextEncoder().encode('oops'), 0x01]);
		const fetchImpl = stub(new Response(body, { status: 400 }));
		const error = await registerStatement(BASE, ROOT, STATEMENT, 'g', fetchImpl).catch((e) => e);
		expect(error.detail).toContain('oops');
		expect(error.detail).not.toMatch(/[^\x20-\x7e]/);
	});

	it('falls back to statusText when the body has nothing printable', async () => {
		const fetchImpl = stub(
			new Response(new Uint8Array([0x00, 0x01]), { status: 500, statusText: 'Server Error' })
		);
		const error = await registerStatement(BASE, ROOT, STATEMENT, 'g', fetchImpl).catch((e) => e);
		expect(error.detail).toBe('Server Error');
	});
});

describe('queryRegistration', () => {
	it('reports sequenced when Location points at a receipt URL', async () => {
		const receiptUrl = `${BASE}/v1/mmrs/14/entries/${ENTRY}/receipt`;
		const fetchImpl = stub(new Response(null, { status: 303, headers: { Location: receiptUrl } }));
		const status = await queryRegistration(`${BASE}/status/xyz`, fetchImpl);

		expect(status).toEqual({ state: 'sequenced', receiptUrl, entryId: ENTRY });
	});

	it('reports pending with the Retry-After delay on a self-303', async () => {
		const self = `${BASE}/status/xyz`;
		const fetchImpl = stub(
			new Response(null, { status: 303, headers: { Location: self, 'Retry-After': '5' } })
		);
		expect(await queryRegistration(self, fetchImpl)).toEqual({
			state: 'pending',
			retryAfterSeconds: 5
		});
	});

	it('defaults the retry delay to 1s when Retry-After is absent or unparseable', async () => {
		const self = `${BASE}/status/xyz`;
		const cases: Record<string, string>[] = [
			{ Location: self },
			{ Location: self, 'Retry-After': 'soon' }
		];
		for (const headers of cases) {
			const fetchImpl = stub(new Response(null, { status: 303, headers }));
			const status = await queryRegistration(self, fetchImpl);
			expect(status).toEqual({ state: 'pending', retryAfterSeconds: 1 });
		}
	});

	it('treats a missing Location as pending against the same URL', async () => {
		const self = `${BASE}/status/xyz`;
		const fetchImpl = stub(new Response(null, { status: 303 }));
		expect(await queryRegistration(self, fetchImpl)).toEqual({
			state: 'pending',
			retryAfterSeconds: 1
		});
	});

	it('throws ScrapiError on a non-303', async () => {
		const fetchImpl = stub(problem(410, 'gone'));
		await expect(queryRegistration(`${BASE}/status/xyz`, fetchImpl)).rejects.toBeInstanceOf(
			ScrapiError
		);
	});
});

describe('fetchReceipt', () => {
	it('reports pending on 404 — the checkpoint is not sealed yet (T9)', async () => {
		const fetchImpl = stub(new Response(null, { status: 404 }));
		expect(await fetchReceipt(`${BASE}/receipt`, fetchImpl)).toEqual({ state: 'pending' });
	});

	it('returns the receipt bytes and content type on 200', async () => {
		const bytes = new Uint8Array([1, 2, 3, 4]);
		const fetchImpl = stub(
			new Response(bytes, { status: 200, headers: { 'Content-Type': 'application/cbor' } })
		);
		const status = await fetchReceipt(`${BASE}/receipt`, fetchImpl);

		expect(status).toEqual({
			state: 'ready',
			receipt: bytes,
			contentType: 'application/cbor'
		});
	});

	it('throws ScrapiError on a 500', async () => {
		const fetchImpl = stub(problem(500, 'upstream'));
		await expect(fetchReceipt(`${BASE}/receipt`, fetchImpl)).rejects.toBeInstanceOf(ScrapiError);
	});
});
