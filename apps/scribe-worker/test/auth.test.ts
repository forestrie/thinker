/**
 * wcc-1 session auth. Two things here are load-bearing beyond ordinary
 * correctness:
 *
 *  1. `challengeMessage` is the literal text a wallet signs. Reformat it — even
 *     whitespace — and every deployed client breaks, silently, because the
 *     recovered address simply stops matching. Nothing else pins it.
 *  2. `DEV_AUTH=1` accepts `Bearer dev:<sub>` with no signature at all. That
 *     gate is the difference between a dev convenience and a production auth
 *     bypass, so it is tested from both sides.
 *
 * Runs on plain Node: auth.ts uses only crypto.subtle, Request/Response and
 * @noble. No DO storage, no workerd.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { challengeMessage, handleAuth, verifySession, type AuthEnv } from '../src/auth.ts';

const ENV: AuthEnv = { SESSION_HMAC_SECRET: 'test-secret-not-a-real-key' };
const WALLET = new Uint8Array(32).fill(3);

const BASE = 'https://scribe.example.test';

const post = (path: string, body?: unknown) =>
	new Request(`${BASE}${path}`, {
		method: 'POST',
		...(body === undefined ? {} : { body: JSON.stringify(body) })
	});

/** Sign the EIP-191 digest of `message` the way a wallet would: r‖s‖(v+27). */
function walletSign(message: string, privateKey = WALLET): string {
	const body = new TextEncoder().encode(message);
	const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
	const data = new Uint8Array(prefix.length + body.length);
	data.set(prefix);
	data.set(body, prefix.length);

	const recovered = secp256k1.sign(keccak_256(data), privateKey, {
		format: 'recovered',
		prehash: false
	});
	let out = '0x';
	for (const b of recovered.slice(1)) out += b.toString(16).padStart(2, '0');
	return out + (recovered[0]! + 27).toString(16).padStart(2, '0');
}

function walletAddress(privateKey = WALLET): string {
	const pub = secp256k1.getPublicKey(privateKey, false);
	const addr = keccak_256(pub.slice(1)).slice(-20);
	let out = '0x';
	for (const b of addr) out += b.toString(16).padStart(2, '0');
	return out;
}

afterEach(() => {
	vi.useRealTimers();
});

describe('challengeMessage — golden string', () => {
	it('renders the exact SIWE-shaped block the wallet signs', () => {
		const message = challengeMessage({
			v: 'wcc-1',
			domain: 'scribe.example.test',
			origin: 'https://scribe.example.test',
			scopes: ['scribe:chat'],
			nonce: 'AAAAAAAAAAAAAAAAAAAAAA',
			issuedAt: '2026-08-16T09:00:00.000Z',
			expiresAt: '2026-08-16T09:02:00.000Z'
		} as Parameters<typeof challengeMessage>[0]);

		expect(message).toBe(
			[
				'scribe.example.test wants you to sign in with your Ethereum account.',
				'',
				'Forestrie Scribe wcc-1 session challenge.',
				'',
				'URI: https://scribe.example.test',
				'Version: wcc-1',
				'Scopes: scribe:chat',
				'Nonce: AAAAAAAAAAAAAAAAAAAAAA',
				'Issued At: 2026-08-16T09:00:00.000Z',
				'Expiration Time: 2026-08-16T09:02:00.000Z'
			].join('\n')
		);
	});
});

describe('POST /auth/challenge', () => {
	it('issues a challenge with a 120s window and a 22-char nonce', async () => {
		const res = await handleAuth(post('/auth/challenge'), ENV);
		expect(res?.status).toBe(200);
		const body = (await res!.json()) as {
			challenge: string;
			message: string;
			expiresAt: string;
		};

		expect(body.challenge).toMatch(/^[\w-]+\.[\w-]+$/);
		expect(body.message).toContain('Forestrie Scribe wcc-1 session challenge.');

		const nonce = body.message.match(/^Nonce: (.+)$/m)?.[1];
		expect(nonce).toHaveLength(22);

		const issuedAt = body.message.match(/^Issued At: (.+)$/m)?.[1];
		expect(Date.parse(body.expiresAt) - Date.parse(issuedAt!)).toBe(120_000);
	});

	it('returns null for GET (not an auth route it handles)', async () => {
		expect(await handleAuth(new Request(`${BASE}/auth/challenge`), ENV)).toBeNull();
	});

	it('returns null for a non-auth path', async () => {
		expect(await handleAuth(post('/turn'), ENV)).toBeNull();
	});
});

describe('full choreography: challenge -> sign -> session', () => {
	async function mintSession() {
		const challengeRes = await handleAuth(post('/auth/challenge'), ENV);
		const { challenge, message } = (await challengeRes!.json()) as {
			challenge: string;
			message: string;
		};
		const res = await handleAuth(
			post('/auth/session', { challenge, signature: walletSign(message) }),
			ENV
		);
		return { res: res!, challenge, message };
	}

	it('mints a session for the recovered wallet with a 10-minute TTL', async () => {
		const { res } = await mintSession();
		expect(res.status).toBe(200);
		const body = (await res.json()) as { token: string; sub: string; exp: number };

		expect(body.sub).toBe(walletAddress());
		expect(body.exp - Date.now()).toBeGreaterThan(590_000);
		expect(body.exp - Date.now()).toBeLessThanOrEqual(600_000);
	});

	it('accepts the minted token on the Authorization header', async () => {
		const { res } = await mintSession();
		const { token } = (await res.json()) as { token: string };

		const request = new Request(`${BASE}/turn`, { headers: { authorization: `Bearer ${token}` } });
		expect(await verifySession(request, ENV)).toBe(walletAddress());
	});

	it('accepts the minted token as a ?token= query param (WebSocket connects)', async () => {
		const { res } = await mintSession();
		const { token } = (await res.json()) as { token: string };

		const request = new Request(`${BASE}/agents/scribe/user-x?token=${encodeURIComponent(token)}`);
		expect(await verifySession(request, ENV)).toBe(walletAddress());
	});

	it('prefers the header when both header and query param are present', async () => {
		const { res } = await mintSession();
		const { token } = (await res.json()) as { token: string };

		const request = new Request(`${BASE}/agents/scribe/user-x?token=garbage`, {
			headers: { authorization: `Bearer ${token}` }
		});
		expect(await verifySession(request, ENV)).toBe(walletAddress());
	});

	it('rejects a token whose MAC segment was tampered with', async () => {
		const { res } = await mintSession();
		const { token } = (await res.json()) as { token: string };

		const dot = token.indexOf('.');
		const mac = token.slice(dot + 1);
		const flipped = (mac[0] === 'A' ? 'B' : 'A') + mac.slice(1);
		const request = new Request(`${BASE}/turn`, {
			headers: { authorization: `Bearer ${token.slice(0, dot)}.${flipped}` }
		});
		expect(await verifySession(request, ENV)).toBeNull();
	});

	it('rejects a session minted under a different HMAC secret', async () => {
		const { res } = await mintSession();
		const { token } = (await res.json()) as { token: string };

		const request = new Request(`${BASE}/turn`, { headers: { authorization: `Bearer ${token}` } });
		expect(await verifySession(request, { SESSION_HMAC_SECRET: 'a-different-secret' })).toBeNull();
	});

	it('rejects a challenge opened under a different HMAC secret', async () => {
		const challengeRes = await handleAuth(post('/auth/challenge'), ENV);
		const { challenge, message } = (await challengeRes!.json()) as {
			challenge: string;
			message: string;
		};
		const res = await handleAuth(
			post('/auth/session', { challenge, signature: walletSign(message) }),
			{
				SESSION_HMAC_SECRET: 'a-different-secret'
			}
		);
		expect(res?.status).toBe(401);
		expect(await res!.text()).toBe('invalid challenge');
	});

	it('rejects an expired challenge', async () => {
		const challengeRes = await handleAuth(post('/auth/challenge'), ENV);
		const { challenge, message } = (await challengeRes!.json()) as {
			challenge: string;
			message: string;
		};

		// Past the 120s window — no real sleep.
		vi.useFakeTimers();
		vi.setSystemTime(Date.now() + 121_000);

		const res = await handleAuth(
			post('/auth/session', { challenge, signature: walletSign(message) }),
			ENV
		);
		expect(res?.status).toBe(401);
		expect(await res!.text()).toBe('challenge expired');
	});

	it('rejects a signature from a different wallet than the message expects', async () => {
		const challengeRes = await handleAuth(post('/auth/challenge'), ENV);
		const { challenge, message } = (await challengeRes!.json()) as {
			challenge: string;
			message: string;
		};
		// Signs a *different* message, so recovery yields some other address —
		// which still verifies structurally but is not this wallet.
		const res = await handleAuth(
			post('/auth/session', { challenge, signature: walletSign(message + 'x') }),
			ENV
		);
		const body = (await res!.json()) as { sub: string };
		expect(body.sub).not.toBe(walletAddress());
	});
});

describe('POST /auth/session — bad input', () => {
	it('400s on a non-JSON body', async () => {
		const res = await handleAuth(
			new Request(`${BASE}/auth/session`, { method: 'POST', body: 'not json' }),
			ENV
		);
		expect(res?.status).toBe(400);
	});

	it('400s when signature is missing', async () => {
		const res = await handleAuth(post('/auth/session', { challenge: 'x.y' }), ENV);
		expect(res?.status).toBe(400);
	});

	it('401s on a 128-char (too short) signature hex', async () => {
		const challengeRes = await handleAuth(post('/auth/challenge'), ENV);
		const { challenge } = (await challengeRes!.json()) as { challenge: string };
		const res = await handleAuth(
			post('/auth/session', { challenge, signature: `0x${'ab'.repeat(64)}` }),
			ENV
		);
		expect(res?.status).toBe(401);
		expect(await res!.text()).toBe('signature does not verify');
	});
});

describe('DEV_AUTH bearer gate', () => {
	const devRequest = (sub: string) =>
		new Request(`${BASE}/turn`, { headers: { authorization: `Bearer dev:${sub}` } });

	it('is REJECTED when DEV_AUTH is unset — the deployed posture', async () => {
		expect(await verifySession(devRequest('0xabc'), ENV)).toBeNull();
	});

	it('is rejected when DEV_AUTH is any value other than "1"', async () => {
		const env: AuthEnv = { ...ENV, DEV_AUTH: 'true' };
		expect(await verifySession(devRequest('0xabc'), env)).toBeNull();
	});

	it('is accepted when DEV_AUTH=1', async () => {
		const env: AuthEnv = { ...ENV, DEV_AUTH: '1' };
		expect(await verifySession(devRequest('0xABC'), env)).toBe('0xabc');
	});

	it('rejects a dev sub containing characters outside the principal grammar', async () => {
		const env: AuthEnv = { ...ENV, DEV_AUTH: '1' };
		for (const bad of ['a/b', 'a@b', '', '-leading']) {
			expect(await verifySession(devRequest(bad), env)).toBeNull();
		}
	});
});

describe('verifySession — no credential', () => {
	it('returns null when neither header nor query param is present', async () => {
		expect(await verifySession(new Request(`${BASE}/turn`), ENV)).toBeNull();
	});

	it('returns null for a malformed token with no dot separator', async () => {
		const request = new Request(`${BASE}/turn`, { headers: { authorization: 'Bearer nodot' } });
		expect(await verifySession(request, ENV)).toBeNull();
	});
});
