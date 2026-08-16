/**
 * The demo gate. Not a security control — a bot deterrent — but the pass/deny
 * rule is subtle enough to be worth pinning, because getting it wrong either
 * locks legitimate API calls out or leaves the front door open.
 *
 * The rule is "Basic OR a valid session", and both halves are load-bearing:
 * browsers attach the cached Basic credential to navigations and to header-less
 * fetches, but an explicit `Authorization: Bearer` on a fetch overrides it, and
 * a WebSocket handshake carries no Authorization header at all.
 */
import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { demoGate, withoutDemoCredential, type DemoGateEnv } from '../src/demo-gate.ts';
import { handleAuth } from '../src/auth.ts';

const BASE = 'https://thinker-dev.example.test';
const PASSWORD = 'correct-horse-battery-staple';
const ENV: DemoGateEnv = {
	SESSION_HMAC_SECRET: 'test-secret-not-a-real-key',
	DEMO_PASSWORD: PASSWORD
};
const WALLET = new Uint8Array(32).fill(5);

const basic = (password: string, user = '') => `Basic ${btoa(`${user}:${password}`)}`;

/** Mint a real session the way the browser does, so the OR-branch is genuine. */
async function mintSession(): Promise<string> {
	const challengeRes = await handleAuth(
		new Request(`${BASE}/auth/challenge`, { method: 'POST' }),
		ENV
	);
	const { challenge, message } = (await challengeRes!.json()) as {
		challenge: string;
		message: string;
	};

	const body = new TextEncoder().encode(message);
	const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
	const data = new Uint8Array(prefix.length + body.length);
	data.set(prefix);
	data.set(body, prefix.length);
	const recovered = secp256k1.sign(keccak_256(data), WALLET, {
		format: 'recovered',
		prehash: false
	});
	let signature = '0x';
	for (const b of recovered.slice(1)) signature += b.toString(16).padStart(2, '0');
	signature += (recovered[0]! + 27).toString(16).padStart(2, '0');

	const sessionRes = await handleAuth(
		new Request(`${BASE}/auth/session`, {
			method: 'POST',
			body: JSON.stringify({ challenge, signature })
		}),
		ENV
	);
	return ((await sessionRes!.json()) as { token: string }).token;
}

describe('challenge', () => {
	it('401s with a Basic WWW-Authenticate when no credential is present', async () => {
		const res = await demoGate(new Request(`${BASE}/`), ENV);
		expect(res?.status).toBe(401);
		expect(res?.headers.get('WWW-Authenticate')).toMatch(/^Basic realm="thinker demo"/);
	});

	it('challenges the UI, the auth routes and the WebSocket path alike', async () => {
		for (const path of [
			'/',
			'/_app/immutable/x.js',
			'/auth/challenge',
			'/agents/scribe/user-0xa'
		]) {
			expect((await demoGate(new Request(`${BASE}${path}`), ENV))?.status).toBe(401);
		}
	});
});

describe('the Basic branch', () => {
	it('passes with the right password', async () => {
		const req = new Request(`${BASE}/`, { headers: { authorization: basic(PASSWORD) } });
		expect(await demoGate(req, ENV)).toBeNull();
	});

	it('ignores the username half — there is only one credential', async () => {
		const req = new Request(`${BASE}/`, { headers: { authorization: basic(PASSWORD, 'anyone') } });
		expect(await demoGate(req, ENV)).toBeNull();
	});

	it('passes when the password itself contains a colon', async () => {
		const env: DemoGateEnv = { ...ENV, DEMO_PASSWORD: 'a:b:c' };
		const req = new Request(`${BASE}/`, { headers: { authorization: basic('a:b:c', 'u') } });
		expect(await demoGate(req, env)).toBeNull();
	});

	it('rejects the wrong password', async () => {
		const req = new Request(`${BASE}/`, { headers: { authorization: basic('wrong') } });
		expect((await demoGate(req, ENV))?.status).toBe(401);
	});

	it('rejects a prefix of the password', async () => {
		const req = new Request(`${BASE}/`, {
			headers: { authorization: basic(PASSWORD.slice(0, -1)) }
		});
		expect((await demoGate(req, ENV))?.status).toBe(401);
	});

	it('rejects malformed base64 without throwing', async () => {
		const req = new Request(`${BASE}/`, { headers: { authorization: 'Basic !!!not-base64!!!' } });
		expect((await demoGate(req, ENV))?.status).toBe(401);
	});
});

describe('the session branch', () => {
	it('passes an API call carrying Bearer but no Basic', async () => {
		// This is the case that makes "Basic only" unworkable: fetch() sets an
		// explicit Authorization, so the browser's cached Basic is dropped.
		const token = await mintSession();
		const req = new Request(`${BASE}/turn`, {
			method: 'POST',
			headers: { authorization: `Bearer ${token}` }
		});
		expect(await demoGate(req, ENV)).toBeNull();
	});

	it('passes a WebSocket handshake carrying ?token= and no Authorization at all', async () => {
		const token = await mintSession();
		const req = new Request(`${BASE}/agents/scribe/user-x?token=${encodeURIComponent(token)}`);
		expect(await demoGate(req, ENV)).toBeNull();
	});

	it('rejects a Bearer token that is not a valid session', async () => {
		const req = new Request(`${BASE}/turn`, {
			method: 'POST',
			headers: { authorization: 'Bearer not-a-real-token' }
		});
		expect((await demoGate(req, ENV))?.status).toBe(401);
	});

	it('rejects a session minted under a different HMAC secret', async () => {
		const token = await mintSession();
		const req = new Request(`${BASE}/turn`, { headers: { authorization: `Bearer ${token}` } });
		const otherEnv: DemoGateEnv = { ...ENV, SESSION_HMAC_SECRET: 'a-different-secret' };
		expect((await demoGate(req, otherEnv))?.status).toBe(401);
	});
});

describe('DEMO_PASSWORD unset', () => {
	it('leaves the gate open so wrangler dev needs no ceremony', async () => {
		const env: DemoGateEnv = { SESSION_HMAC_SECRET: ENV.SESSION_HMAC_SECRET };
		expect(await demoGate(new Request(`${BASE}/`), env)).toBeNull();
	});
});

describe('withoutDemoCredential', () => {
	it('strips a Basic credential before forwarding', () => {
		const req = new Request(`${BASE}/`, { headers: { authorization: basic(PASSWORD) } });
		expect(withoutDemoCredential(req).headers.get('authorization')).toBeNull();
	});

	it('leaves a session Bearer intact — downstream still needs it', () => {
		const req = new Request(`${BASE}/turn`, { headers: { authorization: 'Bearer abc.def' } });
		expect(withoutDemoCredential(req).headers.get('authorization')).toBe('Bearer abc.def');
	});

	it('is a no-op when there is no Authorization header', () => {
		const req = new Request(`${BASE}/`);
		expect(withoutDemoCredential(req).headers.get('authorization')).toBeNull();
	});
});
