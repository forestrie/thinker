/**
 * C3 key derivation. The O5 pre-issue counterfactual is a contract between two
 * *separate programs*: the DO derives the agent kid at init, and
 * `scripts/derive-agent-kid.mjs` derives the same kid offline so the authority
 * can endorse it on a fresh log before the DO ever runs.
 *
 * Nothing enforced that contract before this file. The golden vector below was
 * produced by running the provisioning script itself:
 *
 *   node scripts/derive-agent-kid.mjs \
 *     --user-sub 0x1111111111111111111111111111111111111111 --epoch 1 \
 *     --seed-b64 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
 *
 * so a change to the HKDF salt, the rejection-sampling info string, the NUL
 * framing, or the JWK import path breaks this test rather than silently
 * orphaning every pre-issued grant.
 */
import { describe, expect, it } from 'vitest';
import {
	KmsSeedKeyProvider,
	custodianMacInfo,
	deriveAgentKey,
	localSeedCustodianMac
} from '../src/keys/kms-seed.ts';

const SEED = Uint8Array.from({ length: 32 }, (_, i) => i);
const SUB = '0x1111111111111111111111111111111111111111';
const MAC = localSeedCustodianMac(SEED);

const GOLDEN_KID = '75e2549335b429b713b22b29eccfc5e8087db0a17248bcd0a1539f030a0d6fca';
const GOLDEN_PUBLIC_KEY_XY =
	'75e2549335b429b713b22b29eccfc5e8087db0a17248bcd0a1539f030a0d6fca' +
	'042afdaa93444dda9425c7451476d163a983298ea1eb3c1fd61fffbc2f1a99bc';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

describe('golden derivation vector (matches scripts/derive-agent-kid.mjs)', () => {
	it('derives the pinned kid and publicKeyXY', async () => {
		const derived = await deriveAgentKey(MAC, SUB, 1);
		expect(hex(derived.kid)).toBe(GOLDEN_KID);
		expect(hex(derived.publicKeyXY)).toBe(GOLDEN_PUBLIC_KEY_XY);
	});

	it('is deterministic across calls', async () => {
		const a = await deriveAgentKey(MAC, SUB, 1);
		const b = await deriveAgentKey(MAC, SUB, 1);
		expect(hex(a.publicKeyXY)).toBe(hex(b.publicKeyXY));
	});
});

describe('custodianMacInfo framing', () => {
	it('is label\\0sub\\0epoch, byte for byte', () => {
		expect(custodianMacInfo('abc', 7)).toEqual(
			new TextEncoder().encode('forestrie/agent-signer-seed/v1\u0000abc\u00007')
		);
	});

	it.each([
		['epoch 0', 0],
		['a negative epoch', -1],
		['a fractional epoch', 1.5]
	])('rejects %s', (_label, epoch) => {
		expect(() => custodianMacInfo('abc', epoch)).toThrow(/positive integer/);
	});

	it('rejects a userSub containing NUL — the delimiter is load-bearing', () => {
		expect(() => custodianMacInfo('a\u0000b', 1)).toThrow(/must not contain NUL/);
	});
});

describe('localSeedCustodianMac', () => {
	it('rejects a seed that is not exactly 32 bytes', () => {
		expect(() => localSeedCustodianMac(new Uint8Array(31))).toThrow(/must be 32 bytes, got 31/);
	});

	it('agrees with an independent HMAC-SHA256 over the same info', async () => {
		const info = custodianMacInfo(SUB, 1);
		const key = await crypto.subtle.importKey(
			'raw',
			SEED,
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign']
		);
		const expected = new Uint8Array(await crypto.subtle.sign('HMAC', key, info));
		expect(hex(await MAC(info))).toBe(hex(expected));
	});
});

describe('kid binding and independence', () => {
	it('kid is exactly the x coordinate — the first 32 bytes of x‖y', async () => {
		const derived = await deriveAgentKey(MAC, SUB, 1);
		expect(hex(derived.kid)).toBe(hex(derived.publicKeyXY.slice(0, 32)));
	});

	it('changing only the epoch changes the kid', async () => {
		const a = await deriveAgentKey(MAC, SUB, 1);
		const b = await deriveAgentKey(MAC, SUB, 2);
		expect(hex(a.kid)).not.toBe(hex(b.kid));
	});

	it('changing only the userSub changes the kid', async () => {
		const a = await deriveAgentKey(MAC, SUB, 1);
		const b = await deriveAgentKey(MAC, `${SUB.slice(0, -1)}2`, 1);
		expect(hex(a.kid)).not.toBe(hex(b.kid));
	});

	it('changing only the seed changes the kid', async () => {
		const other = localSeedCustodianMac(Uint8Array.from({ length: 32 }, (_, i) => i + 1));
		const a = await deriveAgentKey(MAC, SUB, 1);
		const b = await deriveAgentKey(other, SUB, 1);
		expect(hex(a.kid)).not.toBe(hex(b.kid));
	});
});

describe('KmsSeedKeyProvider', () => {
	it('signs 64-byte P1363 r‖s that verifies under the derived public key', async () => {
		const provider = await KmsSeedKeyProvider.load(MAC, SUB, 1);
		const message = new TextEncoder().encode('work statement bytes');
		const signature = await provider.sign(message);

		expect(signature.length).toBe(64); // raw r‖s, not DER

		const { publicKey } = await provider.signingKeyPair();
		await expect(
			crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, message)
		).resolves.toBe(true);
	});

	it('exposes the golden kid and epoch', async () => {
		const provider = await KmsSeedKeyProvider.load(MAC, SUB, 1);
		expect(hex(provider.kid())).toBe(GOLDEN_KID);
		expect(provider.epoch()).toBe(1);
	});

	it('rotate() moves the epoch and the kid with it', async () => {
		const provider = await KmsSeedKeyProvider.load(MAC, SUB, 1);
		const before = hex(provider.kid());
		await provider.rotate(2);
		expect(provider.epoch()).toBe(2);
		expect(hex(provider.kid())).not.toBe(before);
	});

	it('refuses to rotate to the same or an earlier epoch', async () => {
		const provider = await KmsSeedKeyProvider.load(MAC, SUB, 2);
		await expect(provider.rotate(2)).rejects.toThrow(/must exceed current epoch/);
		await expect(provider.rotate(1)).rejects.toThrow(/must exceed current epoch/);
	});
});
