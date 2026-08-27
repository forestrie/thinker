/**
 * Golden-capture harness (plan-2608-13 Phase 5.1): a synthetic authenticator
 * stands in for the real gesture so the whole pipeline — real
 * delegateSealingWebauthn ceremony, mock coordinator, contract-mirror
 * verification, JSON assembly — is proven before a human ever touches the
 * page. The committed goldens themselves come from a REAL authenticator.
 */
import { describe, expect, it } from 'vitest';
import { base64UrlEncode } from '@forestrie/encoding';
import { normalizeEs256SignatureLowS } from '@forestrie/delegation-cose';
import type { WebauthnAssertionResult } from '@forestrie/think-scribe/forestrie/delegate';
import { captureGolden, type CaptureIdentity } from './goldens.ts';

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
}

async function syntheticIdentity(): Promise<CaptureIdentity> {
	const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
		'sign',
		'verify'
	])) as CryptoKeyPair;
	const raw = new Uint8Array((await crypto.subtle.exportKey('raw', pair.publicKey)) as ArrayBuffer);
	const rootPublicKeyXY = raw.slice(1, 65);
	const getAssertion = async (challenge: Uint8Array): Promise<WebauthnAssertionResult> => {
		const clientDataJSON = new TextEncoder().encode(
			`{"type":"webauthn.get","challenge":"${base64UrlEncode(challenge)}","origin":"https://thinker.example","crossOrigin":false}`
		);
		const authenticatorData = new Uint8Array(37);
		authenticatorData.fill(0xa1, 0, 32);
		authenticatorData[32] = FLAG_UP | FLAG_UV;
		const cdjHash = await sha256(clientDataJSON);
		const signedBytes = new Uint8Array(authenticatorData.length + 32);
		signedBytes.set(authenticatorData, 0);
		signedBytes.set(cdjHash, authenticatorData.length);
		const signature = normalizeEs256SignatureLowS(
			new Uint8Array(
				await crypto.subtle.sign(
					{ name: 'ECDSA', hash: 'SHA-256' },
					pair.privateKey,
					signedBytes as BufferSource
				)
			)
		);
		return { authenticatorData, clientDataJSON, signature };
	};
	return {
		rootPublicKeyXY,
		getAssertion,
		authenticator: 'synthetic (vitest)',
		rpId: 'thinker.example',
		origin: 'https://thinker.example'
	};
}

describe('captureGolden (5.1 harness)', () => {
	it('runs the real ceremony and emits a self-verified golden', async () => {
		const golden = await captureGolden(await syntheticIdentity());

		// Fixed fixture scope — the same family as onchain-delegation-vectors.json.
		expect(golden.logIdHex).toBe('101112131415161718191a1b1c1d1e1f');
		expect(golden.mmrStart).toBe('0');
		expect(golden.mmrEnd).toBe(String(2 ** 40));
		expect(golden.delegatedKeyX.startsWith('a0a1a2')).toBe(true);
		expect(golden.delegatedKeyY.startsWith('c0c1c2')).toBe(true);
		expect(golden.onchain.protectedHeader).toBe('a1013a00010107');

		// Two DISTINCT assertions — one per artifact (Q1).
		expect(golden.onchain.clientDataJSON).not.toBe(golden.certificate.clientDataJSON);
		expect(golden.onchain.challengeB64u).not.toBe(golden.certificate.challengeB64u);

		// The challenge each clientDataJSON carries binds its own Sig_structure.
		const onchainClient = new TextDecoder().decode(
			Uint8Array.from(golden.onchain.clientDataJSON.match(/../g)!.map((h) => parseInt(h, 16)))
		);
		expect(onchainClient).toContain(`"challenge":"${golden.onchain.challengeB64u}"`);
		const certClient = new TextDecoder().decode(
			Uint8Array.from(golden.certificate.clientDataJSON.match(/../g)!.map((h) => parseInt(h, 16)))
		);
		expect(certClient).toContain(`"challenge":"${golden.certificate.challengeB64u}"`);

		// 64-byte P1363 signatures, 16-byte kid, sane indices.
		expect(golden.onchain.signature.length).toBe(128);
		expect(golden.certificate.signature.length).toBe(128);
		expect(golden.certificate.rootKid.length).toBe(32);
		expect(Number(golden.onchain.challengeIndex)).toBeGreaterThan(0);
		expect(Number(golden.onchain.typeIndex)).toBeGreaterThan(0);
	});
});
