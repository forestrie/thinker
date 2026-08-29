/**
 * The endorsed per-turn envelope (plan-2608-14 3.1, ADR-0065 §2): under
 * passkey custody the browser attaches the passkey's v2 session-key
 * endorsement to the envelope's UNPROTECTED header at label -65801 BEFORE
 * signing, so the registered leaf carries everything canopy admission and an
 * offline auditor need. The unprotected header is outside the Sig_structure,
 * so the session signature is unchanged by it — and a verifier unaware of
 * the label MUST fail to verify the leaf under the root (kid = session x).
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { COSE_LABEL_SESSION_KEY_ENDORSEMENT } from '@forestrie/encoding';
import { extractLeafEndorsement } from '@forestrie/receipt-verify';
import {
	buildUserEnvelopeEs256,
	envelopeEndorsement,
	inputCommitment,
	verifyUserEnvelopeEs256,
	type EnvelopeClaims
} from '../src/forestrie/envelope.ts';
import { cborDecode } from '../src/forestrie/cbor.ts';
import { passkeyCustody, type PasskeyCustody } from './helpers/endorsed.ts';

const NONCE = 'ZmFrZS1ub25jZS12YWx1ZQ';
const CLAIMS: EnvelopeClaims = {
	inputHash: inputCommitment(NONCE, 'what is a transparency log?'),
	sessionId: '0a1b2c3d-0000-4000-8000-000000000001',
	issuedAt: '2026-08-29T09:00:00.000Z',
	nonce: NONCE
};
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

let custody: PasskeyCustody;
beforeAll(async () => {
	custody = await passkeyCustody();
});

describe('endorsed envelope wire shape', () => {
	it('carries the endorsement bytes at unprotected -65801 and nothing else there', async () => {
		const envelope = await buildUserEnvelopeEs256(CLAIMS, custody.sessionSigner, {
			endorsement: custody.endorsement
		});
		const decoded = cborDecode(envelope);
		if (!Array.isArray(decoded)) throw new Error('envelope must be an array');
		const unprotected = decoded[1];
		if (!(unprotected instanceof Map)) throw new Error('unprotected must be a map');
		expect([...unprotected.keys()]).toEqual([COSE_LABEL_SESSION_KEY_ENDORSEMENT]);
		expect(hex(unprotected.get(COSE_LABEL_SESSION_KEY_ENDORSEMENT) as Uint8Array)).toBe(
			hex(custody.endorsement)
		);
		// Protected header is the plain ES256 profile, kid = the SESSION x.
		const header = cborDecode(decoded[0] as Uint8Array) as Map<number, unknown>;
		expect([...header.keys()].sort((a, b) => a - b)).toEqual([1, 3, 4]);
		expect(hex(header.get(4) as Uint8Array)).toBe(hex(custody.sessionSigner.xy.slice(0, 32)));
	});

	it('leaves the unprotected map empty when no endorsement is given (4a custody)', async () => {
		const envelope = await buildUserEnvelopeEs256(CLAIMS, custody.sessionSigner);
		const decoded = cborDecode(envelope) as unknown[];
		expect(decoded[1]).toEqual(new Map());
		expect(envelopeEndorsement(envelope)).toBeNull();
	});

	it('refuses an empty endorsement byte string', async () => {
		await expect(
			buildUserEnvelopeEs256(CLAIMS, custody.sessionSigner, { endorsement: new Uint8Array(0) })
		).rejects.toThrow(/endorsement/);
	});
});

describe('the endorsement is readable by both sides', () => {
	it('envelopeEndorsement returns the exact bytes that were attached', async () => {
		const envelope = await buildUserEnvelopeEs256(CLAIMS, custody.sessionSigner, {
			endorsement: custody.endorsement
		});
		expect(hex(envelopeEndorsement(envelope)!)).toBe(hex(custody.endorsement));
	});

	it('canopy’s reader (receipt-verify extractLeafEndorsement) sees the same bytes and kid', async () => {
		const envelope = await buildUserEnvelopeEs256(CLAIMS, custody.sessionSigner, {
			endorsement: custody.endorsement
		});
		const extracted = extractLeafEndorsement(envelope);
		if (extracted.kind !== 'ok') throw new Error(`expected ok, got ${extracted.kind}`);
		expect(hex(extracted.endorsement)).toBe(hex(custody.endorsement));
		expect(hex(extracted.kid!)).toBe(hex(custody.sessionSigner.xy.slice(0, 32)));
	});
});

describe('signature scope', () => {
	it('verifies under the SESSION key regardless of the attached endorsement', async () => {
		const envelope = await buildUserEnvelopeEs256(CLAIMS, custody.sessionSigner, {
			endorsement: custody.endorsement
		});
		const verified = await verifyUserEnvelopeEs256(envelope, custody.sessionSigner.xy);
		expect(verified.claims).toEqual(CLAIMS);
	});

	it('FAILS to verify under the passkey ROOT — an endorsement-unaware verifier must not pass it', async () => {
		const envelope = await buildUserEnvelopeEs256(CLAIMS, custody.sessionSigner, {
			endorsement: custody.endorsement
		});
		await expect(verifyUserEnvelopeEs256(envelope, custody.rootXy)).rejects.toThrow(
			/kid does not match the trusted root key/
		);
	});
});
