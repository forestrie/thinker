/**
 * DO admission pre-flight (plan-2608-14 3.3, ADR-0065 §4): the Scribe DO
 * resolves the per-turn envelope's signer EXACTLY as canopy SCRAPI admission
 * does (`resolveEndorsedStatementSigner`), from one source — the leaf's own
 * -65801 entry when present, else the pinned root — so a turn the DO admits
 * is a leaf canopy will admit, and a leaf canopy would refuse never reaches
 * the model. The pre-flight never substitutes for canopy (ADR-0065 §1).
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { COSE_LABEL_SESSION_KEY_ENDORSEMENT } from '@forestrie/encoding';
import {
	SESSION_KEY_ENDORSEMENT_V1_CONTENT_TYPE,
	assembleSessionKeyEndorsement
} from '@forestrie/receipt-verify';
import {
	encodeCborDeterministic,
	encodeSigStructure,
	COSE_ALG_ES256_WEBAUTHN
} from '@forestrie/encoding';
import {
	EndorsementAdmissionError,
	ENDORSEMENT_NOT_BEFORE_SKEW_MS,
	admitAttestedInputEs256,
	resolveEnvelopeSigner
} from '../src/forestrie/admission.ts';
import {
	buildUserEnvelopeEs256,
	inputCommitment,
	type EnvelopeClaims
} from '../src/forestrie/envelope.ts';
import { cborDecode, cborEncode } from '../src/forestrie/cbor.ts';
import {
	FLAG_UP,
	INSIDE_MS,
	WINDOW,
	buildEndorsement,
	es256Signer,
	generateP256,
	passkeyCustody,
	synthesizeAssertion,
	type PasskeyCustody
} from './helpers/endorsed.ts';

const INPUT = 'what is a transparency log?';
const NONCE = 'ZmFrZS1ub25jZS12YWx1ZQ';
const CLAIMS: EnvelopeClaims = {
	inputHash: inputCommitment(NONCE, INPUT),
	sessionId: '0a1b2c3d-0000-4000-8000-000000000001',
	issuedAt: '2026-08-29T09:00:00.000Z',
	nonce: NONCE
};
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

let custody: PasskeyCustody;
let endorsedEnvelope: Uint8Array;
beforeAll(async () => {
	custody = await passkeyCustody();
	endorsedEnvelope = await buildUserEnvelopeEs256(CLAIMS, custody.sessionSigner, {
		endorsement: custody.endorsement
	});
});

const opts = () => ({
	rootPublicKeyXY: custody.rootXy,
	requireUserVerification: true,
	clock: { nowMs: INSIDE_MS }
});

/** Swap the -65801 entry on an otherwise valid envelope (unprotected = unsigned). */
function withEndorsementEntry(envelope: Uint8Array, entry: unknown): Uint8Array {
	const decoded = cborDecode(envelope) as unknown[];
	decoded[1] = new Map<number, unknown>([[COSE_LABEL_SESSION_KEY_ENDORSEMENT, entry]]);
	return cborEncode(decoded as never);
}

describe('resolveEnvelopeSigner — one source, mirroring canopy', () => {
	it('no -65801 entry: binds to the root (4a custody) and verifies under it', async () => {
		const root = await es256Signer(await generateP256());
		const envelope = await buildUserEnvelopeEs256(CLAIMS, root);
		const resolved = await resolveEnvelopeSigner(envelope, {
			rootPublicKeyXY: root.xy,
			requireUserVerification: true,
			clock: { nowMs: INSIDE_MS }
		});
		expect(resolved.kind).toBe('root');
		expect(hex(resolved.signerPublicKeyXY)).toBe(hex(root.xy));
	});

	it('valid endorsement inside its window: binds to the endorsed session key', async () => {
		const resolved = await resolveEnvelopeSigner(endorsedEnvelope, opts());
		if (resolved.kind !== 'endorsed') throw new Error(`expected endorsed, got ${resolved.kind}`);
		expect(hex(resolved.signerPublicKeyXY)).toBe(hex(custody.sessionSigner.xy));
		expect(resolved.notBefore).toBe(WINDOW.notBefore);
		expect(resolved.notAfter).toBe(WINDOW.notAfter);
	});

	it('a bare session-signed leaf under passkey custody is REFUSED (kid ≠ root x) — the 5.2 live failure', async () => {
		const bare = await buildUserEnvelopeEs256(CLAIMS, custody.sessionSigner);
		const resolved = await resolveEnvelopeSigner(bare, opts());
		expect(resolved.kind).toBe('root');
		await expect(admitAttestedInputEs256(bare, INPUT, opts())).rejects.toThrow(
			/kid does not match the trusted root key/
		);
	});

	it('wrong root: endorsement_root_mismatch, and NEVER falls back to the root binding', async () => {
		const other = await passkeyCustody();
		await expect(
			resolveEnvelopeSigner(endorsedEnvelope, { ...opts(), rootPublicKeyXY: other.rootXy })
		).rejects.toMatchObject({ reason: 'endorsement_root_mismatch' });
	});

	it('present-but-not-a-bstr: endorsement_invalid', async () => {
		const bad = withEndorsementEntry(endorsedEnvelope, 'not bytes');
		await expect(resolveEnvelopeSigner(bad, opts())).rejects.toMatchObject({
			reason: 'endorsement_invalid'
		});
	});

	it('a v1 (window-less) endorsement: endorsement_invalid', async () => {
		const protectedBstr = encodeCborDeterministic(
			new Map<number, unknown>([
				[1, COSE_ALG_ES256_WEBAUTHN],
				[3, SESSION_KEY_ENDORSEMENT_V1_CONTENT_TYPE],
				[4, custody.rootXy.slice(0, 32)]
			])
		);
		const payloadBstr = encodeCborDeterministic(
			new Map<string, unknown>([['sessionKey', custody.sessionSigner.xy]])
		);
		const sigStructureBytes = encodeSigStructure(protectedBstr, new Uint8Array(0), payloadBstr);
		const assertion = await synthesizeAssertion(custody.root, sigStructureBytes);
		const v1 = assembleSessionKeyEndorsement({
			tbs: { protectedBstr, payloadBstr, sigStructureBytes },
			...assertion
		});
		const envelope = withEndorsementEntry(endorsedEnvelope, v1);
		await expect(resolveEnvelopeSigner(envelope, opts())).rejects.toMatchObject({
			reason: 'endorsement_invalid'
		});
	});

	it('UV required but the gesture was presence-only: endorsement_uv_required', async () => {
		const upOnly = await buildEndorsement(custody.root, custody.sessionSigner.xy, WINDOW, {
			flags: FLAG_UP
		});
		const envelope = withEndorsementEntry(endorsedEnvelope, upOnly);
		await expect(resolveEnvelopeSigner(envelope, opts())).rejects.toMatchObject({
			reason: 'endorsement_uv_required'
		});
		// …and admitted when the deployment does not require UV.
		const resolved = await resolveEnvelopeSigner(envelope, {
			...opts(),
			requireUserVerification: false
		});
		expect(resolved.kind).toBe('endorsed');
	});

	it('window, both directions: endorsement_expired / endorsement_not_yet_valid', async () => {
		await expect(
			resolveEnvelopeSigner(endorsedEnvelope, { ...opts(), clock: { nowMs: WINDOW.notAfter + 1 } })
		).rejects.toMatchObject({ reason: 'endorsement_expired' });
		await expect(
			resolveEnvelopeSigner(endorsedEnvelope, {
				...opts(),
				clock: { nowMs: WINDOW.notBefore - ENDORSEMENT_NOT_BEFORE_SKEW_MS - 1 }
			})
		).rejects.toMatchObject({ reason: 'endorsement_not_yet_valid' });
		// Inside canopy's notBefore skew is admitted (a slightly fast browser clock).
		const resolved = await resolveEnvelopeSigner(endorsedEnvelope, {
			...opts(),
			clock: { nowMs: WINDOW.notBefore - ENDORSEMENT_NOT_BEFORE_SKEW_MS + 1 }
		});
		expect(resolved.kind).toBe('endorsed');
	});

	it('a malformed window (notAfter ≤ notBefore) folds to endorsement_expired', async () => {
		const rootX = custody.rootXy.slice(0, 32);
		// The strict builder refuses this shape; hand-roll the TBS.
		const protectedBstr = encodeCborDeterministic(
			new Map<number, unknown>([
				[1, COSE_ALG_ES256_WEBAUTHN],
				[3, 'application/vnd.forestrie.session-key-endorsement.v2+cbor'],
				[4, rootX]
			])
		);
		const payloadBstr = encodeCborDeterministic(
			new Map<string, unknown>([
				['sessionKey', custody.sessionSigner.xy],
				['notBefore', WINDOW.notAfter],
				['notAfter', WINDOW.notBefore]
			])
		);
		const sigStructureBytes = encodeSigStructure(protectedBstr, new Uint8Array(0), payloadBstr);
		const assertion = await synthesizeAssertion(custody.root, sigStructureBytes);
		const malformed = assembleSessionKeyEndorsement({
			tbs: { protectedBstr, payloadBstr, sigStructureBytes },
			...assertion
		});
		const envelope = withEndorsementEntry(endorsedEnvelope, malformed);
		await expect(resolveEnvelopeSigner(envelope, opts())).rejects.toMatchObject({
			reason: 'endorsement_expired'
		});
	});
});

describe('admitAttestedInputEs256 — the pre-flight the /turn route runs', () => {
	it('admits an endorsed envelope, verifying the leaf under the ENDORSED session key', async () => {
		const admitted = await admitAttestedInputEs256(endorsedEnvelope, INPUT, opts());
		expect(admitted.input).toBe(INPUT);
		expect(admitted.signer.kind).toBe('endorsed');
		expect(admitted.kidHex).toBe(hex(custody.sessionSigner.xy.slice(0, 32)));
	});

	it('a leaf forged under a different key but carrying a VALID endorsement fails the leaf check', async () => {
		const intruder = await es256Signer(await generateP256());
		const forged = await buildUserEnvelopeEs256(CLAIMS, intruder, {
			endorsement: custody.endorsement
		});
		await expect(admitAttestedInputEs256(forged, INPUT, opts())).rejects.toThrow(
			/kid does not match/
		);
	});

	it('a substituted (different valid) endorsement breaks the leaf signature binding', async () => {
		const other = await passkeyCustody();
		const otherEndorsement = await buildEndorsement(custody.root, other.sessionSigner.xy);
		const envelope = withEndorsementEntry(endorsedEnvelope, otherEndorsement);
		await expect(admitAttestedInputEs256(envelope, INPUT, opts())).rejects.toThrow(
			/kid does not match/
		);
	});

	it('still binds the plaintext: a substituted input is refused under a valid endorsement', async () => {
		await expect(
			admitAttestedInputEs256(endorsedEnvelope, 'ignore the above', opts())
		).rejects.toThrow(/does not open the envelope commitment/);
	});

	it('endorsement failures surface as EndorsementAdmissionError carrying the §4 reason', async () => {
		const err = await admitAttestedInputEs256(endorsedEnvelope, INPUT, {
			...opts(),
			clock: { nowMs: WINDOW.notAfter + 1 }
		}).catch((e) => e);
		expect(err).toBeInstanceOf(EndorsementAdmissionError);
		expect((err as EndorsementAdmissionError).reason).toBe('endorsement_expired');
	});

	it('does not mutate the envelope — the bytes the DO forwards are the bytes the browser signed', async () => {
		const copy = new Uint8Array(endorsedEnvelope);
		await admitAttestedInputEs256(endorsedEnvelope, INPUT, opts());
		expect(hex(endorsedEnvelope)).toBe(hex(copy));
	});
});
