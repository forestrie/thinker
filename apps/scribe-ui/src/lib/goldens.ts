/**
 * Real-authenticator golden capture (plan-2608-13 Phase 5.1, dev-only).
 *
 * ADR-0008 records the debt this closes: "The committed test vectors are
 * synthetic … A golden assertion captured from a real authenticator should
 * be added as a fixture once the thinker-side ceremony exists." This module
 * runs the REAL `delegateSealingWebauthn` ceremony — two authenticator
 * gestures — against an in-page mock coordinator, with the FIXED fixture
 * scope already shared by delegation-cose's onchain-delegation vectors
 * (same logId, mmr range 0..2^40, delegated-key byte patterns 0xa0../0xc0..),
 * re-verifies both artifacts through the contract mirrors, and emits one
 * JSON golden for the univocity / delegation-cose / publishproof suites.
 *
 * The mock coordinator serves a standing entry vouched by a FIXED registrar
 * test key, so everything in the golden except the assertions themselves is
 * deterministic. Only the assertions vary per capture (authenticator sign
 * counter, clientDataJSON, signature nonce) — that variation is the point.
 */
import {
	delegateSealingWebauthn,
	type SignWebauthnAssertion
} from '@forestrie/think-scribe/forestrie/delegate';
import {
	assembleSessionKeyEndorsement,
	buildSessionKeyEndorsementTbs,
	extractLeafEndorsement,
	SESSION_KEY_ENDORSEMENT_CONTENT_TYPE,
	spkiToPublicKeyXY,
	verifySessionKeyEndorsement,
	webauthnSignatureToP1363LowS
} from '@forestrie/think-scribe/forestrie/passkey';
import {
	buildUserEnvelopeEs256,
	inputCommitment,
	verifyUserEnvelopeEs256
} from '@forestrie/think-scribe/forestrie/envelope';
import {
	assembleWebauthnDelegationAlgData,
	decodeWebauthnDelegationAlgData,
	buildOnchainDelegationToBeSignedWebauthn,
	verifyOnchainDelegationSignatureWebauthn,
	parseDelegationCertificate
} from '@forestrie/delegation-cose';
import {
	base64UrlEncode,
	decodeCoseSign1,
	encodeCborDeterministic,
	encodeCoseSign1Raw,
	encodeSigStructure,
	verifyCoseSign1WithParsedKey,
	COSE_ALG_ES256_WEBAUTHN
} from '@forestrie/encoding';
import { bytesToB64, bytesToHex } from './utils.ts';

/** Same scope family as delegation-cose testdata/onchain-delegation-vectors.json. */
const GOLDEN_LOG_UUID = '10111213-1415-1617-1819-1a1b1c1d1e1f';
const GOLDEN_LOG_ID_HEX = '101112131415161718191a1b1c1d1e1f';
/** 1 << 40 — the ceremony's mmrStart is fixed at 0 by delegateSealingWebauthn. */
const GOLDEN_MMR_END = 1_099_511_627_776;
const DELEGATED_X = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);
const DELEGATED_Y = Uint8Array.from({ length: 32 }, (_, i) => 0xc0 + i);
/** Fixed P-256 registrar TEST key (scalar d1f1…f1) — never a production key. */
const REGISTRAR_JWK: JsonWebKey = {
	kty: 'EC',
	crv: 'P-256',
	d: '0fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fE',
	x: 'N_rN0WGMxK73w8XwhBaeHIEY0IY2ajeWiNqxFHfU4Pk',
	y: '2tuvRstPAu7sy6FOmpjOXs4gjF4mEdUgjksve195O5A'
};
const SEALER_ID = 'golden-sealer-1';
const EPOCH = 3;
const TTL_SECONDS = 3600;

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
}

/** The authenticator half of a capture — injectable so tests can go synthetic. */
export interface CaptureIdentity {
	/** The root credential's 64-byte P-256 x‖y. */
	rootPublicKeyXY: Uint8Array;
	/** One assertion ceremony per 32-byte challenge, low-s P1363 signature. */
	getAssertion: SignWebauthnAssertion;
	/** Free-text provenance for the fixture ("Touch ID / Chrome 140…"). */
	authenticator: string;
	rpId: string;
	origin: string;
}

/**
 * Create a THROWAWAY capture credential with the real WebAuthn API — kept
 * in memory only, never written to the scribe's IndexedDB custody record
 * (this page must not change what the app believes about its own custody).
 * Mirrors PasskeyRoot.create()/getAssertion(): ES256 only, UV required.
 */
export async function createCaptureIdentity(): Promise<CaptureIdentity | null> {
	let credential: PublicKeyCredential | null;
	try {
		credential = (await navigator.credentials.create({
			publicKey: {
				challenge: crypto.getRandomValues(new Uint8Array(32)),
				rp: { name: 'Forestrie golden capture (dev)' },
				user: {
					id: crypto.getRandomValues(new Uint8Array(16)),
					name: 'golden-capture',
					displayName: 'Golden capture (throwaway)'
				},
				pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
				authenticatorSelection: { residentKey: 'discouraged', userVerification: 'required' }
			}
		})) as PublicKeyCredential | null;
	} catch {
		return null;
	}
	if (!credential) return null;
	const response = credential.response as AuthenticatorAttestationResponse;
	const spki = typeof response.getPublicKey === 'function' ? response.getPublicKey() : null;
	if (!spki) return null;
	const rootPublicKeyXY = await spkiToPublicKeyXY(new Uint8Array(spki));
	if (!rootPublicKeyXY) return null;
	const credentialId = credential.rawId;
	const getAssertion: SignWebauthnAssertion = async (challenge: Uint8Array) => {
		const assertion = (await navigator.credentials.get({
			publicKey: {
				challenge: challenge as BufferSource,
				allowCredentials: [{ type: 'public-key', id: credentialId }],
				userVerification: 'required'
			}
		})) as PublicKeyCredential | null;
		if (!assertion) throw new Error('assertion ceremony was refused');
		const res = assertion.response as AuthenticatorAssertionResponse;
		return {
			authenticatorData: new Uint8Array(res.authenticatorData),
			clientDataJSON: new Uint8Array(res.clientDataJSON),
			signature: webauthnSignatureToP1363LowS(new Uint8Array(res.signature))
		};
	};
	return {
		rootPublicKeyXY,
		getAssertion,
		authenticator: navigator.userAgent,
		rpId: location.hostname,
		origin: location.origin
	};
}

/** COSE key map for the fixed delegated P-256 coordinates, coordinator-shaped. */
function delegatedPublicKeyCbor(): Uint8Array {
	return encodeCborDeterministic(
		new Map<number, unknown>([
			[1, 2],
			[-1, 1],
			[-2, DELEGATED_X],
			[-3, DELEGATED_Y]
		])
	);
}

/** Registrar voucher: plain ES256 COSE Sign1 over {1: sealerId, 2: epoch, 3: key}. */
async function buildVoucher(delegatedKeyCbor: Uint8Array): Promise<Uint8Array> {
	const registrar = await crypto.subtle.importKey(
		'jwk',
		REGISTRAR_JWK,
		{ name: 'ECDSA', namedCurve: 'P-256' },
		false,
		['sign']
	);
	const protectedBstr = encodeCborDeterministic(new Map<number, unknown>([[1, -7]]));
	const payload = encodeCborDeterministic(
		new Map<number, unknown>([
			[1, SEALER_ID],
			[2, EPOCH],
			[3, delegatedKeyCbor]
		])
	);
	const sigStructure = encodeSigStructure(protectedBstr, new Uint8Array(0), payload);
	const signature = new Uint8Array(
		await crypto.subtle.sign(
			{ name: 'ECDSA', hash: 'SHA-256' },
			registrar,
			sigStructure as BufferSource
		)
	);
	return encodeCoseSign1Raw(protectedBstr, new Map(), payload, signature);
}

function registrarPublicKeyXY(): Uint8Array {
	const b64uToBytes = (s: string) =>
		Uint8Array.from(atob(s.replaceAll('-', '+').replaceAll('_', '/')), (c) => c.charCodeAt(0));
	const xy = new Uint8Array(64);
	xy.set(b64uToBytes(REGISTRAR_JWK.x!), 0);
	xy.set(b64uToBytes(REGISTRAR_JWK.y!), 32);
	return xy;
}

function envelopeFromUnprotected(unprotected: unknown): [Uint8Array, Uint8Array] {
	const value =
		unprotected instanceof Map
			? unprotected.get(COSE_ALG_ES256_WEBAUTHN)
			: (unprotected as Record<string, unknown>)?.[String(COSE_ALG_ES256_WEBAUTHN)];
	if (!Array.isArray(value) || value.length !== 2)
		throw new Error('certificate missing the -65800 assertion envelope');
	return [new Uint8Array(value[0] as Uint8Array), new Uint8Array(value[1] as Uint8Array)];
}

/** The golden JSON — hex fields unprefixed, numbers as decimal strings. */
export interface GoldenCapture {
	description: string;
	capturedAt: string;
	origin: string;
	rpId: string;
	authenticator: string;
	alg: 'ES256_WEBAUTHN';
	logIdHex: string;
	mmrStart: string;
	mmrEnd: string;
	delegatedKeyX: string;
	delegatedKeyY: string;
	rootX: string;
	rootY: string;
	onchain: {
		protectedHeader: string;
		signature: string;
		authenticatorData: string;
		clientDataJSON: string;
		challengeIndex: string;
		typeIndex: string;
		sigStructure: string;
		challengeB64u: string;
	};
	certificate: {
		coseSign1: string;
		rootKid: string;
		issuedAt: string;
		expiresAt: string;
		delegatedPublicKeyCbor: string;
		sigStructure: string;
		challengeB64u: string;
		authenticatorData: string;
		clientDataJSON: string;
		signature: string;
	};
}

/**
 * Run the real ceremony (two gestures) against the in-page mock coordinator
 * and return the verified golden. Throws if either artifact fails its
 * contract-mirror verification — an unverifiable golden must never download.
 */
export async function captureGolden(identity: CaptureIdentity): Promise<GoldenCapture> {
	const delegatedKeyCbor = delegatedPublicKeyCbor();
	const voucher = await buildVoucher(delegatedKeyCbor);
	const standing = {
		delegatedPublicKey: bytesToB64(delegatedKeyCbor),
		suggestedTtlSeconds: TTL_SECONDS,
		voucher: bytesToB64(voucher),
		sealerId: SEALER_ID,
		epoch: EPOCH
	};
	const submitted: Record<string, unknown>[] = [];
	const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = String(input);
		if (url.endsWith(`/api/logs/${GOLDEN_LOG_UUID}/pending-delegation`))
			return Response.json({ entries: [standing] });
		if (url.endsWith('/api/delegations/certificate')) {
			submitted.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
			return Response.json({ stored: true });
		}
		throw new Error(`unexpected fetch ${url}`);
	}) as typeof fetch;

	await delegateSealingWebauthn(
		identity.rootPublicKeyXY,
		identity.getAssertion,
		{
			coordinatorUrl: 'https://golden.invalid',
			logId: GOLDEN_LOG_UUID,
			knownSealerKeyB64: bytesToB64(registrarPublicKeyXY()),
			horizonMmrEnd: GOLDEN_MMR_END
		},
		fetchImpl
	);
	if (submitted.length !== 1) throw new Error('ceremony did not submit exactly once');
	const body = submitted[0]!;
	const b64ToBytes = (b64: string) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

	const rootX = identity.rootPublicKeyXY.slice(0, 32);
	const rootY = identity.rootPublicKeyXY.slice(32, 64);

	// --- On-chain proof: assemble algData and verify via the ADR-0008 mirror.
	const onchainAuthData = b64ToBytes(String(body.onchainAuthenticatorData));
	const onchainClientData = b64ToBytes(String(body.onchainClientDataJSON));
	const onchainSignature = b64ToBytes(String(body.onchainSignature));
	const algData = assembleWebauthnDelegationAlgData(onchainAuthData, onchainClientData);
	const decoded = decodeWebauthnDelegationAlgData(algData);
	const onchainInput = {
		logIdHex: GOLDEN_LOG_ID_HEX,
		mmrStart: Number(body.mmrStart),
		mmrEnd: Number(body.mmrEnd),
		delegatedKeyX: DELEGATED_X,
		delegatedKeyY: DELEGATED_Y
	};
	const onchainTbs = buildOnchainDelegationToBeSignedWebauthn(onchainInput);
	const onchainOk = await verifyOnchainDelegationSignatureWebauthn(
		onchainInput,
		onchainSignature,
		algData,
		rootX,
		rootY,
		{ requireUserVerification: true }
	);
	if (!onchainOk) throw new Error('on-chain assertion failed the contract mirror (UV required)');

	// --- Certificate: verify via the shared -65800 envelope branch.
	const certificate = b64ToBytes(String(body.certificate));
	const certOk = await verifyCoseSign1WithParsedKey(
		certificate,
		{ x: rootX, y: rootY, curve: 'P-256' },
		{ requireUserVerification: true }
	);
	if (!certOk) throw new Error('certificate failed the envelope verification (UV required)');
	const cert = decodeCoseSign1(certificate);
	if (!cert) throw new Error('certificate is not a decodable COSE Sign1');
	const [certAuthData, certClientData] = envelopeFromUnprotected(cert.unprotected);
	const certSigStructure = encodeSigStructure(
		cert.protectedBstr,
		new Uint8Array(0),
		cert.payloadBstr
	);
	const info = parseDelegationCertificate(certificate);

	const point = new Uint8Array(65);
	point[0] = 0x04;
	point.set(identity.rootPublicKeyXY, 1);
	const rootKid = (await sha256(point)).slice(0, 16);

	return {
		description:
			'Real-authenticator WebAuthn delegation golden (plan-2608-13 Phase 5.1). ' +
			'Captured via the thinker delegateSealingWebauthn ceremony (scribe-ui /goldens); ' +
			'closes the ADR-0008 synthetic-vectors debt. Scope matches ' +
			'delegation-cose testdata/onchain-delegation-vectors.json.',
		capturedAt: new Date().toISOString(),
		origin: identity.origin,
		rpId: identity.rpId,
		authenticator: identity.authenticator,
		alg: 'ES256_WEBAUTHN',
		logIdHex: GOLDEN_LOG_ID_HEX,
		mmrStart: String(body.mmrStart),
		mmrEnd: String(body.mmrEnd),
		delegatedKeyX: bytesToHex(DELEGATED_X),
		delegatedKeyY: bytesToHex(DELEGATED_Y),
		rootX: bytesToHex(rootX),
		rootY: bytesToHex(rootY),
		onchain: {
			protectedHeader: bytesToHex(onchainTbs.protectedHeader),
			signature: bytesToHex(onchainSignature),
			authenticatorData: bytesToHex(onchainAuthData),
			clientDataJSON: bytesToHex(onchainClientData),
			challengeIndex: decoded.challengeIndex.toString(),
			typeIndex: decoded.typeIndex.toString(),
			sigStructure: bytesToHex(onchainTbs.sigStructureBytes),
			challengeB64u: base64UrlEncode(await sha256(onchainTbs.sigStructureBytes))
		},
		certificate: {
			coseSign1: bytesToHex(certificate),
			rootKid: bytesToHex(rootKid),
			issuedAt: String(info.issuedAt),
			expiresAt: String(info.expiresAt),
			delegatedPublicKeyCbor: bytesToHex(delegatedKeyCbor),
			sigStructure: bytesToHex(certSigStructure),
			challengeB64u: base64UrlEncode(await sha256(certSigStructure)),
			authenticatorData: bytesToHex(certAuthData),
			clientDataJSON: bytesToHex(certClientData),
			signature: bytesToHex(cert.signature)
		}
	};
}

// --- v2 session-key endorsement golden (plan-2608-14 3.4 → 1.3) -------------

/**
 * Fixed 7-day window (unix ms) — the same family as receipt-verify's
 * endorsed-leaf fixture, so the golden slots straight into that suite and
 * canopy-api's admission specs with a leaf time of 1_790_300_000_000.
 */
const GOLDEN_WINDOW = { notBefore: 1_790_000_000_000, notAfter: 1_790_604_800_000 };
const GOLDEN_NONCE = '00112233445566778899aabbccddeeff';
const GOLDEN_INPUT = 'golden: what is a transparency log?';

/** The golden JSON — hex fields unprefixed, numbers as decimal strings. */
export interface EndorsementGoldenCapture {
	description: string;
	capturedAt: string;
	origin: string;
	rpId: string;
	authenticator: string;
	alg: 'ES256_WEBAUTHN';
	contentType: string;
	rootX: string;
	rootY: string;
	sessionX: string;
	sessionY: string;
	notBefore: string;
	notAfter: string;
	endorsement: {
		coseSign1: string;
		protectedHeader: string;
		payload: string;
		sigStructure: string;
		challengeB64u: string;
		authenticatorData: string;
		clientDataJSON: string;
		signature: string;
	};
	/** A per-turn envelope signed by the session key, carrying the endorsement at -65801. */
	leaf: {
		coseSign1: string;
		kid: string;
		claims: { inputHash: string; sessionId: string; issuedAt: string; nonce: string };
		input: string;
	};
}

/**
 * Capture a REAL-authenticator v2 session-key endorsement (ADR-0065 §3) —
 * ONE gesture — over a throwaway session key, verify it under the root with
 * UV enforced, then sign a golden per-turn leaf with that session key
 * carrying the endorsement at -65801 and verify the leaf under the session
 * key. Throws if either fails: an unverifiable golden must never download.
 */
export async function captureEndorsementGolden(
	identity: CaptureIdentity
): Promise<EndorsementGoldenCapture> {
	const rootX = identity.rootPublicKeyXY.slice(0, 32);
	const rootY = identity.rootPublicKeyXY.slice(32, 64);

	// A real (throwaway) P-256 session key: verifiers import it, so the
	// payload must name an actual point.
	const session = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
		'sign',
		'verify'
	])) as CryptoKeyPair;
	const sessionXY = new Uint8Array(
		(await crypto.subtle.exportKey('raw', session.publicKey)) as ArrayBuffer
	).slice(1, 65);

	const tbs = buildSessionKeyEndorsementTbs({
		rootPublicKeyX: rootX,
		sessionPublicKeyXY: sessionXY,
		...GOLDEN_WINDOW
	});
	const challenge = await sha256(tbs.sigStructureBytes);
	const assertion = await identity.getAssertion(challenge);
	const endorsement = assembleSessionKeyEndorsement({ tbs, ...assertion });
	const verified = await verifySessionKeyEndorsement(
		endorsement,
		{ x: rootX, y: rootY, curve: 'P-256' },
		{ requireUserVerification: true }
	);
	if (!verified.ok)
		throw new Error(
			`endorsement failed verification under the root (UV required): ${verified.reason}`
		);

	const claims = {
		inputHash: inputCommitment(GOLDEN_NONCE, GOLDEN_INPUT),
		sessionId: '10111213-1415-1617-1819-1a1b1c1d1e1f',
		issuedAt: '2026-09-21T12:53:20.000Z', // inside the fixed window
		nonce: GOLDEN_NONCE
	};
	const leaf = await buildUserEnvelopeEs256(
		claims,
		{
			publicKeyXY: () => Promise.resolve(sessionXY),
			sign: async (bytes) =>
				new Uint8Array(
					await crypto.subtle.sign(
						{ name: 'ECDSA', hash: 'SHA-256' },
						session.privateKey,
						bytes as BufferSource
					)
				)
		},
		{ endorsement }
	);
	const leafVerified = await verifyUserEnvelopeEs256(leaf, verified.sessionPublicKeyXY);
	const extracted = extractLeafEndorsement(leaf);
	if (extracted.kind !== 'ok' || bytesToHex(extracted.endorsement) !== bytesToHex(endorsement))
		throw new Error('golden leaf does not carry the endorsement at -65801');

	return {
		description:
			'Real-authenticator v2 session-key endorsement golden (devdocs ADR-0065 §3, plan-2608-14 3.4/1.3). ' +
			'Captured via scribe-ui /goldens with one passkey gesture over a throwaway session key; ' +
			'the leaf is the canonical thinker per-turn envelope signed by that session key with the ' +
			'endorsement at unprotected -65801. Window matches receipt-verify endorsed-leaf-fixture.',
		capturedAt: new Date().toISOString(),
		origin: identity.origin,
		rpId: identity.rpId,
		authenticator: identity.authenticator,
		alg: 'ES256_WEBAUTHN',
		contentType: SESSION_KEY_ENDORSEMENT_CONTENT_TYPE,
		rootX: bytesToHex(rootX),
		rootY: bytesToHex(rootY),
		sessionX: bytesToHex(sessionXY.slice(0, 32)),
		sessionY: bytesToHex(sessionXY.slice(32, 64)),
		notBefore: String(GOLDEN_WINDOW.notBefore),
		notAfter: String(GOLDEN_WINDOW.notAfter),
		endorsement: {
			coseSign1: bytesToHex(endorsement),
			protectedHeader: bytesToHex(tbs.protectedBstr),
			payload: bytesToHex(tbs.payloadBstr),
			sigStructure: bytesToHex(tbs.sigStructureBytes),
			challengeB64u: base64UrlEncode(challenge),
			authenticatorData: bytesToHex(assertion.authenticatorData),
			clientDataJSON: bytesToHex(assertion.clientDataJSON),
			signature: bytesToHex(assertion.signature)
		},
		leaf: {
			coseSign1: bytesToHex(leaf),
			kid: leafVerified.kidHex,
			claims,
			input: GOLDEN_INPUT
		}
	};
}
