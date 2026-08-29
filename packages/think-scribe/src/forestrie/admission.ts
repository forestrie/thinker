/**
 * Envelope signer resolution — the DO's admission pre-flight (plan-2608-14
 * 3.3) and the offline verifier's first rung, mirroring canopy SCRAPI
 * admission's `resolveEndorsedStatementSigner` (ADR-0065 §4) step for step:
 *
 * 1. **No `-65801` entry**: the signer is the pinned ROOT — kid == root x,
 *    signature under the root (4a custody; canopy binds to `grantData`).
 * 2. **`-65801` present**: the entry MUST verify as a v2 session-key
 *    endorsement under the pinned root (kid pinned to root x, UV per policy),
 *    its window must contain the clock (with canopy's `notBefore` skew), and
 *    the signer becomes the ENDORSED SESSION key — kid == session x,
 *    signature under the session key.
 *
 * A present-but-invalid endorsement is refused with the §4 reason and NEVER
 * falls back to the root binding. There is exactly one source for the
 * (kid binding, verify key) pair, and it is the leaf's own bytes.
 *
 * canopy admission remains THE enforcement point (ADR-0065 §1): this
 * pre-flight exists so a turn the DO runs is a leaf canopy will admit — a
 * refusal here is a refusal canopy would have issued after the model had
 * already been paid for — and it must agree with canopy, never substitute
 * for it. The primitive is `@forestrie/receipt-verify`'s
 * `verifySessionKeyEndorsement`, the same code canopy and `verifyEndorsedLeaf`
 * run (§5: one verification path).
 */
import {
	checkEndorsementWindow,
	endorsementAdmissionReason,
	verifySessionKeyEndorsement,
	type EndorsementAdmissionReason
} from '@forestrie/receipt-verify';
import {
	EnvelopeError,
	envelopeEndorsement,
	verifyAttestedInputEs256,
	type VerifiedEnvelopeEs256
} from './envelope.ts';

/**
 * canopy's tolerance for a `notBefore` slightly ahead of the verifier's
 * clock (`ENDORSEMENT_NOT_BEFORE_SKEW_MS` in canopy-api `endorsed-signer.ts`).
 * Kept numerically identical so the pre-flight admits exactly what canopy
 * admits.
 */
export const ENDORSEMENT_NOT_BEFORE_SKEW_MS = 5 * 60 * 1000;

/** An ADR-0065 §4 refusal: the endorsement is present and not admissible. */
export class EndorsementAdmissionError extends EnvelopeError {
	readonly reason: EndorsementAdmissionReason;
	constructor(reason: EndorsementAdmissionReason, detail: string) {
		super(`session-key endorsement refused (${reason}): ${detail}`);
		this.reason = reason;
	}
}

export interface ResolveEnvelopeSignerOptions {
	/** The pinned log root, raw P-256 x‖y (64 bytes) — the grant's `grantData`. */
	rootPublicKeyXY: Uint8Array;
	/**
	 * Require UV on the endorsement gesture. At canopy this is the grant's
	 * `GF_REQUIRES_USER_VERIFICATION`; the DO's `USER_ROOT_REQUIRE_UV` must
	 * agree with the flag it asks the authority for (ADR-0064 §3).
	 */
	requireUserVerification: boolean;
	/**
	 * The window check. Admission (the DO, canopy) checks against ITS clock
	 * with canopy's `notBefore` skew. An OFFLINE verifier must pass
	 * `'receipt-rung'` instead: a valid receipt verifies forever, so the
	 * window is checked against the receipted idtimestamp inside
	 * `verifyEndorsedLeaf`, never against wall-clock — this resolver then
	 * only establishes the signer chain (root → endorsement → session key).
	 */
	clock: { nowMs: number; skewMs?: number } | 'receipt-rung';
	logPrefix?: string;
}

export type EnvelopeSignerResolution =
	/** No endorsement: the leaf binds to the root itself (4a custody). */
	| { kind: 'root'; signerPublicKeyXY: Uint8Array }
	/** Endorsement verified: the leaf binds to the endorsed session key. */
	| {
			kind: 'endorsed';
			signerPublicKeyXY: Uint8Array;
			endorsement: Uint8Array;
			notBefore: number;
			notAfter: number;
	  };

/**
 * Resolve which key an ES256 envelope must verify under, from the envelope's
 * own -65801 entry (or its absence) and the pinned root. Pure over bytes and
 * the injected clock; throws {@link EndorsementAdmissionError} with the §4
 * reason, {@link EnvelopeError} on structural faults. Does not verify the
 * leaf signature itself — see {@link admitAttestedInputEs256}.
 */
export async function resolveEnvelopeSigner(
	envelope: Uint8Array,
	opts: ResolveEnvelopeSignerOptions
): Promise<EnvelopeSignerResolution> {
	if (opts.rootPublicKeyXY.length !== 64)
		throw new EnvelopeError('root public key must be 64 bytes x‖y');

	let endorsement: Uint8Array | null;
	try {
		endorsement = envelopeEndorsement(envelope);
	} catch (err) {
		if (err instanceof EnvelopeError && /-65801/.test(err.message))
			throw new EndorsementAdmissionError('endorsement_invalid', err.message);
		throw err;
	}
	if (endorsement === null) return { kind: 'root', signerPublicKeyXY: opts.rootPublicKeyXY };

	const verified = await verifySessionKeyEndorsement(
		endorsement,
		{
			x: opts.rootPublicKeyXY.slice(0, 32),
			y: opts.rootPublicKeyXY.slice(32, 64),
			curve: 'P-256'
		},
		{
			requireUserVerification: opts.requireUserVerification,
			logFailures: true,
			logPrefix: opts.logPrefix ?? 'scribe-admission-endorsement'
		}
	);
	if (!verified.ok) {
		// Fold to the §4 vocabulary exactly as canopy does (a malformed window
		// is "expired": no instant is inside it).
		throw new EndorsementAdmissionError(
			endorsementAdmissionReason(verified.reason),
			`verifier reason ${verified.reason}`
		);
	}

	// The window against the clock, on every call — outside any cache.
	if (opts.clock !== 'receipt-rung') {
		const window = checkEndorsementWindow(verified, opts.clock.nowMs, {
			skewMs: opts.clock.skewMs ?? ENDORSEMENT_NOT_BEFORE_SKEW_MS
		});
		if (!window.ok)
			throw new EndorsementAdmissionError(
				window.reason,
				`window [${verified.notBefore}, ${verified.notAfter}] vs clock ${opts.clock.nowMs}`
			);
	}

	return {
		kind: 'endorsed',
		signerPublicKeyXY: verified.sessionPublicKeyXY,
		endorsement,
		notBefore: verified.notBefore,
		notAfter: verified.notAfter
	};
}

export type AdmittedEnvelopeEs256 = VerifiedEnvelopeEs256 & {
	input: string;
	signer: EnvelopeSignerResolution;
};

/**
 * The /turn pre-flight: resolve the signer from the leaf's own bytes, then
 * run the non-negotiable `verifyAttestedInputEs256` (bounds, kid + signature
 * under the RESOLVED key, and the plaintext opening the commitment). Every
 * ES256 path that feeds the model must come through here.
 */
export async function admitAttestedInputEs256(
	envelope: Uint8Array,
	input: string,
	opts: ResolveEnvelopeSignerOptions
): Promise<AdmittedEnvelopeEs256> {
	const signer = await resolveEnvelopeSigner(envelope, opts);
	const verified = await verifyAttestedInputEs256(envelope, input, signer.signerPublicKeyXY);
	return { ...verified, signer };
}
