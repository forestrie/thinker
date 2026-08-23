/**
 * Grant acquisition seam (plan T4/T10). Cut 1 is "configured": the completed
 * grant — a transparent statement carrying its own inclusion receipt
 * (unprotected header 396) — is provisioned out-of-band by
 * `scripts/provision.sh grant <agent x‖y>` and handed to the Worker as an
 * env secret. Later cuts swap in a requesting provider (x402 onboard, §9-C)
 * behind the same interface.
 *
 * Server reality (canopy grants.md §6): a new writer key is endorsed by
 * CREATING a data log whose creation grant names the key in `grantData` —
 * extend-only follow-up grants on an initialized log are not accepted. So
 * "the agent's grant" is the completed creation grant of its own data log,
 * and rotation (new kid) means provisioning a new log for the new key.
 */
export interface GrantProvider {
	/**
	 * The credential for `Authorization: Forestrie-Grant <...>` — base64
	 * (standard or url-safe) of the completed grant transparent statement.
	 */
	grantB64(): Promise<string>;
}

/** Cut-1 provider: a pre-provisioned grant handed in via config/env. */
export class ConfiguredGrantProvider implements GrantProvider {
	constructor(private readonly b64: string) {
		if (!b64) throw new Error('ConfiguredGrantProvider: empty grant');
	}
	grantB64(): Promise<string> {
		return Promise.resolve(this.b64);
	}
}

/**
 * Payment seam (plan §9-C, M5 stub): a commitment string the agent attaches
 * to grant requests, standing in for the x402 onboard flow (canopy
 * `X402_ONBOARD_PRICE_ATOMIC`; 402→USDC) of the self-onboarding future. The
 * authority records it in its books; nothing is enforced yet.
 */
export interface PaymentProvider {
	commitment(kind: 'grant_agent' | 'grant_user', subject: string): Promise<string | null>;
}

/** M5 stub: names the debt without settling it. */
export class StubPaymentProvider implements PaymentProvider {
	commitment(kind: 'grant_agent' | 'grant_user', subject: string): Promise<string | null> {
		return Promise.resolve(`books:demo:${kind}:${subject.slice(0, 18)}`);
	}
}

export interface IssuedGrant {
	/** Completed creation grant (transparent statement), base64. */
	grantB64: string;
	/** The data log the grant created — its grantData names the signer. */
	logId: string;
	/** True when the authority had already issued this grant (pre-issue, O5). */
	preIssued: boolean;
	/**
	 * The batch ceiling (`maxHeight`) the authority sized this grant to
	 * (plan-2608-09 W4a): the prepaid-turns budget the Scribe DO enforces (W4c)
	 * and the unit the x402 gate priced. Absent on agent grants (unbounded).
	 */
	maxHeight?: number;
}

/**
 * Outcome of asking for a user grant (plan-2608-09 W4b). On a payment-gated
 * lane the authority proxies canopy's 402: it returns the `X-PAYMENT-REQUIRED`
 * challenge for the browser wallet to sign, rather than a grant. On a dark
 * lane it issues straight away.
 */
export type UserGrantResult =
	| { kind: 'issued'; grant: IssuedGrant }
	| { kind: 'payment_required'; challengeB64: string; maxHeight: number };

export class GrantRequestError extends Error {}

/**
 * Request-a-grant client (M5, plan §11 O5 / T10): asks the grant authority
 * (scripts/grant-authority.mjs, the mandate-concern stand-in) to endorse a
 * signer. Server reality means "endorse" = create a fresh data log whose
 * creation grant's `grantData` names the key, so the response carries the
 * new log id alongside the completed grant.
 *
 * Under C3 the agent kid is counterfactually derivable, so the authority may
 * have PRE-issued the grant offline — the request then simply collects it
 * (`preIssued: true`), which is the O5 "yes": both paths converge on the
 * same credential for the same kid.
 */
export class GrantAuthorityClient {
	constructor(
		private readonly authorityUrl: string,
		private readonly token?: string,
		private readonly payment: PaymentProvider = new StubPaymentProvider(),
		private readonly fetchImpl: typeof fetch = fetch
	) {
		if (!authorityUrl) throw new GrantRequestError('empty grant authority url');
	}

	/** Raw POST → `{ status, body }`; leaves status interpretation to callers. */
	async #post(
		path: string,
		body: Record<string, unknown>
	): Promise<{ status: number; body: Record<string, unknown> }> {
		const headers: Record<string, string> = { 'Content-Type': 'application/json' };
		if (this.token) headers.Authorization = `Bearer ${this.token}`;
		// Detach before calling: `this.fetchImpl(...)` would invoke fetch with
		// `this` = the client instance — an Illegal Invocation on workerd.
		const doFetch = this.fetchImpl;
		const res = await doFetch(`${this.authorityUrl.replace(/\/$/, '')}${path}`, {
			method: 'POST',
			headers,
			body: JSON.stringify(body)
		});
		const text = await res.text();
		let parsed: Record<string, unknown> = {};
		if (text) {
			try {
				parsed = JSON.parse(text) as Record<string, unknown>;
			} catch {
				throw new GrantRequestError(
					`grant authority ${path}: HTTP ${res.status} non-JSON ${text.slice(0, 200)}`
				);
			}
		}
		return { status: res.status, body: parsed };
	}

	/** Interpret a `{ status, body }` as an issued grant, or throw. */
	#asIssued(path: string, res: { status: number; body: Record<string, unknown> }): IssuedGrant {
		if (res.status >= 400)
			throw new GrantRequestError(
				`grant authority ${path}: HTTP ${res.status} ${JSON.stringify(res.body).slice(0, 200)}`
			);
		const issued = res.body as Partial<IssuedGrant>;
		if (!issued.grantB64 || !issued.logId)
			throw new GrantRequestError(`grant authority ${path}: response missing grantB64/logId`);
		return {
			grantB64: issued.grantB64,
			logId: issued.logId,
			preIssued: issued.preIssued === true,
			maxHeight: typeof issued.maxHeight === 'number' ? issued.maxHeight : undefined
		};
	}

	/** Endorse the agent statement key (`grant_agent`, grantData = x‖y). */
	async requestAgentGrant(publicKeyXY: Uint8Array): Promise<IssuedGrant> {
		let xyHex = '';
		for (const b of publicKeyXY) xyHex += b.toString(16).padStart(2, '0');
		return this.#asIssued(
			'/grants/agent',
			await this.#post('/grants/agent', {
				publicKeyXY: xyHex,
				paymentCommitment: await this.payment.commitment('grant_agent', xyHex)
			})
		);
	}

	/**
	 * Endorse the user's log root (`grant_user`). Two custody shapes
	 * (plan-2608-13 Phase 4a): with `publicKeyXY` (hex, 64-byte P-256 x‖y) the
	 * grantData is the browser-held ES256 root; without it, the legacy 20-byte
	 * KS256 wallet address. The subject — and the payment identity — is the
	 * wcc-1 address either way. On a payment-gated lane (W4b) the authority
	 * answers 402 with the challenge to sign — the caller relays it to the
	 * browser wallet, then calls {@link payUserGrant}. On a dark lane it
	 * issues straight away.
	 */
	async requestUserGrant(
		address: string,
		opts: { renew?: boolean; publicKeyXY?: string; requiresUserVerification?: boolean } = {}
	): Promise<UserGrantResult> {
		const res = await this.#post('/grants/user', {
			address,
			...(opts.publicKeyXY ? { publicKeyXY: opts.publicKeyXY } : {}),
			paymentCommitment: await this.payment.commitment('grant_user', address),
			// Top-up (W4c): bypass the authority's per-address idempotence cache —
			// a new batch is a NEW grant on a new log (O3), never the spent one.
			...(opts.renew ? { renew: true } : {}),
			// Q3 (plan-2608-13 4.4): stamp GF_REQUIRES_USER_VERIFICATION on the
			// grant. Per-log policy — only valid with an ES256 `publicKeyXY` root
			// whose delegations are WebAuthn ceremonies (passkey custody).
			...(opts.requiresUserVerification ? { requiresUserVerification: true } : {})
		});
		if (res.status === 402) {
			const challengeB64 = res.body.challengeB64;
			if (typeof challengeB64 !== 'string' || !challengeB64)
				throw new GrantRequestError('grant authority /grants/user: 402 without challengeB64');
			return {
				kind: 'payment_required',
				challengeB64,
				maxHeight: typeof res.body.maxHeight === 'number' ? res.body.maxHeight : 0
			};
		}
		return { kind: 'issued', grant: this.#asIssued('/grants/user', res) };
	}

	/**
	 * Resubmit the user grant carrying the wallet-signed x402 `X-PAYMENT`
	 * (W4b phase 2). The authority resubmits register-grant → 303 → completes.
	 */
	async payUserGrant(
		address: string,
		xPayment: string,
		opts: { renew?: boolean; publicKeyXY?: string; requiresUserVerification?: boolean } = {}
	): Promise<IssuedGrant> {
		return this.#asIssued(
			'/grants/user',
			await this.#post('/grants/user', {
				address,
				...(opts.publicKeyXY ? { publicKeyXY: opts.publicKeyXY } : {}),
				xPayment,
				...(opts.renew ? { renew: true } : {}),
				...(opts.requiresUserVerification ? { requiresUserVerification: true } : {})
			})
		);
	}
}
