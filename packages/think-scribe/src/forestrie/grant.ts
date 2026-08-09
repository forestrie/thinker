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
    if (!b64) throw new Error("ConfiguredGrantProvider: empty grant");
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
  commitment(kind: "grant_agent" | "grant_user", subject: string): Promise<string | null>;
}

/** M5 stub: names the debt without settling it. */
export class StubPaymentProvider implements PaymentProvider {
  commitment(kind: "grant_agent" | "grant_user", subject: string): Promise<string | null> {
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
}

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
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    if (!authorityUrl) throw new GrantRequestError("empty grant authority url");
  }

  async #post(path: string, body: Record<string, unknown>): Promise<IssuedGrant> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    // Detach before calling: `this.fetchImpl(...)` would invoke fetch with
    // `this` = the client instance — an Illegal Invocation on workerd.
    const doFetch = this.fetchImpl;
    const res = await doFetch(`${this.authorityUrl.replace(/\/$/, "")}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok)
      throw new GrantRequestError(
        `grant authority ${path}: HTTP ${res.status} ${text.slice(0, 200)}`,
      );
    const issued = JSON.parse(text) as Partial<IssuedGrant>;
    if (!issued.grantB64 || !issued.logId)
      throw new GrantRequestError(`grant authority ${path}: response missing grantB64/logId`);
    return { grantB64: issued.grantB64, logId: issued.logId, preIssued: issued.preIssued === true };
  }

  /** Endorse the agent statement key (`grant_agent`, grantData = x‖y). */
  async requestAgentGrant(publicKeyXY: Uint8Array): Promise<IssuedGrant> {
    let xyHex = "";
    for (const b of publicKeyXY) xyHex += b.toString(16).padStart(2, "0");
    return this.#post("/grants/agent", {
      publicKeyXY: xyHex,
      paymentCommitment: await this.payment.commitment("grant_agent", xyHex),
    });
  }

  /** Endorse the user's wallet key (`grant_user`, grantData = 20-byte address). */
  async requestUserGrant(address: string): Promise<IssuedGrant> {
    return this.#post("/grants/user", {
      address,
      paymentCommitment: await this.payment.commitment("grant_user", address),
    });
  }
}
