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
