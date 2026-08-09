import { createAnthropic } from "@ai-sdk/anthropic";
import { Think, type ThinkModel } from "@cloudflare/think";
import type { Connection, ConnectionContext } from "agents";
import { DoResidentKeyProvider } from "./keys/do-resident.ts";
import { bytesToHex, type KeyProvider } from "./keys/provider.ts";
import { buildSignedStatement } from "./forestrie/cose.ts";
import { ConfiguredGrantProvider, type GrantProvider } from "./forestrie/grant.ts";
import {
  fetchReceipt,
  queryRegistration,
  registerStatement,
  ScrapiError,
} from "./forestrie/register.ts";
import { DelegateError, delegateSealing } from "./forestrie/delegate.ts";

/**
 * Bindings the Scribe needs from its hosting Worker. The app's generated
 * `Env` (wrangler types) must be assignable to this.
 */
export interface ScribeEnv extends Cloudflare.Env {
  /** Anthropic API key (secret: .dev.vars locally, `wrangler secret put` in prod). */
  ANTHROPIC_API_KEY: string;
  /** Model override; defaults to claude-sonnet-5 (plan §11 O2). */
  MODEL_ID?: string;
  /**
   * Base64 32-byte AES-GCM key-encryption key for the DO-resident agent
   * signing key (C2). Secret. Spike S1: workerd cannot persist a CryptoKey
   * (DataCloneError), so the private key is stored wrapped under this and
   * unwrapped to a non-extractable handle on load.
   */
  SCRIBE_KEK: string;
  /**
   * Forestrie write path (M2, plan §6). All three arrive together from
   * `scripts/provision.sh` output — canopy SCRAPI origin, the forest root
   * log id R (registration always goes via the root path; the grant routes
   * the statement to the agent's data log), and the agent's completed
   * writer credential (base64 transparent statement, receipt included).
   * Optional so an unprovisioned dev shell still chats.
   */
  FORESTRIE_BASE_URL?: string;
  FORESTRIE_ROOT_LOG_ID?: string;
  GRANT_AGENT?: string;
  /**
   * Sealing delegation (T9, agent-owned data log): delegation-coordinator
   * origin and the pinned registrar voucher key (base64 x‖y). The agent's
   * log is owned by the agent's key, so the DO itself must authorize the
   * lane's sealer — see forestrie/delegate.ts.
   */
  DELEGATION_COORDINATOR_URL?: string;
  KNOWN_SEALER_KEY?: string;
}

export const DEFAULT_MODEL_ID = "claude-sonnet-5";

/**
 * Header carrying the wcc-1-verified principal `sub` from the Worker edge
 * into the DO. Set ONLY by the edge gate after session verification (which
 * also strips any client-supplied value); the DO trusts it and binds to it
 * on first touch.
 */
export const PRINCIPAL_HEADER = "x-scribe-principal";

const PRINCIPAL_STORAGE_KEY = "scribe:principal";

function decodeBase64(value: string): Uint8Array {
  const bin = atob(value);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * The Scribe — a per-user Think agent (Option B: one DO instance per user)
 * that will produce a tamper-evident, externally verifiable record of the
 * conversation: the user attests to their input, the agent attests to its
 * own choices and outputs (plan §2).
 *
 * M0: a bare Think DO streaming chat via Anthropic.
 * M1: per-instance agent signing key (C2, {@link DoResidentKeyProvider}),
 * principal bound on first touch, `GET …/identity`.
 * The Forestrie commitment path (forestrie/, attestation) lands in M2–M3
 * through the `onStepFinish` → enqueue → drain seam; nothing is signed or
 * registered inline in the chat loop.
 */
export class Scribe<Env extends ScribeEnv = ScribeEnv> extends Think<Env> {
  #keys?: Promise<DoResidentKeyProvider>;

  /**
   * Anthropic via the AI-SDK provider (plan §11 O2). Swappable by design:
   * subclasses or later milestones may return any AI-SDK `LanguageModel`
   * or a Workers-AI / AI-Gateway model id string.
   *
   * Sonnet 5 note: sampling params (`temperature`/`top_p`) are rejected by
   * the model — steer with the system prompt, not sampling.
   */
  getModel(): ThinkModel {
    const anthropic = createAnthropic({ apiKey: this.env.ANTHROPIC_API_KEY });
    return anthropic(this.env.MODEL_ID ?? DEFAULT_MODEL_ID);
  }

  getSystemPrompt(): string {
    return [
      "You are the Scribe, a careful assistant whose conversation is",
      "committed to a public transparency log: the user signs their input,",
      "and you sign your own choices and outputs. Only hashes are logged —",
      "never the transcript itself. Answer plainly and note, when asked,",
      "that this conversation is being made tamper-evident.",
    ].join(" ");
  }

  /**
   * The agent's statement-signing key (custody seam, plan §8). Lazy: the
   * key is created on this instance's first use and persists (wrapped) in
   * DO storage thereafter.
   */
  keys(): Promise<KeyProvider> {
    this.#keys ??= DoResidentKeyProvider.load(
      this.ctx.storage,
      decodeBase64(this.env.SCRIBE_KEK),
    );
    return this.#keys;
  }

  /**
   * The agent's writer credential (grant seam, plan T4). Cut 1: configured
   * from the environment; `GrantProvider.request` variants come later (§9-C).
   */
  grants(): GrantProvider {
    if (!this.env.GRANT_AGENT)
      throw new ForestrieUnconfigured("GRANT_AGENT not set");
    return new ConfiguredGrantProvider(this.env.GRANT_AGENT);
  }

  #forestrieTarget(): { baseUrl: string; rootLogId: string } {
    const baseUrl = this.env.FORESTRIE_BASE_URL;
    const rootLogId = this.env.FORESTRIE_ROOT_LOG_ID;
    if (!baseUrl || !rootLogId)
      throw new ForestrieUnconfigured(
        "FORESTRIE_BASE_URL / FORESTRIE_ROOT_LOG_ID not set",
      );
    return { baseUrl, rootLogId };
  }

  /**
   * Sign a statement with the agent key and register it on the configured
   * forest (T5/T6). Returns the accept — sequencing and the receipt are
   * followed up asynchronously (T7); nothing here waits on the lane.
   */
  async signAndRegister(
    payload: Uint8Array,
    contentType: string,
    sub: string,
  ): Promise<{
    kid: string;
    contentHash: string;
    statusUrl: string;
    /** The registered COSE Sign1 — verification needs the exact bytes. */
    statement: Uint8Array;
  }> {
    const { baseUrl, rootLogId } = this.#forestrieTarget();
    const keys = await this.keys();
    const statement = await buildSignedStatement(keys, {
      payload,
      contentType,
      sub,
    });
    const accepted = await registerStatement(
      baseUrl,
      rootLogId,
      statement,
      await this.grants().grantB64(),
    );
    return { kid: bytesToHex(keys.kid()), statement, ...accepted };
  }

  /**
   * Bind-on-first-touch (plan §4): the first verified principal to reach
   * this instance is stored; every later request must present the same one.
   * Defense-in-depth behind the edge gate's name check — a misrouted or
   * misconfigured caller cannot adopt someone else's instance.
   */
  async #ensurePrincipal(sub: string | null): Promise<string> {
    if (!sub) throw new PrincipalError(401, "missing principal");
    const bound = await this.ctx.storage.get<string>(PRINCIPAL_STORAGE_KEY);
    if (bound === undefined) {
      await this.ctx.storage.put(PRINCIPAL_STORAGE_KEY, sub);
      return sub;
    }
    if (bound !== sub)
      throw new PrincipalError(403, "principal does not match bound instance owner");
    return bound;
  }

  async onConnect(connection: Connection, ctx: ConnectionContext): Promise<void> {
    try {
      await this.#ensurePrincipal(ctx.request.headers.get(PRINCIPAL_HEADER));
    } catch (err) {
      const status = err instanceof PrincipalError ? err.status : 500;
      connection.close(4000 + status, String(err));
      return;
    }
    return super.onConnect(connection, ctx);
  }

  async onRequest(request: Request): Promise<Response> {
    let principal: string;
    try {
      principal = await this.#ensurePrincipal(request.headers.get(PRINCIPAL_HEADER));
    } catch (err) {
      const status = err instanceof PrincipalError ? err.status : 500;
      return new Response(String(err), { status });
    }

    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname.endsWith("/identity")) {
      const keys = await this.keys();
      return Response.json({
        principal,
        alg: "ES256",
        epoch: (keys as DoResidentKeyProvider).epoch?.() ?? 1,
        kid: bytesToHex(keys.kid()),
        publicKeyXY: bytesToHex(await keys.publicKeyXY()),
      });
    }

    // M2 write-path harness (S4): sign an arbitrary payload and register it.
    // The real commitment path (M3) goes onStepFinish → enqueue → drain and
    // never signs in a request handler; this endpoint exists so the smoke
    // test can drive T5–T8 end-to-end from workerd.
    if (request.method === "POST" && url.pathname.endsWith("/register-test")) {
      try {
        const body = (await request.json()) as { payload?: unknown; sub?: string };
        const payload = new TextEncoder().encode(
          JSON.stringify(body.payload ?? { probe: "m2" }),
        );
        const sub = body.sub ?? `urn:thinker:m2:${crypto.randomUUID()}`;
        const { statement, ...accepted } = await this.signAndRegister(
          payload,
          "application/json",
          sub,
        );
        let statementB64 = "";
        for (const b of statement) statementB64 += String.fromCharCode(b);
        return Response.json({
          principal,
          sub,
          statementB64: btoa(statementB64),
          ...accepted,
        });
      } catch (err) {
        return forestrieProblem(err);
      }
    }

    // Authorize the lane's sealer for the agent's own data log (T9). The
    // log id arrives from the provisioner for now; the request-grant-at-init
    // path (M5) will carry it with the grant.
    if (request.method === "POST" && url.pathname.endsWith("/delegate-sealing")) {
      const coordinatorUrl = this.env.DELEGATION_COORDINATOR_URL;
      const knownSealerKeyB64 = this.env.KNOWN_SEALER_KEY;
      if (!coordinatorUrl || !knownSealerKeyB64)
        return new Response(
          "forestrie not configured: DELEGATION_COORDINATOR_URL / KNOWN_SEALER_KEY not set",
          { status: 503 },
        );
      try {
        const body = (await request.json()) as { logId?: string };
        if (!body.logId) return new Response("logId required", { status: 400 });
        const result = await delegateSealing(await this.keys(), {
          coordinatorUrl,
          logId: body.logId,
          knownSealerKeyB64,
        });
        return Response.json({ principal, ...result });
      } catch (err) {
        return forestrieProblem(err);
      }
    }

    // Poll a registration from workerd: status 303 loop, then the receipt.
    if (request.method === "GET" && url.pathname.endsWith("/registration")) {
      const statusUrl = url.searchParams.get("status");
      const receiptUrl = url.searchParams.get("receipt");
      try {
        if (receiptUrl) {
          const receipt = await fetchReceipt(receiptUrl);
          return receipt.state === "ready"
            ? new Response(receipt.receipt as BodyInit, {
                headers: {
                  "Content-Type": receipt.contentType ?? "application/octet-stream",
                },
              })
            : Response.json({ state: "pending" }, { status: 202 });
        }
        if (statusUrl) return Response.json(await queryRegistration(statusUrl));
        return new Response("status or receipt query param required", { status: 400 });
      } catch (err) {
        return forestrieProblem(err);
      }
    }
    return super.onRequest(request);
  }
}

function forestrieProblem(err: unknown): Response {
  if (err instanceof ForestrieUnconfigured)
    return new Response(`forestrie not configured: ${err.message}`, { status: 503 });
  if (err instanceof ScrapiError || err instanceof DelegateError)
    return new Response(err.message, { status: 502 });
  return new Response(String(err), { status: 500 });
}

class ForestrieUnconfigured extends Error {}

class PrincipalError extends Error {
  constructor(
    readonly status: 401 | 403,
    message: string,
  ) {
    super(message);
  }
}
