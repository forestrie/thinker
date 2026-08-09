import { createAnthropic } from "@ai-sdk/anthropic";
import { Think, type ThinkModel } from "@cloudflare/think";
import type { Connection, ConnectionContext } from "agents";
import { DoResidentKeyProvider } from "./keys/do-resident.ts";
import { bytesToHex, type KeyProvider } from "./keys/provider.ts";

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
    return super.onRequest(request);
  }
}

class PrincipalError extends Error {
  constructor(
    readonly status: 401 | 403,
    message: string,
  ) {
    super(message);
  }
}
