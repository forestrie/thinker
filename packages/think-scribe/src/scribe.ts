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
import { EnvelopeError, verifyUserEnvelope } from "./forestrie/envelope.ts";
import {
  buildWorkStatementPayload,
  sha256Hex,
  type CommittedStep,
} from "./attestation.ts";

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
const workKey = (workId: string) => `work:${workId}`;
const STEP_BUFFER_KEY = "turn:steps";
const AGENT_LOG_ID_KEY = "forestrie:agentLogId";
const GRANT_B64_KEY = "forestrie:grantB64";
const DELEGATION_EXPIRES_KEY = "forestrie:delegationExpiresAt";
/** Renew the sealing lease when it has less runway than this (seconds). */
const DELEGATION_RENEW_MARGIN_S = 600;

/**
 * A work unit's lifecycle record (plan §7): admitted → turn completed and
 * commitment queued → statement registered (receipt collection is M4).
 */
interface WorkRecord {
  workId: string;
  envelopeB64: string;
  state: "submitted" | "queued" | "registered" | "error";
  submittedAt: number;
  /** Present from "queued": the assembled per-turn commitment. */
  steps?: CommittedStep[];
  outputHash?: string;
  leafId?: string;
  requestId?: string;
  /** Present from "registered". */
  contentHash?: string;
  statusUrl?: string;
  /** Registered statement bytes (base64) — the verify artifact. */
  statementB64?: string;
  error?: string;
}

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
   * The agent's writer credential (grant seam, plan T4). Per-instance: the
   * grant is bound to THIS DO's kid, so it lives in DO storage (set via
   * `/configure-forestrie` for now; request-grant-at-init will store it the
   * same way in M5). Env `GRANT_AGENT` is a single-user dev fallback.
   */
  async grants(): Promise<GrantProvider> {
    const stored = await this.ctx.storage.get<string>(GRANT_B64_KEY);
    const b64 = stored ?? this.env.GRANT_AGENT;
    if (!b64)
      throw new ForestrieUnconfigured(
        "no agent grant configured (storage or GRANT_AGENT)",
      );
    return new ConfiguredGrantProvider(b64);
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
      await (await this.grants()).grantB64(),
    );
    return { kid: bytesToHex(keys.kid()), statement, ...accepted };
  }

  /**
   * Turn admission with user attestation (M3, plan §7): verify the signed
   * input envelope, bind it to the wcc-1 principal, and durably submit the
   * turn under `workId = H(envelope)` — submissionId AND idempotencyKey —
   * so the agent cannot run work under a different id than it commits to.
   */
  async admitAttestedTurn(
    envelopeB64: string,
    principal: string,
  ): Promise<{ workId: string; accepted: boolean; status: string }> {
    const envelope = decodeBase64(envelopeB64);
    const verified = await verifyUserEnvelope(envelope);
    if (verified.address.toLowerCase() !== principal.toLowerCase())
      throw new EnvelopeError(
        "envelope signer does not match the session principal",
      );

    const record: WorkRecord = {
      workId: verified.workId,
      envelopeB64,
      state: "submitted",
      submittedAt: Date.now(),
    };
    await this.ctx.storage.put(workKey(verified.workId), record);

    const submission = await this.submitMessages(
      [
        {
          id: crypto.randomUUID(),
          role: "user" as const,
          parts: [{ type: "text" as const, text: verified.claims.input }],
        },
      ],
      {
        submissionId: verified.workId,
        idempotencyKey: verified.workId,
        metadata: { workId: verified.workId },
      },
    );
    return {
      workId: verified.workId,
      accepted: submission.accepted,
      status: submission.status,
    };
  }

  /**
   * Per-step agent choices (S3: the full AI-SDK step record). Only bounded
   * projections are buffered — tool args/results are hashed, the transcript
   * itself stays in the session ("pipe not store").
   */
  async onStepFinish(ctx: {
    stepNumber?: number;
    finishReason?: string;
    toolCalls?: Array<{ toolName?: string; input?: unknown }>;
    toolResults?: Array<{ toolName?: string; output?: unknown }>;
  }): Promise<void> {
    const encode = (value: unknown) =>
      new TextEncoder().encode(JSON.stringify(value ?? null));
    const step: CommittedStep = {
      stepNumber: ctx.stepNumber ?? 0,
      finishReason: ctx.finishReason ?? "unknown",
      toolCalls: await Promise.all(
        (ctx.toolCalls ?? []).map(async (c) => ({
          toolName: c.toolName ?? "unknown",
          argsHash: await sha256Hex(encode(c.input)),
        })),
      ),
      toolResults: await Promise.all(
        (ctx.toolResults ?? []).map(async (r) => ({
          toolName: r.toolName ?? "unknown",
          resultHash: await sha256Hex(encode(r.output)),
        })),
      ),
    };
    const buffer =
      (await this.ctx.storage.get<CommittedStep[]>(STEP_BUFFER_KEY)) ?? [];
    buffer.push(step);
    await this.ctx.storage.put(STEP_BUFFER_KEY, buffer);
  }

  /**
   * Turn boundary (O3: one statement per turn). Correlate the completed
   * turn back to its admitted work unit via the submission's requestId,
   * assemble the commitment, and hand off to the drain — nothing signs or
   * registers inline in the chat path.
   */
  async onChatResponse(result: {
    message: { id: string; parts?: Array<{ type: string; text?: string }> };
    requestId: string;
    status: "completed" | "error" | "aborted";
    continuation: boolean;
  }): Promise<void> {
    const steps =
      (await this.ctx.storage.get<CommittedStep[]>(STEP_BUFFER_KEY)) ?? [];
    await this.ctx.storage.delete(STEP_BUFFER_KEY);
    if (result.status !== "completed") return;

    // Which admitted work unit ran? submissionId = workId, and the
    // submission inspection carries the turn's requestId.
    const works = await this.ctx.storage.list<WorkRecord>({ prefix: "work:" });
    let matched: WorkRecord | undefined;
    for (const record of works.values()) {
      if (record.state !== "submitted") continue;
      const inspection = await this.inspectSubmission(record.workId);
      if (inspection?.requestId === result.requestId) {
        matched = record;
        break;
      }
    }
    // Turns without an admitted envelope (e.g. raw WS chat) are unattested
    // in cut 1 — the demo client always enters via admitAttestedTurn.
    if (!matched) return;

    const outputText = (result.message.parts ?? [])
      .filter((p) => p.type === "text" && typeof p.text === "string")
      .map((p) => p.text)
      .join("");
    matched.steps = steps;
    matched.outputHash = await sha256Hex(new TextEncoder().encode(outputText));
    matched.leafId = result.message.id;
    matched.requestId = result.requestId;
    matched.state = "queued";
    await this.ctx.storage.put(workKey(matched.workId), matched);
    await this.schedule(1, "drainCommitments", {});
  }

  /**
   * Drain (plan §5 turn admission row + post-M2 decisions): renew the
   * sealing delegation when its lease is short (delegate-at-drain), then
   * sign and register each queued commitment. Runs from a scheduled task,
   * never from the chat path.
   */
  async drainCommitments(): Promise<void> {
    await this.#renewDelegationIfNeeded();
    const works = await this.ctx.storage.list<WorkRecord>({ prefix: "work:" });
    for (const record of works.values()) {
      if (record.state !== "queued") continue;
      try {
        const payload = buildWorkStatementPayload({
          workId: record.workId,
          userEnvelopeB64: record.envelopeB64,
          steps: record.steps ?? [],
          outputHash: record.outputHash ?? "",
          leafId: record.leafId ?? "",
          requestId: record.requestId ?? "",
        });
        const { statement, ...accepted } = await this.signAndRegister(
          payload,
          "application/json",
          `urn:thinker:work:${record.workId}`,
        );
        record.contentHash = accepted.contentHash;
        record.statusUrl = accepted.statusUrl;
        let b64 = "";
        for (const b of statement) b64 += String.fromCharCode(b);
        record.statementB64 = btoa(b64);
        record.state = "registered";
      } catch (err) {
        record.error = String(err);
        record.state = "error";
      }
      await this.ctx.storage.put(workKey(record.workId), record);
    }
  }

  /** Delegate-at-drain: re-lease sealing when under the renewal margin. */
  async #renewDelegationIfNeeded(): Promise<void> {
    const coordinatorUrl = this.env.DELEGATION_COORDINATOR_URL;
    const knownSealerKeyB64 = this.env.KNOWN_SEALER_KEY;
    const logId = await this.ctx.storage.get<string>(AGENT_LOG_ID_KEY);
    if (!coordinatorUrl || !knownSealerKeyB64 || !logId) return;
    const expiresAt =
      (await this.ctx.storage.get<number>(DELEGATION_EXPIRES_KEY)) ?? 0;
    if (expiresAt - Date.now() / 1000 > DELEGATION_RENEW_MARGIN_S) return;
    try {
      const result = await delegateSealing(await this.keys(), {
        coordinatorUrl,
        logId,
        knownSealerKeyB64,
      });
      await this.ctx.storage.put(DELEGATION_EXPIRES_KEY, result.expiresAt);
    } catch (err) {
      // Sequencing still works without the lease; receipts just lag. The
      // next drain retries.
      console.warn("delegation renewal failed", err);
    }
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

    // M3 attested turn admission: the user's signed input envelope enters
    // here; the turn runs durably under workId (plan §7).
    if (request.method === "POST" && url.pathname.endsWith("/turn")) {
      try {
        const body = (await request.json()) as { envelopeB64?: string };
        if (!body.envelopeB64)
          return new Response("envelopeB64 required", { status: 400 });
        const admitted = await this.admitAttestedTurn(body.envelopeB64, principal);
        return Response.json({ principal, ...admitted });
      } catch (err) {
        if (err instanceof EnvelopeError)
          return new Response(err.message, { status: 400 });
        return forestrieProblem(err);
      }
    }

    // Per-instance Forestrie wiring: the grant bound to this DO's kid and
    // the agent's own data log id (provisioned out-of-band for this kid;
    // request-grant-at-init stores the same keys in M5).
    if (
      request.method === "POST" &&
      url.pathname.endsWith("/configure-forestrie")
    ) {
      const body = (await request.json()) as {
        grantB64?: string;
        agentLogId?: string;
      };
      if (!body.grantB64 || !body.agentLogId)
        return new Response("grantB64 and agentLogId required", { status: 400 });
      await this.ctx.storage.put(GRANT_B64_KEY, body.grantB64);
      await this.ctx.storage.put(AGENT_LOG_ID_KEY, body.agentLogId);
      return Response.json({ principal, configured: true });
    }

    // Work-unit lifecycle inspection (harness + later the client UI).
    if (request.method === "GET" && url.pathname.endsWith("/work")) {
      const workId = url.searchParams.get("id");
      if (!workId) return new Response("id query param required", { status: 400 });
      const record = await this.ctx.storage.get<WorkRecord>(workKey(workId));
      if (!record) return new Response("unknown workId", { status: 404 });
      return Response.json(record);
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
        // The agent's own log id: persist so the drain can renew the lease
        // without being told again (until request-grant-at-init carries it).
        await this.ctx.storage.put(AGENT_LOG_ID_KEY, body.logId);
        await this.ctx.storage.put(DELEGATION_EXPIRES_KEY, result.expiresAt);
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
