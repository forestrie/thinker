import { createAnthropic } from "@ai-sdk/anthropic";
import { Think, type ThinkModel } from "@cloudflare/think";
import type { Connection, ConnectionContext } from "agents";
import { DoResidentKeyProvider } from "./keys/do-resident.ts";
import { KmsSeedKeyProvider, localSeedCustodianMac } from "./keys/kms-seed.ts";
import { bytesToHex, type KeyProvider } from "./keys/provider.ts";
import { buildSignedStatement } from "./forestrie/cose.ts";
import {
  ConfiguredGrantProvider,
  GrantAuthorityClient,
  type GrantProvider,
  type IssuedGrant,
} from "./forestrie/grant.ts";
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
  /**
   * Key custody selection (M5, plan §8/D4): "do-resident" (C2, default) or
   * "kms-seed" (C3 — derive from the custodian seed; kid counterfactually
   * derivable offline, which is what enables grant pre-issue, O5).
   */
  KEY_PROVIDER?: "do-resident" | "kms-seed";
  /** C3 dev custodian seed: base64 32 bytes (prod: a narrow KMS MAC endpoint). */
  KMS_SEED_SECRET?: string;
  /** C3 key epoch (operator-maintained integer, ADR-0050 grammar). Default 1. */
  AGENT_KEY_EPOCH?: string;
  /**
   * Grant authority (M5, GrantProvider.request): when set, the DO requests
   * its own writer credentials at init — `grant_agent` for its kid, and in
   * separate-leaf mode `grant_user` for the bound principal's wallet.
   */
  GRANT_AUTHORITY_URL?: string;
  GRANT_AUTHORITY_TOKEN?: string;
  /**
   * O4 user-attestation shape: "embed" (default — the envelope rides inside
   * the agent's leaf only) or "separate" (M5 flip — the envelope is ALSO
   * registered as its own leaf under `grant_user`, making "the user said
   * this" an independent, separately-receipted log entry).
   */
  ATTESTATION_MODE?: "embed" | "separate";
  /**
   * W4d offline parent-policy proof (plan-2608-09): the completed
   * user-authority creation grant (base64 transparent statement, receipt
   * included) and the forest root's public key (hex 64-byte x||y) as its
   * trust anchor. Provisioning artifacts (`provision.sh config`), surfaced
   * verbatim on `/identity` so the browser can prove the user grant's parent
   * carries `requiresChildPayment` without trusting this worker.
   */
  GRANT_USER_AUTHORITY?: string;
  FORESTRIE_ROOT_PUBLIC_KEY_XY?: string;
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
/** The kid (hex) the stored agent grant endorses — re-request on mismatch. */
const GRANT_KID_KEY = "forestrie:grantKid";
const USER_GRANT_B64_KEY = "forestrie:userGrantB64";
const USER_LOG_ID_KEY = "forestrie:userLogId";
/**
 * A pending x402 `X-PAYMENT-REQUIRED` challenge (base64) for the user grant
 * (plan-2608-09 W4b): stored when the authority proxies canopy's 402, exposed
 * on `/identity` for the browser wallet to sign, and cleared once
 * `/pay-user-grant` completes. Only set on a payment-gated lane.
 */
const USER_GRANT_CHALLENGE_KEY = "forestrie:userGrantChallenge";
/** The purchased grant's batch ceiling (maxHeight) — seeds prepaidTurns (W4c). */
const USER_GRANT_MAXHEIGHT_KEY = "forestrie:userGrantMaxHeight";
/**
 * Turns remaining in the purchased batch (W4c): seeded from the grant's
 * maxHeight when it is stored, decremented per admitted turn, refused at
 * zero. Absent = unmetered (embed mode, or no batch ceiling recorded).
 */
const PREPAID_TURNS_KEY = "forestrie:prepaidTurns";
/**
 * Set while a top-up purchase is in flight (W4c): the spent grant has been
 * dropped and the next user-grant request must tell the authority to bypass
 * its per-address idempotence cache (a NEW grant and log per batch, O3).
 * Cleared when the fresh grant is stored.
 */
const USER_GRANT_RENEWAL_KEY = "forestrie:userGrantRenewal";
/**
 * Set (epoch ms) when the CLIENT confirms the wallet signed a sealing
 * delegation for the user's log. User leaves are HELD until then — the
 * provision.sh ordering (prepare → delegate → create) applied to the user
 * flow: never register a leaf into a log nothing is authorized to seal.
 */
const USER_SEALING_DELEGATED_KEY = "forestrie:userSealingDelegatedAt";
const DELEGATION_EXPIRES_KEY = "forestrie:delegationExpiresAt";
/** Renew the sealing lease when it has less runway than this (seconds). */
const DELEGATION_RENEW_MARGIN_S = 600;
/** Receipt collection cadence (T7→T8). Sequencing is seconds; sealing is
 * minutes-latent (T9) — poll gently from a scheduled task, never inline. */
const RECEIPT_POLL_S = 10;
/** Give up on a work unit's receipt after this many polls (~20 min). */
const MAX_RECEIPT_POLLS = 120;
const COLLECT_CALLBACK = "collectReceipts";

/**
 * A work unit's lifecycle record (plan §7): admitted → turn completed and
 * commitment queued → statement registered → sequenced → receipt collected
 * (M4, T7→T8).
 */
interface WorkRecord {
  workId: string;
  envelopeB64: string;
  state:
    | "submitted"
    | "queued"
    | "registered"
    | "sequenced"
    | "receipted"
    | "error";
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
  /** Present from "sequenced". */
  entryId?: string;
  receiptUrl?: string;
  /** Present from "receipted": the sealed COSE receipt (base64). */
  receiptB64?: string;
  receiptedAt?: number;
  /** Scheduled-collection bookkeeping. */
  pollAttempts?: number;
  error?: string;
  /**
   * O4 separate mode (M5): the user's envelope registered as its OWN leaf
   * under `grant_user` on the user's log — same lifecycle as the agent leaf,
   * advanced by the same scheduled collector. Absent in embed mode; an
   * `error` state here never blocks the agent leaf (graceful fallback).
   * "held" = awaiting the user's sealing authorization (not yet registered).
   */
  userLeaf?: {
    state: "held" | "registered" | "sequenced" | "receipted" | "error";
    contentHash?: string;
    statusUrl?: string;
    entryId?: string;
    receiptUrl?: string;
    receiptB64?: string;
    receiptedAt?: number;
    pollAttempts?: number;
    error?: string;
  };
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
  #keys?: Promise<KeyProvider>;

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
   * The agent's statement-signing key (custody seam, plan §8). Selection is
   * config-only (D4): C2 keeps a wrapped key in DO storage; C3 re-derives
   * from the custodian seed + the bound principal + epoch — nothing stored,
   * and the kid is knowable offline before this instance ever runs (O5).
   */
  keys(): Promise<KeyProvider> {
    this.#keys ??= this.#loadKeys();
    return this.#keys;
  }

  async #loadKeys(): Promise<KeyProvider> {
    if ((this.env.KEY_PROVIDER ?? "do-resident") === "kms-seed") {
      if (!this.env.KMS_SEED_SECRET)
        throw new ForestrieUnconfigured("KEY_PROVIDER=kms-seed needs KMS_SEED_SECRET");
      const sub = await this.ctx.storage.get<string>(PRINCIPAL_STORAGE_KEY);
      if (!sub)
        throw new ForestrieUnconfigured(
          "kms-seed derivation needs the bound principal — no principal bound yet",
        );
      return KmsSeedKeyProvider.load(
        localSeedCustodianMac(decodeBase64(this.env.KMS_SEED_SECRET)),
        sub,
        Number(this.env.AGENT_KEY_EPOCH ?? "1"),
      );
    }
    return DoResidentKeyProvider.load(
      this.ctx.storage,
      decodeBase64(this.env.SCRIBE_KEK),
    );
  }

  #authority(): GrantAuthorityClient | null {
    if (!this.env.GRANT_AUTHORITY_URL) return null;
    return new GrantAuthorityClient(
      this.env.GRANT_AUTHORITY_URL,
      this.env.GRANT_AUTHORITY_TOKEN,
    );
  }

  /**
   * The agent's writer credential (grant seam, plan T4), keyed to the
   * CURRENT kid. Resolution order:
   *
   *  1. DO storage, if the stored grant endorses this kid (configured via
   *     `/configure-forestrie`, or a previous request).
   *  2. Request-at-init (M5, GrantProvider.request): ask the authority to
   *     endorse the kid. Under C3 the authority has typically PRE-issued the
   *     grant on the offline-derived kid (O5) and this collects it; a kid
   *     rotation lands here too and re-requests.
   *  3. Env `GRANT_AGENT` — single-user dev fallback.
   */
  async grants(): Promise<GrantProvider> {
    const keys = await this.keys();
    const kidHex = bytesToHex(keys.kid());
    const stored = await this.ctx.storage.get<string>(GRANT_B64_KEY);
    const storedKid = await this.ctx.storage.get<string>(GRANT_KID_KEY);
    if (stored && (storedKid === undefined || storedKid === kidHex))
      return new ConfiguredGrantProvider(stored);

    const authority = this.#authority();
    if (authority) {
      const issued = await authority.requestAgentGrant(await keys.publicKeyXY());
      await this.ctx.storage.put(GRANT_B64_KEY, issued.grantB64);
      await this.ctx.storage.put(GRANT_KID_KEY, kidHex);
      await this.ctx.storage.put(AGENT_LOG_ID_KEY, issued.logId);
      return new ConfiguredGrantProvider(issued.grantB64);
    }

    if (this.env.GRANT_AGENT) return new ConfiguredGrantProvider(this.env.GRANT_AGENT);
    throw new ForestrieUnconfigured(
      "no agent grant: configure one, set GRANT_AUTHORITY_URL, or set GRANT_AGENT",
    );
  }

  #attestationMode(): "embed" | "separate" {
    return this.env.ATTESTATION_MODE === "separate" ? "separate" : "embed";
  }

  /**
   * The user's writer credential (O4 separate leaf): `grant_user` endorsing
   * the bound principal's wallet address, requested from the authority on
   * first need and stored. Returns null when not in separate mode or no
   * authority is configured — callers fall back to embed-only.
   */
  async #userGrant(): Promise<{ grantB64: string; logId: string } | null> {
    if (this.#attestationMode() !== "separate") return null;
    const storedGrant = await this.ctx.storage.get<string>(USER_GRANT_B64_KEY);
    const storedLog = await this.ctx.storage.get<string>(USER_LOG_ID_KEY);
    if (storedGrant && storedLog) return { grantB64: storedGrant, logId: storedLog };
    // A pending payment challenge means we already asked and canopy 402'd:
    // the browser must sign before we can issue. Don't re-hit the authority
    // every drain — the wallet drives completion via `/pay-user-grant` (W4b).
    if (await this.ctx.storage.get<string>(USER_GRANT_CHALLENGE_KEY)) return null;
    const authority = this.#authority();
    if (!authority) return null;
    const principal = await this.ctx.storage.get<string>(PRINCIPAL_STORAGE_KEY);
    if (!principal) return null;
    const renew =
      (await this.ctx.storage.get<boolean>(USER_GRANT_RENEWAL_KEY)) === true;
    const result = await authority.requestUserGrant(principal, { renew });
    if (result.kind === "payment_required") {
      // Park the challenge for the browser; stay embed-only until it's paid.
      await this.ctx.storage.put(USER_GRANT_CHALLENGE_KEY, result.challengeB64);
      await this.ctx.storage.put(USER_GRANT_MAXHEIGHT_KEY, result.maxHeight);
      return null;
    }
    return this.#storeUserGrant(result.grant);
  }

  /** Persist an issued user grant + its batch ceiling; clear any challenge. */
  async #storeUserGrant(grant: IssuedGrant): Promise<{ grantB64: string; logId: string }> {
    // A different logId means a NEW batch log (top-up, O3): the wallet's
    // sealing authorization was for the old log, so its leaves must hold
    // until the wallet delegates the new one.
    const previousLogId = await this.ctx.storage.get<string>(USER_LOG_ID_KEY);
    if (previousLogId !== undefined && previousLogId !== grant.logId)
      await this.ctx.storage.delete(USER_SEALING_DELEGATED_KEY);
    await this.ctx.storage.put(USER_GRANT_B64_KEY, grant.grantB64);
    await this.ctx.storage.put(USER_LOG_ID_KEY, grant.logId);
    if (typeof grant.maxHeight === "number") {
      await this.ctx.storage.put(USER_GRANT_MAXHEIGHT_KEY, grant.maxHeight);
      // The purchased batch IS the turn budget (W4c).
      await this.ctx.storage.put(PREPAID_TURNS_KEY, grant.maxHeight);
    }
    await this.ctx.storage.delete(USER_GRANT_CHALLENGE_KEY);
    await this.ctx.storage.delete(USER_GRANT_RENEWAL_KEY);
    return { grantB64: grant.grantB64, logId: grant.logId };
  }

  /**
   * Prepaid-turn balance (W4c). `null` = unmetered: embed mode, or no batch
   * ceiling on record (no user grant yet — nothing was purchased). Grants
   * stored before this key existed seed lazily from the recorded ceiling.
   */
  async #prepaidTurns(): Promise<number | null> {
    if (this.#attestationMode() !== "separate") return null;
    const balance = await this.ctx.storage.get<number>(PREPAID_TURNS_KEY);
    if (balance !== undefined) return balance;
    if ((await this.ctx.storage.get<string>(USER_GRANT_B64_KEY)) === undefined) return null;
    const ceiling = await this.ctx.storage.get<number>(USER_GRANT_MAXHEIGHT_KEY);
    if (ceiling === undefined) return null;
    await this.ctx.storage.put(PREPAID_TURNS_KEY, ceiling);
    return ceiling;
  }

  /**
   * The batch is exhausted: top-up = repeat the W4b purchase (a NEW grant
   * and log per batch, O3). Drop the spent grant so {@link #userGrant}
   * re-requests, flag the request a renewal so the authority bypasses its
   * idempotence cache, and kick acquisition off the request path — on a paid
   * lane a fresh challenge parks for the browser wallet to sign; on a dark
   * lane the new batch issues straight away. Idempotent while in flight.
   */
  async #beginTopUp(): Promise<void> {
    if ((await this.ctx.storage.get<boolean>(USER_GRANT_RENEWAL_KEY)) === true) return;
    await this.ctx.storage.put(USER_GRANT_RENEWAL_KEY, true);
    await this.ctx.storage.delete(USER_GRANT_B64_KEY);
    await this.ctx.storage.delete(USER_LOG_ID_KEY);
    await this.schedule(0, "acquireUserGrant", {});
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

    // Prepaid-turn metering (W4c): each NEW admitted turn spends one turn of
    // the purchased batch, before any work runs. Refuse at zero and start
    // the top-up purchase so the browser finds a fresh challenge to pay. A
    // re-submitted envelope (same workId) is not a new turn — never double-
    // spend on the idempotent path.
    if ((await this.ctx.storage.get<WorkRecord>(workKey(verified.workId))) === undefined) {
      const balance = await this.#prepaidTurns();
      if (balance !== null) {
        if (balance <= 0) {
          await this.#beginTopUp();
          throw new TurnsExhausted();
        }
        await this.ctx.storage.put(PREPAID_TURNS_KEY, balance - 1);
      }
    }

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
    // O4 separate mode: acquire (or collect) grant_user once per drain. A
    // failure here degrades to embed-only for this drain — the agent leaf
    // still registers, and the next drain retries.
    let userGrant: { grantB64: string; logId: string } | null = null;
    try {
      userGrant = await this.#userGrant();
    } catch (err) {
      console.warn("user grant acquisition failed — embed-only this drain", err);
    }
    const works = await this.ctx.storage.list<WorkRecord>({ prefix: "work:" });
    const sealingDelegated =
      (await this.ctx.storage.get<number>(USER_SEALING_DELEGATED_KEY)) !== undefined;
    let registered = false;
    for (const record of works.values()) {
      // Release pass: leaves held while the user hadn't authorized sealing
      // register now, regardless of how far the agent side has advanced.
      if (userGrant && sealingDelegated && record.userLeaf?.state === "held") {
        record.userLeaf = await this.#registerUserLeaf(record, userGrant.grantB64);
        if (record.userLeaf.state === "registered") registered = true;
        await this.ctx.storage.put(workKey(record.workId), record);
      }
      if (record.state !== "queued") continue;
      // The user's leaf: the signed envelope registered AS-IS under
      // grant_user — it already is a valid KS256 COSE Sign1 statement whose
      // kid (the wallet address) matches the grant's grantData. Cross-ref to
      // the agent leaf is the stable workId = H(envelope) (no ordering
      // dependency; sequencing is async). Until the wallet has authorized
      // sealing for the user's log, the leaf is HELD, not registered — a
      // leaf that sequences before any delegation exists cannot seal until
      // the sealer's slow retry, and its receipt poll budget burns down
      // waiting (the 2026-08-10 stall).
      if (userGrant && !record.userLeaf) {
        if (!sealingDelegated) {
          record.userLeaf = { state: "held" };
        } else {
          record.userLeaf = await this.#registerUserLeaf(record, userGrant.grantB64);
          if (record.userLeaf.state === "registered") registered = true;
        }
      }
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
        registered = true;
      } catch (err) {
        record.error = String(err);
        record.state = "error";
      }
      await this.ctx.storage.put(workKey(record.workId), record);
    }
    if (registered) {
      // Re-check the sealing lease AFTER registering: on the drain that
      // first acquires the grant, agentLogId is only stored inside the loop
      // (request-at-init), so the pre-loop check had nothing to lease —
      // without this, a fresh instance's leaves sequence but never seal
      // until a second turn happens to drain again.
      await this.#renewDelegationIfNeeded();
      await this.#ensureReceiptCollection(2);
    }
  }

  /** Register the user's envelope as its own leaf under grant_user. */
  async #registerUserLeaf(
    record: WorkRecord,
    grantB64: string,
  ): Promise<NonNullable<WorkRecord["userLeaf"]>> {
    try {
      const { baseUrl, rootLogId } = this.#forestrieTarget();
      const accepted = await registerStatement(
        baseUrl,
        rootLogId,
        decodeBase64(record.envelopeB64),
        grantB64,
      );
      return {
        state: "registered",
        contentHash: accepted.contentHash,
        statusUrl: accepted.statusUrl,
      };
    } catch (err) {
      return { state: "error", error: String(err) };
    }
  }

  /**
   * Grant-at-bind (UX ordering, 2026-08-10): the user's address is known
   * the moment the principal binds, so `grant_user` (and with it the user's
   * log) is requested right away from a scheduled task — the authorize-
   * sealing step can then happen during onboarding, BEFORE the first turn,
   * and the first user leaf seals on the sealer's first reactive attempt.
   * Failures are logged; the drain's request path remains the fallback.
   */
  async acquireUserGrant(): Promise<void> {
    try {
      await this.#userGrant();
    } catch (err) {
      console.warn("grant-at-bind user grant acquisition failed — drain will retry", err);
    }
  }

  /**
   * Scheduled receipt collection (M4, T7→T8): advance every in-flight work
   * unit one step — status poll until sequenced, then receipt fetch until
   * the covering checkpoint seals — and reschedule while any remain. Runs
   * only from the schedule alarm; the chat path never waits on the lane.
   */
  async collectReceipts(): Promise<void> {
    const works = await this.ctx.storage.list<WorkRecord>({ prefix: "work:" });
    let pending = false;
    const inFlight = (s: string) => s === "registered" || s === "sequenced";
    for (const record of works.values()) {
      const agentInFlight = inFlight(record.state);
      const userInFlight = record.userLeaf ? inFlight(record.userLeaf.state) : false;
      if (!agentInFlight && !userInFlight) continue;

      if (agentInFlight) {
        record.pollAttempts = (record.pollAttempts ?? 0) + 1;
        if (record.pollAttempts > MAX_RECEIPT_POLLS) {
          record.error = `receipt collection gave up after ${MAX_RECEIPT_POLLS} polls`;
          record.state = "error";
        } else {
          try {
            if (record.state === "registered" && record.statusUrl) {
              const status = await queryRegistration(record.statusUrl);
              if (status.state === "sequenced") {
                record.entryId = status.entryId;
                record.receiptUrl = status.receiptUrl;
                record.state = "sequenced";
              }
            }
            if (record.state === "sequenced" && record.receiptUrl) {
              const receipt = await fetchReceipt(record.receiptUrl);
              if (receipt.state === "ready") {
                let b64 = "";
                for (const b of receipt.receipt) b64 += String.fromCharCode(b);
                record.receiptB64 = btoa(b64);
                record.receiptedAt = Date.now();
                record.state = "receipted";
              }
            }
          } catch (err) {
            // Transient lane errors: keep the record in flight; the attempt
            // cap bounds how long we retry.
            console.warn(`receipt poll failed for ${record.workId}`, err);
          }
        }
      }

      // The user leaf follows the identical status→receipt ladder on the
      // user's log. Its sealing needs the USER's delegation (client-side,
      // KS256) — until that lands, it simply stays "sequenced".
      const leaf = record.userLeaf;
      if (leaf && inFlight(leaf.state)) {
        leaf.pollAttempts = (leaf.pollAttempts ?? 0) + 1;
        if (leaf.pollAttempts > MAX_RECEIPT_POLLS) {
          leaf.error = `user-leaf receipt collection gave up after ${MAX_RECEIPT_POLLS} polls`;
          leaf.state = "error";
        } else {
          try {
            if (leaf.state === "registered" && leaf.statusUrl) {
              const status = await queryRegistration(leaf.statusUrl);
              if (status.state === "sequenced") {
                leaf.entryId = status.entryId;
                leaf.receiptUrl = status.receiptUrl;
                leaf.state = "sequenced";
              }
            }
            if (leaf.state === "sequenced" && leaf.receiptUrl) {
              const receipt = await fetchReceipt(leaf.receiptUrl);
              if (receipt.state === "ready") {
                let b64 = "";
                for (const b of receipt.receipt) b64 += String.fromCharCode(b);
                leaf.receiptB64 = btoa(b64);
                leaf.receiptedAt = Date.now();
                leaf.state = "receipted";
              }
            }
          } catch (err) {
            console.warn(`user-leaf receipt poll failed for ${record.workId}`, err);
          }
        }
      }

      if (inFlight(record.state) || (record.userLeaf && inFlight(record.userLeaf.state)))
        pending = true;
      await this.ctx.storage.put(workKey(record.workId), record);
    }
    if (pending) await this.#ensureReceiptCollection(RECEIPT_POLL_S);
  }

  /**
   * Schedule the collector unless a FUTURE run is already booked. The dedupe
   * must ignore past-due rows: the SDK deletes a one-shot schedule row only
   * AFTER its callback completes, so during collectReceipts its own row is
   * still listed — matching on it would stall the chain.
   */
  async #ensureReceiptCollection(delaySeconds: number): Promise<void> {
    const now = Date.now() / 1000;
    const schedules = await this.listSchedules();
    if (schedules.some((s) => s.callback === COLLECT_CALLBACK && s.time > now))
      return;
    await this.schedule(delaySeconds, COLLECT_CALLBACK, {});
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
   * The DO's current claim of the assistant's output for a turn's leaf,
   * straight from Think's session store. Must mirror how onChatResponse
   * derived outputHash (join of the message's text parts) so an untampered
   * record round-trips to the committed hash exactly.
   */
  #currentOutputText(leafId: string): string | null {
    try {
      const rows = this.sql<{ content: string }>`
        SELECT content FROM assistant_messages WHERE id = ${leafId}
      `;
      if (!rows.length) return null;
      const message = JSON.parse(rows[0]!.content) as {
        parts?: Array<{ type: string; text?: string }>;
      };
      return (message.parts ?? [])
        .filter((p) => p.type === "text" && typeof p.text === "string")
        .map((p) => p.text)
        .join("");
    } catch {
      return null;
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
      // Grant-at-bind: kick user-grant acquisition off the request path —
      // issuance waits on an auth-log seal (up to ~a minute) and nothing
      // here should block on it.
      if (this.#attestationMode() === "separate" && this.env.GRANT_AUTHORITY_URL)
        await this.schedule(0, "acquireUserGrant", {});
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
        keyProvider: this.env.KEY_PROVIDER ?? "do-resident",
        attestationMode: this.#attestationMode(),
        epoch: (keys as { epoch?: () => number }).epoch?.() ?? 1,
        kid: bytesToHex(keys.kid()),
        publicKeyXY: bytesToHex(await keys.publicKeyXY()),
        agentLogId: (await this.ctx.storage.get<string>(AGENT_LOG_ID_KEY)) ?? null,
        userLogId: (await this.ctx.storage.get<string>(USER_LOG_ID_KEY)) ?? null,
        userSealingDelegated:
          (await this.ctx.storage.get<number>(USER_SEALING_DELEGATED_KEY)) !== undefined,
        // A pending x402 challenge (W4b) the browser wallet must sign to buy
        // the user grant; null on dark lanes and once paid.
        userGrantChallenge:
          (await this.ctx.storage.get<string>(USER_GRANT_CHALLENGE_KEY)) ?? null,
        // Turns remaining in the purchased batch (W4c); null = unmetered.
        prepaidTurns:
          (await this.ctx.storage.get<number>(PREPAID_TURNS_KEY)) ?? null,
        // W4d offline parent-policy proof: the completed user-authority
        // creation grant (receipt included) and the forest root's public key
        // as its trust anchor, both provisioning artifacts handed in via env.
        userAuthorityGrant: this.env.GRANT_USER_AUTHORITY ?? null,
        rootPublicKeyXY: this.env.FORESTRIE_ROOT_PUBLIC_KEY_XY ?? null,
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
        if (err instanceof TurnsExhausted)
          // 402 with a top-up affordance (W4c): the DO has already dropped
          // the spent grant and re-requested — the client polls up the fresh
          // challenge and repeats the W4b purchase.
          return Response.json(
            { error: err.message, topUp: true, prepaidTurns: 0 },
            { status: 402 },
          );
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
      // The hand-configured grant endorses the CURRENT kid (the caller read
      // it from /identity) — record the binding so grants() honours it.
      await this.ctx.storage.put(GRANT_KID_KEY, bytesToHex((await this.keys()).kid()));
      return Response.json({ principal, configured: true });
    }

    // Receipt export (M4): every work unit with its verify artifacts, plus
    // what this DO CURRENTLY claims the assistant said for each leaf — read
    // live from the session store, so verification catches any divergence
    // between the DO's memory and the receipted commitment (the tamper beat).
    if (request.method === "GET" && url.pathname.endsWith("/receipts")) {
      const keys = await this.keys();
      const works = await this.ctx.storage.list<WorkRecord>({ prefix: "work:" });
      const exported = [...works.values()]
        .sort((a, b) => a.submittedAt - b.submittedAt)
        .map((record) => ({
          workId: record.workId,
          state: record.state,
          submittedAt: record.submittedAt,
          envelopeB64: record.envelopeB64,
          statementB64: record.statementB64,
          contentHash: record.contentHash,
          entryId: record.entryId,
          receiptB64: record.receiptB64,
          receiptedAt: record.receiptedAt,
          leafId: record.leafId,
          error: record.error,
          userLeaf: record.userLeaf ?? null,
          currentOutputText: record.leafId
            ? this.#currentOutputText(record.leafId)
            : null,
        }));
      return Response.json({
        principal,
        attestationMode: this.#attestationMode(),
        identity: {
          kid: bytesToHex(keys.kid()),
          publicKeyXY: bytesToHex(await keys.publicKeyXY()),
        },
        forestrie: {
          agentLogId: (await this.ctx.storage.get<string>(AGENT_LOG_ID_KEY)) ?? null,
          userLogId: (await this.ctx.storage.get<string>(USER_LOG_ID_KEY)) ?? null,
          userSealingDelegated:
            (await this.ctx.storage.get<number>(USER_SEALING_DELEGATED_KEY)) !== undefined,
          // Polled every refresh (identity is pinned at first fetch): the
          // browser picks up the parked x402 challenge here and pays it (W4b).
          userGrantChallenge:
            (await this.ctx.storage.get<string>(USER_GRANT_CHALLENGE_KEY)) ?? null,
          // Polled too (W4c): the turns-remaining card tracks the balance live.
          prepaidTurns:
            (await this.ctx.storage.get<number>(PREPAID_TURNS_KEY)) ?? null,
        },
        works: exported,
      });
    }

    // Manual collection kick (harness/demo): book an immediate poll.
    if (request.method === "POST" && url.pathname.endsWith("/collect-receipts")) {
      await this.#ensureReceiptCollection(1);
      return Response.json({ principal, scheduled: true });
    }

    // The client confirms the wallet signed a sealing delegation for the
    // user's log (delegateSealingKs256 ran browser-side — the DO cannot
    // observe it, the coordinator has no read API). Held user leaves are
    // released by the drain this schedules. Worst case for a false claim
    // is the pre-hold behavior: leaves sequence and wait on the sealer.
    if (
      request.method === "POST" &&
      url.pathname.endsWith("/user-sealing-delegated")
    ) {
      await this.ctx.storage.put(USER_SEALING_DELEGATED_KEY, Date.now());
      await this.schedule(1, "drainCommitments", {});
      return Response.json({ principal, delegated: true });
    }

    // Complete the x402 user-grant purchase (plan-2608-09 W4b): the browser
    // wallet signed the parked `X-PAYMENT-REQUIRED` challenge; forward the
    // resulting `X-PAYMENT` to the authority, which resubmits register-grant
    // → 303 and hands back the issued grant. The DO relays; it never holds the
    // wallet key (the browser is the payer, the authority the registrar — H1).
    if (request.method === "POST" && url.pathname.endsWith("/pay-user-grant")) {
      if (this.#attestationMode() !== "separate")
        return new Response("not in separate attestation mode", { status: 409 });
      const authority = this.#authority();
      if (!authority)
        return new Response("no grant authority configured", { status: 503 });
      try {
        const body = (await request.json()) as { xPayment?: string };
        if (!body.xPayment)
          return new Response("xPayment required", { status: 400 });
        // A top-up purchase (W4c) must bypass the authority's per-address
        // idempotence cache, or it would hand back the spent batch's grant.
        const renew =
          (await this.ctx.storage.get<boolean>(USER_GRANT_RENEWAL_KEY)) === true;
        const grant = await authority.payUserGrant(principal, body.xPayment, { renew });
        const { logId } = await this.#storeUserGrant(grant);
        // Kick the drain so held/queued user leaves register now that we have
        // a grant, and grant-at-bind's follow-on work (public-root upload,
        // sealing) proceeds.
        await this.schedule(1, "drainCommitments", {});
        return Response.json({ principal, paid: true, userLogId: logId });
      } catch (err) {
        return forestrieProblem(err);
      }
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

/** The purchased turn batch is spent (W4c) — the caller should offer a top-up. */
class TurnsExhausted extends Error {
  constructor() {
    super("prepaid turns exhausted — top up to continue");
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
