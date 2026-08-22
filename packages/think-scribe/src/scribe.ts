import { shouldRetryUserGrant } from './user-grant-retry.ts';
import { createAnthropic } from '@ai-sdk/anthropic';
import { Think, type ThinkModel, type TurnConfig, type TurnContext } from '@cloudflare/think';
import { getAgentByName, type Agent, type Connection, type ConnectionContext } from 'agents';
import {
	applyDailyCaps,
	parseCap,
	readDailyCaps,
	type AdmitResult,
	type CapConfig,
	type CapStatus,
	type CounterStore,
	type DailyCapCounters
} from './demo-cap.ts';

/**
 * The RPC surface the global spend-bound DO exposes to the per-user DO. Kept as
 * a narrow interface so this file never depends on the full DemoBudget/Agent
 * type — resolving that generic through a Durable Object stub blows the
 * TypeScript instantiation depth.
 */
interface DemoBudgetRpc {
	/**
	 * Atomic check-and-increment of today's global counter. `sub` registers the
	 * principal for the retention sweep (D3) — the budget DO is the only place
	 * that knows which per-user instances exist.
	 */
	admit(cap: number, sub?: string): Promise<AdmitResult>;
	/** Today's global counter, read-only. */
	counters(cap: number): Promise<CapStatus & { date: string }>;
}
import { DoResidentKeyProvider } from './keys/do-resident.ts';
import { KmsSeedKeyProvider, localSeedCustodianMac } from './keys/kms-seed.ts';
import { bytesToHex, type KeyProvider } from './keys/provider.ts';
import { buildSignedStatement } from './forestrie/cose.ts';
import {
	ConfiguredGrantProvider,
	GrantAuthorityClient,
	type GrantProvider,
	type IssuedGrant
} from './forestrie/grant.ts';
import {
	fetchReceipt,
	queryRegistration,
	registerStatement,
	ScrapiError
} from './forestrie/register.ts';
import { DelegateError, delegateSealing } from './forestrie/delegate.ts';
import { EnvelopeError, verifyAttestedInput } from './forestrie/envelope.ts';
import {
	buildWorkStatementPayload,
	newSaltHex,
	outputCommitment,
	sha256Hex,
	type CommittedStep
} from './attestation.ts';
import {
	WORK_INDEX_PREFIX,
	parseWorkIndexKey,
	planRetentionSweep,
	workIndexKey
} from './retention.ts';
import { isPermittedClientFrame } from './ws-frames.ts';

/**
 * Bindings the Scribe needs from its hosting Worker. The app's generated
 * `Env` (wrangler types) must be assignable to this.
 */
export interface ScribeEnv extends Cloudflare.Env {
	/** Anthropic API key (secret: .dev.vars locally, `wrangler secret put` in prod). */
	ANTHROPIC_API_KEY: string;
	/** Model override; defaults to {@link DEFAULT_MODEL_ID} (claude-haiku-4-5). */
	MODEL_ID?: string;
	/**
	 * The global daily spend bound. One named instance (`idFromName('global')`)
	 * holds the global daily turn counter; the Scribe DO reaches it over this
	 * binding to hard-cap total Anthropic spend across all users. Optional so a
	 * bare dev shell (no binding) still chats — then only the per-user cap
	 * applies.
	 */
	DEMO_BUDGET?: DurableObjectNamespace;
	/** Global daily turn cap. Default {@link DEFAULT_DEMO_DAILY_TURN_CAP}. */
	DEMO_DAILY_TURN_CAP?: string;
	/** Per-user daily turn cap. Default {@link DEFAULT_DEMO_USER_DAILY_TURN_CAP}. */
	DEMO_USER_DAILY_TURN_CAP?: string;
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
	KEY_PROVIDER?: 'do-resident' | 'kms-seed';
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
	ATTESTATION_MODE?: 'embed' | 'separate';
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

/**
 * Local dev default. Matched to what ships (deployed environments set
 * `MODEL_ID=claude-haiku-4-5`) so local behavior and cost track production
 * rather than a pricier default masking cost regressions. 200K context is ample
 * for this demo.
 */
export const DEFAULT_MODEL_ID = 'claude-haiku-4-5';

/**
 * Global daily turn cap default. At roughly $0.004/turn with prompt caching,
 * ~500 turns is a low-single-digit-dollar/day ceiling. Overridable via
 * `DEMO_DAILY_TURN_CAP`.
 */
export const DEFAULT_DEMO_DAILY_TURN_CAP = 500;

/**
 * Per-user daily turn cap default. Identities are free, so this is fairness
 * only, not a spend control — the global cap is the real bound. Overridable via
 * `DEMO_USER_DAILY_TURN_CAP`.
 */
export const DEFAULT_DEMO_USER_DAILY_TURN_CAP = 50;

/**
 * Header carrying the wcc-1-verified principal `sub` from the Worker edge
 * into the DO. Set ONLY by the edge gate after session verification (which
 * also strips any client-supplied value); the DO trusts it and binds to it
 * on first touch.
 */
export const PRINCIPAL_HEADER = 'x-scribe-principal';

const PRINCIPAL_STORAGE_KEY = 'scribe:principal';
const workKey = (workId: string) => `work:${workId}`;
const STEP_BUFFER_KEY = 'turn:steps';
const AGENT_LOG_ID_KEY = 'forestrie:agentLogId';
const GRANT_B64_KEY = 'forestrie:grantB64';
/** The kid (hex) the stored agent grant endorses — re-request on mismatch. */
const GRANT_KID_KEY = 'forestrie:grantKid';
const USER_GRANT_B64_KEY = 'forestrie:userGrantB64';
const USER_LOG_ID_KEY = 'forestrie:userLogId';
/**
 * A pending x402 `X-PAYMENT-REQUIRED` challenge (base64) for the user grant
 * (plan-2608-09 W4b): stored when the authority proxies canopy's 402, exposed
 * on `/identity` for the browser wallet to sign, and cleared once
 * `/pay-user-grant` completes. Only set on a payment-gated lane.
 */
const USER_GRANT_CHALLENGE_KEY = 'forestrie:userGrantChallenge';
/** The purchased grant's batch ceiling (maxHeight) — seeds prepaidTurns (W4c). */
const USER_GRANT_MAXHEIGHT_KEY = 'forestrie:userGrantMaxHeight';
/**
 * When user-grant acquisition was last attempted (epoch ms), and why it last
 * failed (plan-2608-11). The stamp rate-limits the request-path retry — every
 * route passes the principal check and the UI polls /receipts every ~7s — and
 * the error is surfaced on /identity so the browser can say what is wrong
 * instead of claiming a log is being created.
 */
const USER_GRANT_ATTEMPT_AT_KEY = 'forestrie:userGrantAttemptAt';
const USER_GRANT_ERROR_KEY = 'forestrie:userGrantError';
/**
 * Turns remaining in the purchased batch (W4c): seeded from the grant's
 * maxHeight when it is stored, decremented per admitted turn, refused at
 * zero. Absent = unmetered (embed mode, or no batch ceiling recorded).
 */
const PREPAID_TURNS_KEY = 'forestrie:prepaidTurns';
/**
 * Set while a top-up purchase is in flight (W4c): the spent grant has been
 * dropped and the next user-grant request must tell the authority to bypass
 * its per-address idempotence cache (a NEW grant and log per batch, O3).
 * Cleared when the fresh grant is stored.
 */
const USER_GRANT_RENEWAL_KEY = 'forestrie:userGrantRenewal';
/**
 * Set (epoch ms) when the CLIENT confirms the wallet signed a sealing
 * delegation for the user's log. User leaves are HELD until then — the
 * provision.sh ordering (prepare → delegate → create) applied to the user
 * flow: never register a leaf into a log nothing is authorized to seal.
 */
const USER_SEALING_DELEGATED_KEY = 'forestrie:userSealingDelegatedAt';
const DELEGATION_EXPIRES_KEY = 'forestrie:delegationExpiresAt';
/** Renew the sealing lease when it has less runway than this (seconds). */
const DELEGATION_RENEW_MARGIN_S = 600;
/** Receipt collection cadence (T7→T8). Sequencing is seconds; sealing is
 * minutes-latent (T9) — poll gently from a scheduled task, never inline. */
const RECEIPT_POLL_S = 10;
/** Give up on a work unit's receipt after this many polls (~20 min). */
const MAX_RECEIPT_POLLS = 120;
const COLLECT_CALLBACK = 'collectReceipts';

/**
 * A work unit's lifecycle record (plan §7): admitted → turn completed and
 * commitment queued → statement registered → sequenced → receipt collected
 * (M4, T7→T8).
 */
interface WorkRecord {
	workId: string;
	envelopeB64: string;
	state: 'submitted' | 'queued' | 'registered' | 'sequenced' | 'receipted' | 'error';
	submittedAt: number;
	/** Present from "queued": the assembled per-turn commitment. */
	steps?: CommittedStep[];
	/**
	 * The statement's salt (D2), minted when the turn is queued because the
	 * committed `outputHash` is taken over it. Carried in the payload, so an
	 * auditor holding the statement can re-derive the hash from the text.
	 */
	salt?: string;
	/** {@link outputCommitment}(salt, outputText) — never a bare hash (D2). */
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
		state: 'held' | 'registered' | 'sequenced' | 'receipted' | 'error';
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
	 * Close the raw-WebSocket turn path.
	 *
	 * Think accepts `cf_agent_use_chat_request` frames over the socket and feeds
	 * the client's `messages` array straight to the model
	 * (`_handleChatRequest`). That bypasses EVERYTHING this agent exists to do:
	 * no signed envelope, no `workId`, no prepaid-turn decrement, no daily cap,
	 * no attestation — a turn from a browser console, unmetered and unattested.
	 * `cf_agent_chat_clear` is nearly as bad: it wipes the transcript that
	 * `GET /receipts` compares the committed `outputHash` against, which is the
	 * exact check the tamper beat demonstrates.
	 *
	 * ‼️ This MUST be a constructor re-wrap, not a method override. Think wraps
	 * `this.onMessage` in its own constructor and dispatches protocol events
	 * from the wrapper — so a `onMessage` method on this class would be
	 * captured as the wrapper's INNER callback and never see a `chat-request`
	 * at all. Wrapping after `super()` puts this filter outermost, where it can
	 * actually see the raw frame first.
	 *
	 * Allowlist rather than denylist, because the legitimate surface is tiny and
	 * known: the browser client sends exactly two frames — a resume probe on
	 * connect and its ACK (`apps/scribe-ui/src/lib/chat.svelte.ts:168,228`).
	 * Everything the user can legitimately do flows through `POST /turn`.
	 */
	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
		const inner = this.onMessage.bind(this);
		this.onMessage = async (connection: Connection, message: string | ArrayBuffer) => {
			if (typeof message === 'string' && !isPermittedClientFrame(message)) {
				console.warn('scribe: dropped a non-permitted client frame');
				return;
			}
			return inner(connection, message);
		};
	}

	/**
	 * Anthropic via the AI-SDK provider (plan §11 O2). Swappable by design:
	 * subclasses or later milestones may return any AI-SDK `LanguageModel`
	 * or a Workers-AI / AI-Gateway model id string.
	 *
	 * Prompt caching (the bigger cost lever) is applied in {@link beforeTurn},
	 * not here — `cache_control` rides on message parts, not the model handle.
	 */
	getModel(): ThinkModel {
		const anthropic = createAnthropic({ apiKey: this.env.ANTHROPIC_API_KEY });
		return anthropic(this.env.MODEL_ID ?? DEFAULT_MODEL_ID);
	}

	/**
	 * Prompt caching. Think re-sends the whole transcript every turn; with no
	 * cache breakpoint the entire prefix bills as fresh input.
	 * Marking the last assembled message tells the Anthropic provider to cache
	 * everything BEFORE it — tools, the system prompt, and the transcript prefix
	 * — so the next turn reads that prefix instead of re-billing it. It pays
	 * twice: cache reads bill at ~0.1×, AND `cache_read_input_tokens` do not
	 * count toward the ITPM rate limit. (Verify live: `usage.cache_read_input_tokens`
	 * non-zero from the second turn on.)
	 *
	 * The breakpoint rides on message-level `providerOptions` — the AI-SDK
	 * Anthropic provider applies a message's `cacheControl` to its last content
	 * part — so it works whether the content is a string or a parts array, and
	 * without reaching into part internals.
	 */
	beforeTurn(ctx: TurnContext): TurnConfig | void {
		const messages = ctx.messages;
		if (messages.length === 0) return;
		const last = messages[messages.length - 1]!;
		const priorAnthropic = (last.providerOptions?.anthropic ?? {}) as Record<string, unknown>;
		const withCache = {
			...last,
			providerOptions: {
				...last.providerOptions,
				anthropic: { ...priorAnthropic, cacheControl: { type: 'ephemeral' } }
			}
		};
		return { messages: [...messages.slice(0, -1), withCache] };
	}

	/**
	 * D5: this told users something false. It claimed "only hashes are logged"
	 * while the plaintext prompt reached the lane twice over — inside the signed
	 * envelope and again embedded in the work statement. After D1/D2 the claim
	 * is true, and the wording now says what is actually committed rather than
	 * gesturing at it.
	 */
	getSystemPrompt(): string {
		return [
			'You are the Scribe, a careful assistant whose conversation is made',
			'tamper-evident on a public transparency log. What is published is',
			'commitments, not words: the user signs H(nonce ‖ their message), you',
			'sign a salted hash of your reply plus a record of your own choices.',
			'The message text itself never leaves this instance — the user keeps',
			'the opening to their commitment and can prove what they said to',
			'anyone, later, without us. Message text here is not retained long',
			'term (about a week), so tell users to keep their own copy and to',
			'avoid posting personal information. Answer plainly, and explain any',
			'of this accurately when asked.'
		].join(' ');
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
		if ((this.env.KEY_PROVIDER ?? 'do-resident') === 'kms-seed') {
			if (!this.env.KMS_SEED_SECRET)
				throw new ForestrieUnconfigured('KEY_PROVIDER=kms-seed needs KMS_SEED_SECRET');
			const sub = await this.ctx.storage.get<string>(PRINCIPAL_STORAGE_KEY);
			if (!sub)
				throw new ForestrieUnconfigured(
					'kms-seed derivation needs the bound principal — no principal bound yet'
				);
			return KmsSeedKeyProvider.load(
				localSeedCustodianMac(decodeBase64(this.env.KMS_SEED_SECRET)),
				sub,
				Number(this.env.AGENT_KEY_EPOCH ?? '1')
			);
		}
		return DoResidentKeyProvider.load(this.ctx.storage, decodeBase64(this.env.SCRIBE_KEK));
	}

	/**
	 * The grant authority client.
	 *
	 * Deployed, the authority is a sibling Worker with `workers_dev: false`,
	 * reached over the AUTHORITY service binding — it has no public URL to
	 * address, which is the point: an authority that can mint writer credentials
	 * against a live lane should not be on the internet. `GRANT_AUTHORITY_URL`
	 * then names only the base path the binding is called with.
	 *
	 * Locally, `scripts/authority.sh` runs the same Worker on :8799 and there is
	 * no binding, so the URL is a real origin and global fetch is used. Both
	 * paths run identical authority code.
	 */
	#authority(): GrantAuthorityClient | null {
		const binding = (this.env as { AUTHORITY?: Fetcher }).AUTHORITY;
		if (binding)
			return new GrantAuthorityClient(
				this.env.GRANT_AUTHORITY_URL || 'https://authority.internal',
				this.env.GRANT_AUTHORITY_TOKEN,
				undefined,
				binding.fetch.bind(binding)
			);
		if (!this.env.GRANT_AUTHORITY_URL) return null;
		return new GrantAuthorityClient(this.env.GRANT_AUTHORITY_URL, this.env.GRANT_AUTHORITY_TOKEN);
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
			'no agent grant: configure one, set GRANT_AUTHORITY_URL, or set GRANT_AGENT'
		);
	}

	#attestationMode(): 'embed' | 'separate' {
		return this.env.ATTESTATION_MODE === 'separate' ? 'separate' : 'embed';
	}

	/**
	 * The user's writer credential (O4 separate leaf): `grant_user` endorsing
	 * the bound principal's wallet address, requested from the authority on
	 * first need and stored. Returns null when not in separate mode or no
	 * authority is configured — callers fall back to embed-only.
	 */
	async #userGrant(): Promise<{ grantB64: string; logId: string } | null> {
		if (this.#attestationMode() !== 'separate') return null;
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
		const renew = (await this.ctx.storage.get<boolean>(USER_GRANT_RENEWAL_KEY)) === true;
		const result = await authority.requestUserGrant(principal, { renew });
		if (result.kind === 'payment_required') {
			// Park the challenge for the browser; stay embed-only until it's paid.
			await this.ctx.storage.put(USER_GRANT_CHALLENGE_KEY, result.challengeB64);
			await this.ctx.storage.put(USER_GRANT_MAXHEIGHT_KEY, result.maxHeight);
			// Reaching a priced 402 is the gate working, not a failure — clear any
			// error from an earlier attempt so the UI stops reporting it.
			await this.ctx.storage.delete(USER_GRANT_ERROR_KEY);
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
		if (typeof grant.maxHeight === 'number') {
			await this.ctx.storage.put(USER_GRANT_MAXHEIGHT_KEY, grant.maxHeight);
			// The purchased batch IS the turn budget (W4c).
			await this.ctx.storage.put(PREPAID_TURNS_KEY, grant.maxHeight);
		}
		await this.ctx.storage.delete(USER_GRANT_CHALLENGE_KEY);
		await this.ctx.storage.delete(USER_GRANT_RENEWAL_KEY);
		await this.ctx.storage.delete(USER_GRANT_ERROR_KEY);
		return { grantB64: grant.grantB64, logId: grant.logId };
	}

	/**
	 * Prepaid-turn balance (W4c). `null` = unmetered: embed mode, or no batch
	 * ceiling on record (no user grant yet — nothing was purchased). Grants
	 * stored before this key existed seed lazily from the recorded ceiling.
	 */
	async #prepaidTurns(): Promise<number | null> {
		if (this.#attestationMode() !== 'separate') return null;
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
		await this.schedule(0, 'acquireUserGrant', {});
	}

	/**
	 * Is `candidate` a URL on the configured lane?
	 *
	 * Compared by parsed ORIGIN, never by string prefix: `startsWith(baseUrl)`
	 * is defeated by `https://api-a.forest-2.forestrie.dev.evil.test/…`, and by
	 * userinfo tricks like `https://api-a.forest-2.forestrie.dev@evil.test/`.
	 * Parsing both sides and comparing `.origin` collapses port, case and
	 * userinfo, so only a genuine same-origin URL passes.
	 */
	#isLaneUrl(candidate: string): boolean {
		let laneOrigin: string;
		try {
			laneOrigin = new URL(this.#forestrieTarget().baseUrl).origin;
		} catch {
			return false;
		}
		try {
			return new URL(candidate).origin === laneOrigin;
		} catch {
			return false;
		}
	}

	#forestrieTarget(): { baseUrl: string; rootLogId: string } {
		const baseUrl = this.env.FORESTRIE_BASE_URL;
		const rootLogId = this.env.FORESTRIE_ROOT_LOG_ID;
		if (!baseUrl || !rootLogId)
			throw new ForestrieUnconfigured('FORESTRIE_BASE_URL / FORESTRIE_ROOT_LOG_ID not set');
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
		sub: string
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
			sub
		});
		const accepted = await registerStatement(
			baseUrl,
			rootLogId,
			statement,
			await (await this.grants()).grantB64()
		);
		return { kid: bytesToHex(keys.kid()), statement, ...accepted };
	}

	/** The configured daily caps (env overrides, else the defaults above). */
	#capConfig(): CapConfig {
		return {
			userCap: parseCap(this.env.DEMO_USER_DAILY_TURN_CAP, DEFAULT_DEMO_USER_DAILY_TURN_CAP),
			globalCap: parseCap(this.env.DEMO_DAILY_TURN_CAP, DEFAULT_DEMO_DAILY_TURN_CAP)
		};
	}

	/** This DO's storage as the per-user daily counter store (Scribe-local). */
	#userCounterStore(): CounterStore {
		return {
			get: (key) => this.ctx.storage.get<number>(key),
			put: (key, value) => this.ctx.storage.put(key, value)
		};
	}

	/** Cached budget stub, resolved once per wake by {@link #demoBudget}. */
	#budget?: Promise<DemoBudgetRpc | null>;

	/**
	 * The global spend-bound DO, reached over the DEMO_BUDGET binding at the
	 * single `global` name — NOT through the agent lobby, which only routes
	 * `user-<sub>` names. Null when unbound (a bare dev shell): then only the
	 * per-user cap applies.
	 *
	 * ‼️ Addressed with `getAgentByName`, not a raw `ns.get(idFromName(…))`.
	 * A user-defined RPC method does not pass through `Server.fetch`, which is
	 * where the SDK would otherwise initialize the instance — so a raw stub
	 * gives a DO whose `onStart` never runs and whose name is never persisted.
	 * That was invisible while this only incremented a counter, and silently
	 * fatal the moment `onStart` became where the retention sweep is scheduled
	 * (D3): counters kept working, and nothing was ever swept.
	 *
	 * Resolved once per wake and cached — stubs are location-independent
	 * handles, safe to reuse — so the extra init RPC is paid once, not per turn.
	 */
	#demoBudget(): Promise<DemoBudgetRpc | null> {
		this.#budget ??= (async () => {
			const ns = this.env.DEMO_BUDGET;
			if (!ns) return null;
			return (await getAgentByName(
				ns as unknown as DurableObjectNamespace<Agent<ScribeEnv>>,
				'global'
			)) as unknown as DemoBudgetRpc;
		})();
		return this.#budget;
	}

	/**
	 * Per-user + global daily counters for /identity and /receipts (no mutation).
	 *
	 * Best-effort: these counters are cosmetic, but /identity is session
	 * bootstrap and /receipts is the live proof poll, so a failing global-cap RPC
	 * must NOT take either down. On any failure it returns null and the caller
	 * omits the counters (the wire field is optional; the UI hides the line)
	 * rather than surfacing a 5xx.
	 */
	async #demoTurnCounters(): Promise<DailyCapCounters | null> {
		try {
			const budget = await this.#demoBudget();
			return await readDailyCaps(
				Date.now(),
				this.#userCounterStore(),
				this.#capConfig(),
				budget ? (cap) => budget.counters(cap) : null
			);
		} catch (err) {
			console.warn('demo-turn counters unavailable — omitting from response', err);
			return null;
		}
	}

	/**
	 * Turn admission with user attestation (M3, plan §7; redacted in D1):
	 * verify the signed input envelope, check that the submitted plaintext
	 * OPENS the envelope's `H(nonce ‖ input)` commitment, bind it to the wcc-1
	 * principal, and durably submit the turn under `workId = H(envelope)` —
	 * submissionId AND idempotencyKey — so the agent cannot run work under a
	 * different id than it commits to.
	 *
	 * `input` is the plaintext, which reaches this worker and no further: the
	 * envelope registered on the lane carries only the commitment.
	 */
	async admitAttestedTurn(
		envelopeB64: string,
		input: string,
		principal: string
	): Promise<{ workId: string; accepted: boolean; status: string }> {
		const envelope = decodeBase64(envelopeB64);
		// ‼️ verifyAttestedInput, never verifyUserEnvelope: this is where the
		// signature is bound to the text the model is about to be fed. It throws
		// before anything is spent or stored.
		const verified = await verifyAttestedInput(envelope, input);
		if (verified.address.toLowerCase() !== principal.toLowerCase())
			throw new EnvelopeError('envelope signer does not match the session principal');

		// Resolved BEFORE the gate closes: addressing the budget DO costs an init
		// RPC on the first call of each wake, and the input gate should be held
		// for the metering, not for connection setup.
		const budget = await this.#demoBudget();

		// Admission (new-turn detection → cap/prepaid metering → record write)
		// runs under the input gate held closed, so two concurrent submits of the
		// SAME envelope cannot both pass the "new turn?" test: the first persists
		// the record before the second reads it. Without this, the gate reopens on
		// the cross-DO global-cap RPC await, and the race would double-count the
		// caps and double-decrement the prepaid batch. The callback RETURNS the
		// reject reason instead of throwing — a throw inside blockConcurrencyWhile
		// resets the whole DO — so refusals are raised afterwards.
		const outcome = await this.ctx.blockConcurrencyWhile(
			async (): Promise<
				| { reject: null }
				| { reject: 'cap'; scope: 'user' | 'global'; used: number; cap: number }
				| { reject: 'exhausted' }
			> => {
				// The record's presence IS the "is this a new turn?" test: a
				// re-submitted envelope (same workId) already has one, so the caps
				// and the prepaid batch are never charged twice on the idempotent
				// path.
				const isNewTurn =
					(await this.ctx.storage.get<WorkRecord>(workKey(verified.workId))) === undefined;
				if (isNewTurn) {
					// Daily caps — the demo's real spend bound. Checked and rejected
					// BEFORE the prepaid decrement, so a capped turn never burns a
					// prepaid turn. A cap refusal becomes HTTP 429 (not 402): a daily
					// cap is not a top-up the wallet can resolve.
					if (!budget)
						// The global cap is the only real spend bound (identities are
						// free). Absent binding = per-user cap only; log it so the guard
						// can never silently disappear from a deployed environment.
						console.warn('DEMO_BUDGET unbound — global daily spend cap NOT enforced');
					const decision = await applyDailyCaps({
						isNewTurn: true,
						now: Date.now(),
						userStore: this.#userCounterStore(),
						// The principal rides along so the budget DO can register this
						// instance for the retention sweep (D3) — it is the only place
						// that knows which per-user DOs exist.
						admitGlobal: budget ? (cap) => budget.admit(cap, principal) : null,
						config: this.#capConfig()
					});
					if (!decision.ok)
						return { reject: 'cap', scope: decision.scope, used: decision.used, cap: decision.cap };

					// Prepaid-turn metering (W4c): each NEW admitted turn spends one
					// turn of the purchased batch, before any work runs. Refuse at zero
					// and start the top-up purchase so the browser finds a fresh
					// challenge.
					const balance = await this.#prepaidTurns();
					if (balance !== null) {
						if (balance <= 0) {
							await this.#beginTopUp();
							return { reject: 'exhausted' };
						}
						await this.ctx.storage.put(PREPAID_TURNS_KEY, balance - 1);
					}
				}
				// Reserve the record inside the gate so a concurrent same-workId
				// submit sees it. Overwrites unconditionally, matching the prior
				// resubmit-resets-to-submitted behavior.
				const record: WorkRecord = {
					workId: verified.workId,
					envelopeB64,
					state: 'submitted',
					submittedAt: Date.now()
				};
				await this.ctx.storage.put(workKey(verified.workId), record);
				// Time-ordered index for the retention sweep (D3): `work:` keys sort
				// by hash. A resubmit writes a second index row for the same workId —
				// harmless, the sweep deletes by workId and drops stale rows it finds.
				await this.ctx.storage.put(workIndexKey(record.submittedAt, record.workId), 1);
				return { reject: null };
			}
		);
		if (outcome.reject === 'cap') throw new CapExceeded(outcome.scope, outcome.used, outcome.cap);
		if (outcome.reject === 'exhausted') throw new TurnsExhausted();

		const submission = await this.submitMessages(
			[
				{
					id: crypto.randomUUID(),
					role: 'user' as const,
					// The verified plaintext: `verifyAttestedInput` returned it only
					// after proving it opens the signed commitment.
					parts: [{ type: 'text' as const, text: verified.input }]
				}
			],
			{
				submissionId: verified.workId,
				idempotencyKey: verified.workId,
				metadata: { workId: verified.workId }
			}
		);
		return {
			workId: verified.workId,
			accepted: submission.accepted,
			status: submission.status
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
		const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value ?? null));
		const step: CommittedStep = {
			stepNumber: ctx.stepNumber ?? 0,
			finishReason: ctx.finishReason ?? 'unknown',
			toolCalls: await Promise.all(
				(ctx.toolCalls ?? []).map(async (c) => ({
					toolName: c.toolName ?? 'unknown',
					argsHash: await sha256Hex(encode(c.input))
				}))
			),
			toolResults: await Promise.all(
				(ctx.toolResults ?? []).map(async (r) => ({
					toolName: r.toolName ?? 'unknown',
					resultHash: await sha256Hex(encode(r.output))
				}))
			)
		};
		const buffer = (await this.ctx.storage.get<CommittedStep[]>(STEP_BUFFER_KEY)) ?? [];
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
		status: 'completed' | 'error' | 'aborted';
		continuation: boolean;
	}): Promise<void> {
		const steps = (await this.ctx.storage.get<CommittedStep[]>(STEP_BUFFER_KEY)) ?? [];
		await this.ctx.storage.delete(STEP_BUFFER_KEY);
		if (result.status !== 'completed') return;

		// Which admitted work unit ran? submissionId = workId, and the
		// submission inspection carries the turn's requestId.
		const works = await this.ctx.storage.list<WorkRecord>({ prefix: 'work:' });
		let matched: WorkRecord | undefined;
		for (const record of works.values()) {
			if (record.state !== 'submitted') continue;
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
			.filter((p) => p.type === 'text' && typeof p.text === 'string')
			.map((p) => p.text)
			.join('');
		matched.steps = steps;
		// Salt the output commitment (D2). The salt is minted here rather than
		// inside the payload builder because the hash is taken OVER it: a bare
		// sha256(outputText) is brute-forceable for short replies, the same
		// weakness D1 fixes on the input side.
		matched.salt = newSaltHex();
		matched.outputHash = outputCommitment(matched.salt, outputText);
		matched.leafId = result.message.id;
		matched.requestId = result.requestId;
		matched.state = 'queued';
		await this.ctx.storage.put(workKey(matched.workId), matched);
		await this.schedule(1, 'drainCommitments', {});
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
			console.warn('user grant acquisition failed — embed-only this drain', err);
		}
		const works = await this.ctx.storage.list<WorkRecord>({ prefix: 'work:' });
		const sealingDelegated =
			(await this.ctx.storage.get<number>(USER_SEALING_DELEGATED_KEY)) !== undefined;
		let registered = false;
		for (const record of works.values()) {
			// Release pass: leaves held while the user hadn't authorized sealing
			// register now, regardless of how far the agent side has advanced.
			if (userGrant && sealingDelegated && record.userLeaf?.state === 'held') {
				record.userLeaf = await this.#registerUserLeaf(record, userGrant.grantB64);
				if (record.userLeaf.state === 'registered') registered = true;
				await this.ctx.storage.put(workKey(record.workId), record);
			}
			if (record.state !== 'queued') continue;
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
					record.userLeaf = { state: 'held' };
				} else {
					record.userLeaf = await this.#registerUserLeaf(record, userGrant.grantB64);
					if (record.userLeaf.state === 'registered') registered = true;
				}
			}
			try {
				const payload = buildWorkStatementPayload({
					workId: record.workId,
					steps: record.steps ?? [],
					salt: record.salt ?? '',
					outputHash: record.outputHash ?? '',
					leafId: record.leafId ?? '',
					requestId: record.requestId ?? ''
				});
				const { statement, ...accepted } = await this.signAndRegister(
					payload,
					'application/json',
					`urn:thinker:work:${record.workId}`
				);
				record.contentHash = accepted.contentHash;
				record.statusUrl = accepted.statusUrl;
				let b64 = '';
				for (const b of statement) b64 += String.fromCharCode(b);
				record.statementB64 = btoa(b64);
				record.state = 'registered';
				registered = true;
			} catch (err) {
				record.error = String(err);
				record.state = 'error';
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
		grantB64: string
	): Promise<NonNullable<WorkRecord['userLeaf']>> {
		try {
			const { baseUrl, rootLogId } = this.#forestrieTarget();
			const accepted = await registerStatement(
				baseUrl,
				rootLogId,
				decodeBase64(record.envelopeB64),
				grantB64
			);
			return {
				state: 'registered',
				contentHash: accepted.contentHash,
				statusUrl: accepted.statusUrl
			};
		} catch (err) {
			return { state: 'error', error: String(err) };
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
		await this.ctx.storage.put(USER_GRANT_ATTEMPT_AT_KEY, Date.now());
		try {
			await this.#userGrant();
		} catch (err) {
			// Recorded as well as logged: a console.warn inside the DO is invisible
			// to the person staring at a disabled button (plan-2608-11 W3). The
			// request path retries on a cooldown, so this is a status, not a
			// terminal state.
			await this.ctx.storage.put(USER_GRANT_ERROR_KEY, String(err));
			console.warn('user grant acquisition failed — will retry', err);
		}
	}

	/**
	 * Scheduled receipt collection (M4, T7→T8): advance every in-flight work
	 * unit one step — status poll until sequenced, then receipt fetch until
	 * the covering checkpoint seals — and reschedule while any remain. Runs
	 * only from the schedule alarm; the chat path never waits on the lane.
	 */
	async collectReceipts(): Promise<void> {
		const works = await this.ctx.storage.list<WorkRecord>({ prefix: 'work:' });
		let pending = false;
		const inFlight = (s: string) => s === 'registered' || s === 'sequenced';
		for (const record of works.values()) {
			const agentInFlight = inFlight(record.state);
			const userInFlight = record.userLeaf ? inFlight(record.userLeaf.state) : false;
			if (!agentInFlight && !userInFlight) continue;

			if (agentInFlight) {
				record.pollAttempts = (record.pollAttempts ?? 0) + 1;
				if (record.pollAttempts > MAX_RECEIPT_POLLS) {
					record.error = `receipt collection gave up after ${MAX_RECEIPT_POLLS} polls`;
					record.state = 'error';
				} else {
					try {
						if (record.state === 'registered' && record.statusUrl) {
							const status = await queryRegistration(record.statusUrl);
							if (status.state === 'sequenced') {
								record.entryId = status.entryId;
								record.receiptUrl = status.receiptUrl;
								record.state = 'sequenced';
							}
						}
						if (record.state === 'sequenced' && record.receiptUrl) {
							const receipt = await fetchReceipt(record.receiptUrl);
							if (receipt.state === 'ready') {
								let b64 = '';
								for (const b of receipt.receipt) b64 += String.fromCharCode(b);
								record.receiptB64 = btoa(b64);
								record.receiptedAt = Date.now();
								record.state = 'receipted';
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
					leaf.state = 'error';
				} else {
					try {
						if (leaf.state === 'registered' && leaf.statusUrl) {
							const status = await queryRegistration(leaf.statusUrl);
							if (status.state === 'sequenced') {
								leaf.entryId = status.entryId;
								leaf.receiptUrl = status.receiptUrl;
								leaf.state = 'sequenced';
							}
						}
						if (leaf.state === 'sequenced' && leaf.receiptUrl) {
							const receipt = await fetchReceipt(leaf.receiptUrl);
							if (receipt.state === 'ready') {
								let b64 = '';
								for (const b of receipt.receipt) b64 += String.fromCharCode(b);
								leaf.receiptB64 = btoa(b64);
								leaf.receiptedAt = Date.now();
								leaf.state = 'receipted';
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
	 * Bounded, expiring retention (D3) — called over RPC from the `DemoBudget`
	 * DO's daily sweep, never on a schedule of this instance's own (an interval
	 * schedule on `Scribe` would wake every idle user's DO forever).
	 *
	 * Deletes, per user and nowhere central:
	 *  - work records past the 1-week window, and any beyond the 1000-record
	 *    ceiling, oldest first;
	 *  - the Think transcript rows and durable submissions older than the same
	 *    cutoff — that is where the actual words live, and until Phase D
	 *    nothing in this system ever deleted anything.
	 *
	 * Expiry destroying auditability is acceptable ONLY because the browser
	 * keeps the user's own copy and can export a proof bundle (D4): the receipt
	 * stays verifiable forever from that bundle, with this service switched off.
	 *
	 * Returns what it removed and how much remains — the caller uses `remaining`
	 * to drop a fully-swept, long-idle instance from its registry so it stops
	 * being woken.
	 */
	async sweepRetention(now = Date.now()): Promise<{
		expired: number;
		trimmed: number;
		remaining: number;
		transcriptPruned: boolean;
	}> {
		const index = await this.ctx.storage.list<number>({ prefix: WORK_INDEX_PREFIX });
		// A workId can carry more than one index row (a resubmitted envelope
		// writes a second one), so collapse to the NEWEST timestamp per workId
		// before planning — otherwise a stale row would expire a record whose
		// latest submission is still well inside the window, and take the fresh
		// index row with it.
		const newest = new Map<string, number>();
		const keysOf = new Map<string, string[]>();
		for (const key of index.keys()) {
			const parsed = parseWorkIndexKey(key);
			if (!parsed) {
				await this.ctx.storage.delete(key);
				continue;
			}
			newest.set(parsed.workId, Math.max(newest.get(parsed.workId) ?? 0, parsed.submittedAt));
			keysOf.set(parsed.workId, [...(keysOf.get(parsed.workId) ?? []), key]);
		}
		const entries = [...newest].map(([workId, submittedAt]) => ({ workId, submittedAt }));
		const plan = planRetentionSweep(entries, now);
		for (const workId of plan.workIds) {
			await this.ctx.storage.delete(workKey(workId));
			for (const key of keysOf.get(workId) ?? []) await this.ctx.storage.delete(key);
		}
		const transcriptPruned = this.#pruneTranscript(plan.cutoff);
		return {
			expired: plan.expired,
			trimmed: plan.trimmed,
			remaining: entries.length - plan.workIds.length,
			transcriptPruned
		};
	}

	/**
	 * Drop transcript state older than `cutoff` from Think's session store.
	 *
	 * Deleting the OLDEST messages is safe with this schema: history is a
	 * recursive walk from the active leaf up through `parent_id`, so a missing
	 * ancestor simply ends the walk — the recent tail stays intact and the model
	 * keeps its near context. Both the FTS mirror and the compaction summaries
	 * carry the same text and must go with it, as must Think's durable
	 * submissions, whose `messages_json` holds the raw prompt.
	 *
	 * Each statement is separately guarded: these tables belong to the agents
	 * SDK and Think, are created lazily, and a missing one must not abort the
	 * sweep for the tables that do exist.
	 */
	#pruneTranscript(cutoff: number): boolean {
		// SQLite DATETIME columns hold 'YYYY-MM-DD HH:MM:SS' in UTC.
		const stamp = new Date(cutoff).toISOString().replace('T', ' ').slice(0, 19);
		let deleted = false;
		let ok = true;
		// Retention IS the privacy guarantee: past the window the plaintext must
		// be gone. These tables belong to Think / the agents SDK, so a version
		// bump could rename one — and a swallowed error would then leave prompts
		// on disk indefinitely while the sweep reported success. So each table is
		// deleted AND re-counted below the cutoff: anything left (a wrong
		// name/column, or a delete that matched nothing) is logged LOUD and marks
		// the sweep not-ok, rather than passing silently.
		const prune = (
			label: string,
			del: () => unknown,
			remaining: () => Array<{ n: number }>
		): void => {
			try {
				del();
				const left = remaining()[0]?.n ?? 0;
				if (left > 0) {
					ok = false;
					console.error(
						`retention: ${label} still holds ${left} rows older than the cutoff after prune`
					);
				} else {
					deleted = true;
				}
			} catch (err) {
				ok = false;
				console.error(`retention: transcript prune FAILED for ${label} (schema drift?)`, err);
			}
		};
		// The FTS mirror carries the same text as the messages it indexes, so it
		// goes first (its ids come from the messages table the next step empties).
		// It has no timestamp of its own to re-count; a wrong table name here still
		// throws and is caught loud, and the assistant_messages check below is the
		// real guard that plaintext is gone.
		prune(
			'assistant_fts',
			() =>
				this.sql`DELETE FROM assistant_fts WHERE id IN (
					SELECT id FROM assistant_messages WHERE created_at < ${stamp}
				)`,
			() => [{ n: 0 }]
		);
		prune(
			'assistant_messages',
			() => this.sql`DELETE FROM assistant_messages WHERE created_at < ${stamp}`,
			() =>
				this.sql<{
					n: number;
				}>`SELECT COUNT(*) AS n FROM assistant_messages WHERE created_at < ${stamp}`
		);
		prune(
			'assistant_compactions',
			() => this.sql`DELETE FROM assistant_compactions WHERE created_at < ${stamp}`,
			() =>
				this.sql<{
					n: number;
				}>`SELECT COUNT(*) AS n FROM assistant_compactions WHERE created_at < ${stamp}`
		);
		// Think's submissions store epoch ms, not a DATETIME string.
		prune(
			'cf_think_submissions',
			() => this.sql`DELETE FROM cf_think_submissions WHERE created_at < ${cutoff}`,
			() =>
				this.sql<{
					n: number;
				}>`SELECT COUNT(*) AS n FROM cf_think_submissions WHERE created_at < ${cutoff}`
		);
		if (!ok)
			console.error(
				'retention: transcript prune did not fully complete — plaintext may persist past its retention window'
			);
		return deleted;
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
		if (schedules.some((s) => s.callback === COLLECT_CALLBACK && s.time > now)) return;
		await this.schedule(delaySeconds, COLLECT_CALLBACK, {});
	}

	/** Delegate-at-drain: re-lease sealing when under the renewal margin. */
	async #renewDelegationIfNeeded(): Promise<void> {
		const coordinatorUrl = this.env.DELEGATION_COORDINATOR_URL;
		const knownSealerKeyB64 = this.env.KNOWN_SEALER_KEY;
		const logId = await this.ctx.storage.get<string>(AGENT_LOG_ID_KEY);
		if (!coordinatorUrl || !knownSealerKeyB64 || !logId) return;
		const expiresAt = (await this.ctx.storage.get<number>(DELEGATION_EXPIRES_KEY)) ?? 0;
		if (expiresAt - Date.now() / 1000 > DELEGATION_RENEW_MARGIN_S) return;
		try {
			const result = await delegateSealing(await this.keys(), {
				coordinatorUrl,
				logId,
				knownSealerKeyB64
			});
			await this.ctx.storage.put(DELEGATION_EXPIRES_KEY, result.expiresAt);
		} catch (err) {
			// Sequencing still works without the lease; receipts just lag. The
			// next drain retries.
			console.warn('delegation renewal failed', err);
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
				.filter((p) => p.type === 'text' && typeof p.text === 'string')
				.map((p) => p.text)
				.join('');
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
		if (!sub) throw new PrincipalError(401, 'missing principal');
		const bound = await this.ctx.storage.get<string>(PRINCIPAL_STORAGE_KEY);
		if (bound === undefined) {
			await this.ctx.storage.put(PRINCIPAL_STORAGE_KEY, sub);
			// Grant-at-bind: kick user-grant acquisition off the request path —
			// issuance waits on an auth-log seal (up to ~a minute) and nothing
			// here should block on it. Fire when the authority is reachable by
			// EITHER a URL or the AUTHORITY service binding: the deployed worker
			// reaches it over the binding with no URL, so gating on the URL alone
			// skipped grant-at-bind there and the user log (and its sealing/pay
			// affordances) only appeared at the first turn's drain.
			const authorityReachable =
				!!this.env.GRANT_AUTHORITY_URL || !!(this.env as { AUTHORITY?: Fetcher }).AUTHORITY;
			if (this.#attestationMode() === 'separate' && authorityReachable)
				await this.schedule(0, 'acquireUserGrant', {});
			return sub;
		}
		if (bound !== sub)
			throw new PrincipalError(403, 'principal does not match bound instance owner');

		// Grant-at-bind fires ONCE. When that single attempt failed, the user log
		// never appeared, "Authorize sealing" stayed disabled, and the only
		// fallback was the turn drain — but the UI puts activation BEFORE
		// chatting, so a user following the intended order waited forever
		// (plan-2608-11 D1; seen on deployed dev with a fresh funded wallet).
		// Retry here, rate-limited: this runs on EVERY route and the UI polls
		// /receipts every ~7s.
		await this.#retryUserGrantIfStuck();
		return bound;
	}

	/**
	 * Re-arm user-grant acquisition for an already-bound principal that still
	 * has none. Cheap and silent when there is nothing to do — the predicate
	 * (and its tests) live in user-grant-retry.ts.
	 */
	async #retryUserGrantIfStuck(): Promise<void> {
		if (await this.ctx.storage.get<string>(USER_GRANT_B64_KEY)) return;
		const retry = shouldRetryUserGrant({
			attestationMode: this.#attestationMode(),
			authorityReachable:
				!!this.env.GRANT_AUTHORITY_URL || !!(this.env as { AUTHORITY?: Fetcher }).AUTHORITY,
			hasGrant: false,
			hasParkedChallenge:
				(await this.ctx.storage.get<string>(USER_GRANT_CHALLENGE_KEY)) !== undefined,
			lastAttemptAt: (await this.ctx.storage.get<number>(USER_GRANT_ATTEMPT_AT_KEY)) ?? null,
			now: Date.now()
		});
		if (!retry) return;
		// Stamped here as well as in acquireUserGrant: the scheduled task may not
		// run for a moment, and without the stamp every request in that window
		// would queue another one.
		await this.ctx.storage.put(USER_GRANT_ATTEMPT_AT_KEY, Date.now());
		await this.schedule(0, 'acquireUserGrant', {});
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
		if (request.method === 'GET' && url.pathname.endsWith('/identity')) {
			const keys = await this.keys();
			return Response.json({
				principal,
				alg: 'ES256',
				keyProvider: this.env.KEY_PROVIDER ?? 'do-resident',
				attestationMode: this.#attestationMode(),
				// Daily demo-turn counters. Pinned here at first fetch; the live
				// values are re-polled from /receipts.
				demoTurns: await this.#demoTurnCounters(),
				epoch: (keys as { epoch?: () => number }).epoch?.() ?? 1,
				kid: bytesToHex(keys.kid()),
				publicKeyXY: bytesToHex(await keys.publicKeyXY()),
				agentLogId: (await this.ctx.storage.get<string>(AGENT_LOG_ID_KEY)) ?? null,
				userLogId: (await this.ctx.storage.get<string>(USER_LOG_ID_KEY)) ?? null,
				userSealingDelegated:
					(await this.ctx.storage.get<number>(USER_SEALING_DELEGATED_KEY)) !== undefined,
				// A pending x402 challenge (W4b) the browser wallet must sign to buy
				// the user grant; null on dark lanes and once paid.
				userGrantChallenge: (await this.ctx.storage.get<string>(USER_GRANT_CHALLENGE_KEY)) ?? null,
				// Why the last acquisition attempt failed, if it did (plan-2608-11).
				// Non-null means the UI should say so rather than claim the log is
				// still being created; a retry is already scheduled on a cooldown.
				userGrantError: (await this.ctx.storage.get<string>(USER_GRANT_ERROR_KEY)) ?? null,
				// Turns remaining in the purchased batch (W4c); null = unmetered.
				prepaidTurns: (await this.ctx.storage.get<number>(PREPAID_TURNS_KEY)) ?? null,
				// W4d offline parent-policy proof: the completed user-authority
				// creation grant (receipt included) and the forest root's public key
				// as its trust anchor, both provisioning artifacts handed in via env.
				userAuthorityGrant: this.env.GRANT_USER_AUTHORITY ?? null,
				rootPublicKeyXY: this.env.FORESTRIE_ROOT_PUBLIC_KEY_XY ?? null
			});
		}

		// REMOVED: the M2 write-path harness `POST …/register-test`.
		//
		// It signed an arbitrary caller-supplied payload under an arbitrary
		// caller-supplied `sub` with the agent key and registered it on the live
		// lane — i.e. any principal could publish unlimited attacker-authored,
		// agent-signed leaves, including ones impersonating another user's
		// `urn:thinker:work:<workId>`. Fine as a local smoke harness, indefensible
		// on a public origin, and the real commitment path (onStepFinish → enqueue
		// → drain) never signs in a request handler anyway.
		//
		// m2-smoke.mjs drives T5–T8 through `POST /turn` instead.

		// M3 attested turn admission: the user's signed input envelope enters
		// here; the turn runs durably under workId (plan §7).
		if (request.method === 'POST' && url.pathname.endsWith('/turn')) {
			try {
				// D1: the envelope carries the COMMITMENT, the body carries the
				// plaintext. Both are required — the commitment without an opening
				// is unrunnable, the opening without a commitment is unattested.
				const body = (await request.json()) as { envelopeB64?: string; input?: string };
				if (!body.envelopeB64) return new Response('envelopeB64 required', { status: 400 });
				if (typeof body.input !== 'string')
					return new Response('input required (the plaintext the envelope commits to)', {
						status: 400
					});
				const admitted = await this.admitAttestedTurn(body.envelopeB64, body.input, principal);
				return Response.json({ principal, ...admitted });
			} catch (err) {
				if (err instanceof EnvelopeError) return new Response(err.message, { status: 400 });
				if (err instanceof CapExceeded)
					// 429, not 402: a daily cap is not a top-up the wallet can pay off
					// (chat.svelte.ts branches on 402 to offer the proof panel).
					return Response.json(
						{
							error: err.message,
							capExceeded: true,
							scope: err.scope,
							used: err.used,
							cap: err.cap
						},
						{ status: 429 }
					);
				if (err instanceof TurnsExhausted)
					// 402 with a top-up affordance (W4c): the DO has already dropped
					// the spent grant and re-requested — the client polls up the fresh
					// challenge and repeats the W4b purchase.
					return Response.json(
						{ error: err.message, topUp: true, prepaidTurns: 0 },
						{ status: 402 }
					);
				return forestrieProblem(err);
			}
		}

		// Per-instance Forestrie wiring: the grant bound to this DO's kid and
		// the agent's own data log id (provisioned out-of-band for this kid;
		// request-grant-at-init stores the same keys in M5).
		if (request.method === 'POST' && url.pathname.endsWith('/configure-forestrie')) {
			const body = (await request.json()) as {
				grantB64?: string;
				agentLogId?: string;
			};
			if (!body.grantB64 || !body.agentLogId)
				return new Response('grantB64 and agentLogId required', { status: 400 });
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
		if (request.method === 'GET' && url.pathname.endsWith('/receipts')) {
			const keys = await this.keys();
			const works = await this.ctx.storage.list<WorkRecord>({ prefix: 'work:' });
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
					currentOutputText: record.leafId ? this.#currentOutputText(record.leafId) : null
				}));
			return Response.json({
				principal,
				attestationMode: this.#attestationMode(),
				identity: {
					kid: bytesToHex(keys.kid()),
					publicKeyXY: bytesToHex(await keys.publicKeyXY())
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
					prepaidTurns: (await this.ctx.storage.get<number>(PREPAID_TURNS_KEY)) ?? null,
					// Live daily-cap counters: /identity is pinned at first fetch, so
					// the UI reads the moving values from here.
					demoTurns: await this.#demoTurnCounters()
				},
				works: exported
			});
		}

		// Manual collection kick (harness/demo): book an immediate poll.
		if (request.method === 'POST' && url.pathname.endsWith('/collect-receipts')) {
			await this.#ensureReceiptCollection(1);
			return Response.json({ principal, scheduled: true });
		}

		// The client confirms the wallet signed a sealing delegation for the
		// user's log (delegateSealingKs256 ran browser-side — the DO cannot
		// observe it, the coordinator has no read API). Held user leaves are
		// released by the drain this schedules. Worst case for a false claim
		// is the pre-hold behavior: leaves sequence and wait on the sealer.
		if (request.method === 'POST' && url.pathname.endsWith('/user-sealing-delegated')) {
			await this.ctx.storage.put(USER_SEALING_DELEGATED_KEY, Date.now());
			await this.schedule(1, 'drainCommitments', {});
			return Response.json({ principal, delegated: true });
		}

		// Complete the x402 user-grant purchase (plan-2608-09 W4b): the browser
		// wallet signed the parked `X-PAYMENT-REQUIRED` challenge; forward the
		// resulting `X-PAYMENT` to the authority, which resubmits register-grant
		// → 303 and hands back the issued grant. The DO relays; it never holds the
		// wallet key (the browser is the payer, the authority the registrar — H1).
		if (request.method === 'POST' && url.pathname.endsWith('/pay-user-grant')) {
			if (this.#attestationMode() !== 'separate')
				return new Response('not in separate attestation mode', { status: 409 });
			const authority = this.#authority();
			if (!authority) return new Response('no grant authority configured', { status: 503 });
			try {
				const body = (await request.json()) as { xPayment?: string };
				if (!body.xPayment) return new Response('xPayment required', { status: 400 });
				// A top-up purchase (W4c) must bypass the authority's per-address
				// idempotence cache, or it would hand back the spent batch's grant.
				const renew = (await this.ctx.storage.get<boolean>(USER_GRANT_RENEWAL_KEY)) === true;
				const grant = await authority.payUserGrant(principal, body.xPayment, { renew });
				const { logId } = await this.#storeUserGrant(grant);
				// Kick the drain so held/queued user leaves register now that we have
				// a grant, and grant-at-bind's follow-on work (public-root upload,
				// sealing) proceeds.
				await this.schedule(1, 'drainCommitments', {});
				return Response.json({ principal, paid: true, userLogId: logId });
			} catch (err) {
				return forestrieProblem(err);
			}
		}

		// Work-unit lifecycle inspection (harness + later the client UI).
		if (request.method === 'GET' && url.pathname.endsWith('/work')) {
			const workId = url.searchParams.get('id');
			if (!workId) return new Response('id query param required', { status: 400 });
			const record = await this.ctx.storage.get<WorkRecord>(workKey(workId));
			if (!record) return new Response('unknown workId', { status: 404 });
			return Response.json(record);
		}

		// Authorize the lane's sealer for the agent's own data log (T9). The
		// log id arrives from the provisioner for now; the request-grant-at-init
		// path (M5) will carry it with the grant.
		if (request.method === 'POST' && url.pathname.endsWith('/delegate-sealing')) {
			const coordinatorUrl = this.env.DELEGATION_COORDINATOR_URL;
			const knownSealerKeyB64 = this.env.KNOWN_SEALER_KEY;
			if (!coordinatorUrl || !knownSealerKeyB64)
				return new Response(
					'forestrie not configured: DELEGATION_COORDINATOR_URL / KNOWN_SEALER_KEY not set',
					{ status: 503 }
				);
			try {
				const body = (await request.json()) as { logId?: string };
				if (!body.logId) return new Response('logId required', { status: 400 });
				const result = await delegateSealing(await this.keys(), {
					coordinatorUrl,
					logId: body.logId,
					knownSealerKeyB64
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
		if (request.method === 'GET' && url.pathname.endsWith('/registration')) {
			const statusUrl = url.searchParams.get('status');
			const receiptUrl = url.searchParams.get('receipt');
			// Both are caller-supplied and were previously handed straight to
			// fetch(), with the upstream body returned verbatim — an
			// authenticated open GET proxy running from Cloudflare egress. Pin
			// them to the configured lane: these URLs only ever legitimately come
			// from a Location header that lane issued in the first place.
			for (const candidate of [statusUrl, receiptUrl]) {
				if (candidate !== null && !this.#isLaneUrl(candidate))
					return new Response('status/receipt must be a URL on the configured lane', {
						status: 400
					});
			}
			try {
				if (receiptUrl) {
					const receipt = await fetchReceipt(receiptUrl);
					return receipt.state === 'ready'
						? new Response(receipt.receipt as BodyInit, {
								headers: {
									'Content-Type': receipt.contentType ?? 'application/octet-stream'
								}
							})
						: Response.json({ state: 'pending' }, { status: 202 });
				}
				if (statusUrl) return Response.json(await queryRegistration(statusUrl));
				return new Response('status or receipt query param required', { status: 400 });
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
		super('prepaid turns exhausted — top up to continue');
	}
}

/**
 * A daily demo-turn cap is reached. Distinct from {@link TurnsExhausted}: this
 * is a hard time-boxed bound (429), not a top-up-able balance (402). `scope`
 * says whether the per-user or the global cap fired.
 */
class CapExceeded extends Error {
	constructor(
		readonly scope: 'user' | 'global',
		readonly used: number,
		readonly cap: number
	) {
		super(`daily ${scope} demo-turn cap reached (${used}/${cap})`);
	}
}

class PrincipalError extends Error {
	constructor(
		readonly status: 401 | 403,
		message: string
	) {
		super(message);
	}
}
