import { env } from '$env/dynamic/public';
import {
	verifyParentPolicyOffline,
	verifyWorkReceipt,
	type ParentPolicyResult,
	type WorkVerifyResult
} from '@forestrie/think-scribe/forestrie/receipt';
import {
	delegateSealing,
	delegateSealingWebauthn
} from '@forestrie/think-scribe/forestrie/delegate';
import {
	confirmUserSealingDelegated,
	fetchIdentity,
	fetchReceipts,
	kickReceiptCollection,
	payUserGrant,
	postCustodyPending,
	postUserRoot,
	ScribeApiError,
	type DemoTurnCounters,
	type IdentityResponse,
	type ReceiptsExport,
	type WorkExportWire
} from './scribe-api.ts';
import { bootRegistration } from './custody.ts';
import { endorsementPhase } from './endorsement.ts';
import type { EndorsementProvider } from './chat.svelte.ts';
import type { ScribeSession } from './session.svelte.ts';
import type { DemoWallet } from './wallet.svelte.ts';
import type { UserRootKey } from './user-root.ts';
import { PasskeyRoot } from './passkey.ts';
import type { TurnVault } from './vault.svelte.ts';
import { bytesToHex as bytesToHexLocal, hexToBytes } from './utils.ts';

/** Sequencing is seconds; sealing minutes — poll gently while in flight. */
const POLL_MS = 6000;

export interface WorkVerification extends WorkVerifyResult {
	at: number;
}

function inFlight(work: WorkExportWire): boolean {
	const live = (s: string) =>
		s === 'submitted' || s === 'queued' || s === 'registered' || s === 'sequenced';
	return live(work.state) || (work.userLeaf ? live(work.userLeaf.state) : false);
}

/**
 * The Forestrie proof panel state (plan §5.1, "the demo's point"): the
 * per-turn commitment lifecycle from `GET /receipts`, offline verification
 * in the browser via the receipt.ts primitives, and the user-side sealing
 * delegation for their own log. The trust roots are pinned OUT of the
 * export being audited: the agent key from `GET /identity` at session
 * start, the user's root key from the browser's own custody (Phase 4a).
 */
export class ProofPanel implements EndorsementProvider {
	#session: ScribeSession;
	#wallet: DemoWallet;
	#userRoot: UserRootKey;
	#passkey: PasskeyRoot | null;
	#vault: TurnVault;
	#pollTimer: ReturnType<typeof setTimeout> | null = null;

	export = $state<ReceiptsExport | null>(null);
	/** Pinned at first fetch — the "known log key" enrolment (FOR-297). */
	identity = $state<IdentityResponse | null>(null);
	verifications = $state<Record<string, WorkVerification>>({});
	refreshing = $state(false);
	verifying = $state(false);
	error = $state<string | null>(null);

	/**
	 * Root onboarding (4.3, ADR-0064): where this browser stands on declaring
	 * its log root. `needs-activation` = WebAuthn is available and NO custody
	 * shape is pinned — passkey creation waits behind the explicit "Activate
	 * your log" gesture, and chat is locked (turn admission needs the root).
	 * `reset-required` = the DO holds a root this browser no longer does.
	 */
	onboarding = $state<'pending' | 'needs-activation' | 'registered' | 'reset-required' | 'error'>(
		'pending'
	);
	onboardingDetail = $state<string | null>(null);
	/** Which custody shape won: the passkey root, or the 4a session root. */
	custody = $state<'passkey' | 'session' | null>(null);
	/** True while the activation ceremony's gestures are in flight. */
	activating = $state(false);
	/**
	 * When the passkey's endorsement of this browser's signing key lapses
	 * (unix ms, ADR-0065 §3) — the countdown next to the sealing lease. Null
	 * under 4a custody or before the first endorsement.
	 */
	endorsementExpiresAt = $state<number | null>(null);
	/** True while an explicit re-endorsement gesture is in flight. */
	reendorsing = $state(false);
	/** The endorsement the DO last saw — re-posted when it changes. */
	#postedEndorsementB64: string | null = null;

	delegation = $state<'idle' | 'working' | 'done' | 'error'>('idle');
	delegationDetail = $state<string | null>(null);
	/** Sealing-lease expiry (epoch seconds) from THIS session's delegation. */
	#leaseExpiresAt = $state<number | null>(null);

	/** x402 user-grant purchase (W4b): the wallet signs the parked challenge. */
	payment = $state<'idle' | 'paying' | 'paid' | 'error'>('idle');
	paymentDetail = $state<string | null>(null);
	#paying: Promise<void> | null = null;

	/** Offline parent-policy proof (W4d): payment policy as a receipted fact. */
	policy = $state<'idle' | 'verifying' | 'done' | 'error'>('idle');
	policyResult = $state<ParentPolicyResult | null>(null);

	constructor(
		session: ScribeSession,
		wallet: DemoWallet,
		userRoot: UserRootKey,
		vault: TurnVault,
		/** Passkey custody (4.1): the log root when present; else 4a stands. */
		passkey: PasskeyRoot | null = null
	) {
		this.#session = session;
		this.#wallet = wallet;
		this.#userRoot = userRoot;
		this.#vault = vault;
		this.#passkey = passkey;
	}

	/**
	 * The mount-time half of onboarding (4.3) — NO user gesture available, so
	 * this only re-posts a shape that already exists or defers. The decision
	 * table is `bootRegistration` (custody.ts): an existing passkey re-posts
	 * the endorsed shape silently (endorsement cached — one gesture EVER); a
	 * WebAuthn-free runtime posts the 4a session root; anything else declares
	 * the custody choice PENDING to the DO — which then holds `grant_user`
	 * until a root lands — and waits for the activation gesture.
	 */
	async registerRoot(): Promise<void> {
		try {
			const plan = bootRegistration({
				webauthnSupported: this.#passkey !== null && PasskeyRoot.supported(),
				hasPasskeyRecord: ((await this.#passkey?.currentPublicKeyXY()) ?? null) !== null
			});
			if (plan === 'endorsed-post') {
				try {
					await this.#postEndorsedRoot();
				} catch (err) {
					if (err instanceof ScribeApiError && err.status === 409) {
						// Legacy instance: the pinned root predates passkey custody
						// (it is the 4a session key) — the bare idempotent post
						// stands, and upgrading means an identity reset (ADR-0064).
						await this.#postSessionRoot();
					} else {
						// Likely a re-endorsement needing a gesture (session key
						// rotated) — the activation button retries WITH one.
						this.onboarding = 'needs-activation';
						this.onboardingDetail = String(err);
					}
				}
			} else if (plan === 'bare-post') {
				await this.#postSessionRoot();
			} else {
				const pending = await postCustodyPending(this.#session.sub!, await this.#session.ensure());
				if (!pending.custodyPending && pending.publicKeyXY) {
					// A root was pinned in an earlier session. If it is our session
					// key, this is settled 4a custody; anything else is a key this
					// browser no longer holds.
					if (pending.publicKeyXY === (await this.#userRoot.publicKeyXYHex()))
						await this.#postSessionRoot();
					else {
						this.onboarding = 'reset-required';
						this.onboardingDetail =
							'this log is rooted by a key this browser no longer holds — reset your identity to start a fresh log';
					}
				} else {
					this.onboarding = 'needs-activation';
				}
			}
		} catch (err) {
			this.onboarding = 'error';
			this.onboardingDetail = String(err);
		}
	}

	/**
	 * THE activation gesture (4.3): create the passkey (browser prompt),
	 * endorse the session key (assertion prompt — ADR-0064's one extra
	 * gesture), and post root + session + endorsement. Must run from a click:
	 * `credentials.create()` needs a user activation.
	 */
	async activateWithPasskey(): Promise<void> {
		if (this.activating) return;
		this.activating = true;
		this.onboardingDetail = null;
		try {
			const record = await this.#passkey?.create();
			if (!record) {
				this.onboardingDetail =
					'passkey creation was refused or cancelled — try again, or continue without one';
				return;
			}
			await this.#postEndorsedRoot();
			await this.refresh();
		} catch (err) {
			if (err instanceof ScribeApiError && err.status === 409) {
				this.onboarding = 'reset-required';
				this.onboardingDetail =
					'a different root is already pinned to this log — reset your identity to re-root';
			} else {
				this.onboardingDetail = String(err);
			}
		} finally {
			this.activating = false;
		}
	}

	/**
	 * The explicit 4a opt-out: pin the session key as the log ROOT. What used
	 * to happen silently at page load now costs a deliberate click, because it
	 * is one-way — upgrading to a passkey afterwards means an identity reset.
	 */
	async continueWithoutPasskey(): Promise<void> {
		if (this.activating) return;
		this.activating = true;
		this.onboardingDetail = null;
		try {
			await this.#postSessionRoot();
			await this.refresh();
		} catch (err) {
			this.onboardingDetail = String(err);
		} finally {
			this.activating = false;
		}
	}

	/**
	 * Post root + session key + endorsement (ADR-0064 §3 pin-or-rotate; the
	 * DO's copy is display-only since ADR-0065). At mount there is no user
	 * activation, so an existing UNEXPIRED endorsement is re-posted as-is even
	 * if it is lapsing — the next turn's click re-endorses it; only an absent
	 * or expired one forces the gesture here (and a refused gesture lands in
	 * `needs-activation`, whose button retries with one).
	 */
	async #postEndorsedRoot(opts: { force?: boolean } = {}): Promise<void> {
		const rootHex = await this.#passkey!.publicKeyXYHex();
		if (!rootHex) throw new Error('no passkey record to post');
		const sessionXY = await this.#userRoot.publicKeyXY();
		let current = opts.force ? null : await this.#passkey!.currentEndorsement(sessionXY);
		if (!current || endorsementPhase(current.notAfter, Date.now()) === 'expired')
			current = await this.#passkey!.ensureEndorsement(sessionXY, { force: opts.force });
		await postUserRoot(this.#session.sub!, await this.#session.ensure(), rootHex, {
			sessionPublicKeyXY: await this.#userRoot.publicKeyXYHex(),
			endorsementB64: current.endorsementB64
		});
		this.#postedEndorsementB64 = current.endorsementB64;
		this.endorsementExpiresAt = current.notAfter;
		this.custody = 'passkey';
		this.onboarding = 'registered';
		this.onboardingDetail = null;
	}

	/**
	 * {@link EndorsementProvider}: the endorsement each turn carries (ADR-0065
	 * §2). Under passkey custody this is the passkey's CURRENT endorsement of
	 * the session key, re-minted (one prompt, riding on the send click) when
	 * the window is lapsing; a fresh one is also posted to the DO so
	 * `/receipts` displays what the leaves carry. Null under 4a custody.
	 */
	async forTurn(sessionPublicKeyXY: Uint8Array): Promise<Uint8Array | null> {
		if (this.custody !== 'passkey' || !this.#passkey) return null;
		const current = await this.#passkey.ensureEndorsement(sessionPublicKeyXY);
		this.endorsementExpiresAt = current.notAfter;
		if (current.endorsementB64 !== this.#postedEndorsementB64) {
			const rootHex = await this.#passkey.publicKeyXYHex();
			if (rootHex)
				await postUserRoot(this.#session.sub!, await this.#session.ensure(), rootHex, {
					sessionPublicKeyXY: bytesToHexLocal(sessionPublicKeyXY),
					endorsementB64: current.endorsementB64
				});
			this.#postedEndorsementB64 = current.endorsementB64;
		}
		return current.endorsement;
	}

	/** The explicit re-endorsement gesture (the countdown's button). */
	async reendorse(): Promise<void> {
		if (this.reendorsing || this.custody !== 'passkey') return;
		this.reendorsing = true;
		this.onboardingDetail = null;
		try {
			await this.#postEndorsedRoot({ force: true });
		} catch (err) {
			this.onboardingDetail = String(err);
		} finally {
			this.reendorsing = false;
		}
	}

	/**
	 * The passkey root to dispatch on, respecting the SETTLED custody shape:
	 * under session custody (including the legacy 409 fallback) a stray local
	 * passkey record must not win — the DO's pinned root is the session key,
	 * and a WebAuthn ceremony against it could never verify.
	 */
	async #passkeyRootXY(): Promise<Uint8Array | null> {
		if (this.custody === 'session') return null;
		return (await this.#passkey?.currentPublicKeyXY()) ?? null;
	}

	async #postSessionRoot(): Promise<void> {
		try {
			await postUserRoot(
				this.#session.sub!,
				await this.#session.ensure(),
				await this.#userRoot.publicKeyXYHex()
			);
		} catch (err) {
			if (err instanceof ScribeApiError && err.status === 409) {
				this.onboarding = 'reset-required';
				this.onboardingDetail =
					'this log is rooted by a different key — reset your identity to start a fresh log';
				return;
			}
			throw err;
		}
		this.custody = 'session';
		this.onboarding = 'registered';
		this.onboardingDetail = null;
	}

	/** The user's locally-kept copy of a prompt, if this browser still has it. */
	keptInput(workId: string): string | null {
		return this.#vault.input(workId);
	}

	get keptCount(): number {
		return this.#vault.count;
	}

	get works(): WorkExportWire[] {
		return this.export?.works ?? [];
	}

	/**
	 * The user's own log id — null until the first drain creates it (the DO
	 * requests `grant_user` when the first attested turn commits), which is
	 * why sealing can only be authorized AFTER the first turn.
	 */
	get userLogId(): string | null {
		return this.export?.forestrie.userLogId ?? this.identity?.userLogId ?? null;
	}

	/** True once the DO knows sealing was authorized (any session). */
	get sealingDelegated(): boolean {
		return (
			this.delegation === 'done' ||
			(this.export?.forestrie.userSealingDelegated ?? this.identity?.userSealingDelegated ?? false)
		);
	}

	/**
	 * When the sealing lease expires (epoch seconds): this session's own
	 * delegation first, else the DO-exported claim from an earlier one (4.3).
	 * Null = no lease on record (pre-4.3 confirmation, or never delegated).
	 */
	get sealingLeaseExpiresAt(): number | null {
		return (
			this.#leaseExpiresAt ??
			this.export?.forestrie.userSealingLeaseExpiresAt ??
			this.identity?.userSealingLeaseExpiresAt ??
			null
		);
	}

	get anyInFlight(): boolean {
		return this.works.some(inFlight);
	}

	/**
	 * A parked x402 challenge (W4b) awaiting the wallet's signature — set on a
	 * payment-gated lane once grant-at-bind hits canopy's 402, cleared when the
	 * grant is bought. Null on dark lanes. Read from the polled export first
	 * (identity is pinned at first fetch, before the challenge is parked).
	 */
	get grantChallenge(): string | null {
		return this.export?.forestrie.userGrantChallenge ?? this.identity?.userGrantChallenge ?? null;
	}

	/**
	 * Turns remaining in the purchased batch (W4c) — polled from the export
	 * (the balance moves per turn); null = unmetered (dark lane before any
	 * grant, or embed mode).
	 */
	/**
	 * Why the Scribe's last attempt to get the user grant failed, if it did.
	 * Non-null means the "Activate your log" card must say so rather than claim
	 * the log is still being created — the DO retries on a cooldown, so this is
	 * a status, not a dead end (plan-2608-11).
	 */
	get userGrantError(): string | null {
		return this.identity?.userGrantError ?? null;
	}

	get prepaidTurns(): number | null {
		return this.export?.forestrie.prepaidTurns ?? this.identity?.prepaidTurns ?? null;
	}

	/**
	 * Daily demo-turn counters. Read from the polled export first — /identity is
	 * pinned at first fetch, so its counters go stale while /receipts tracks the
	 * live values.
	 */
	get demoTurns(): DemoTurnCounters | null {
		return this.export?.forestrie.demoTurns ?? this.identity?.demoTurns ?? null;
	}

	async refresh(): Promise<void> {
		this.refreshing = true;
		try {
			const token = await this.#session.ensure();
			const sub = this.#session.sub!;
			this.identity ??= await fetchIdentity(sub, token);
			this.export = await fetchReceipts(sub, token);
			this.error = null;
		} catch (err) {
			this.error = String(err);
		} finally {
			this.refreshing = false;
		}
		// Embed mode has no user log to root, so a deferred custody choice has
		// nothing to choose — settle on the 4a session shape (turn admission
		// still verifies envelopes against it). The mode is only knowable from
		// the DO, and the pending declaration had to land before this fetch.
		if (this.export?.attestationMode === 'embed' && this.onboarding === 'needs-activation')
			await this.#postSessionRoot().catch((err) => {
				this.onboarding = 'error';
				this.onboardingDetail = String(err);
			});
		// A parked x402 challenge (W4b) is NOT paid here: money moves only on an
		// explicit gesture — the setup card's "Approve payment" or the
		// out-of-turns "Add more turns", both of which call ensureUserGrantPaid.
		this.#schedulePoll();
	}

	/**
	 * The x402 user-grant purchase (plan-2608-09 W4b). When a payment-gated
	 * lane parks a challenge, the demo wallet signs it (silently, like the
	 * session and sealing signatures) and the DO forwards `X-PAYMENT` to the
	 * authority, which resubmits register-grant → 303. Single-flight; a no-op
	 * on dark lanes (no challenge) and once the grant exists (userLogId set).
	 */
	async ensureUserGrantPaid(): Promise<void> {
		const challenge = this.grantChallenge;
		if (!challenge || this.userLogId) return;
		this.#paying ??= this.#payUserGrant(challenge).finally(() => {
			this.#paying = null;
		});
		return this.#paying;
	}

	async #payUserGrant(challenge: string): Promise<void> {
		this.payment = 'paying';
		try {
			const xPayment = this.#wallet.signX402Payment(challenge);
			const token = await this.#session.ensure();
			await payUserGrant(this.#session.sub!, token, xPayment);
			this.payment = 'paid';
			this.paymentDetail = null;
		} catch (err) {
			this.payment = 'error';
			this.paymentDetail = String(err);
			return;
		}
		await this.refresh();
	}

	/**
	 * Explicit top-up (W4d): re-trigger the W4b purchase. After exhaustion
	 * the DO has already dropped the spent grant and parked (or is parking) a
	 * fresh challenge — refresh to pick it up, clear a sticky payment error,
	 * and let the single-flight purchase run. On a dark lane the new batch
	 * issues without a challenge and the refresh simply shows it.
	 */
	async topUp(): Promise<void> {
		if (this.payment === 'error') this.payment = 'idle';
		await this.refresh();
		await this.ensureUserGrantPaid();
	}

	/**
	 * The offline parent-policy proof (W4d, the demo's honesty beat): decode
	 * the user-authority grant from `/identity`, read `requiresChildPayment`
	 * off its flag bytes, and verify its inclusion receipt under the forest
	 * root key — all in the browser, no network. Proves "user grants cost
	 * money" is a fact of the log, not a claim of the operator.
	 */
	async verifyParentPolicy(): Promise<void> {
		const grantB64 = this.identity?.userAuthorityGrant;
		const rootXY = this.identity?.rootPublicKeyXY;
		if (!grantB64 || !rootXY) {
			this.policy = 'error';
			this.policyResult = {
				ok: false,
				requiresChildPayment: false,
				authorityLogId: '',
				checks: [
					{
						name: 'artifacts',
						ok: false,
						detail: 'user-authority grant / root key not provisioned on this worker'
					}
				]
			};
			return;
		}
		this.policy = 'verifying';
		try {
			this.policyResult = await verifyParentPolicyOffline(grantB64, hexToBytes(rootXY));
			this.policy = 'done';
		} catch (err) {
			this.policy = 'error';
			this.policyResult = {
				ok: false,
				requiresChildPayment: false,
				authorityLogId: '',
				checks: [{ name: 'verify', ok: false, detail: String(err) }]
			};
		}
	}

	/** Ask the DO to poll the lane now (demo acceleration), then refresh. */
	async collectNow(): Promise<void> {
		try {
			const token = await this.#session.ensure();
			await kickReceiptCollection(this.#session.sub!, token);
		} catch (err) {
			this.error = String(err);
		}
		await this.refresh();
	}

	#schedulePoll(): void {
		if (this.#pollTimer) clearTimeout(this.#pollTimer);
		// Keep polling while receipts are in flight, and during onboarding
		// while grant-at-bind is still creating the user's log (~a minute) —
		// the authorize button waits on its id. NOT while the custody choice
		// is still pending (4.3): the DO is deliberately idle then, and the
		// next move is the user's gesture, not a poll.
		const onboarding =
			this.export?.attestationMode === 'separate' &&
			this.userLogId === null &&
			this.onboarding === 'registered';
		if (!this.anyInFlight && !onboarding) return;
		this.#pollTimer = setTimeout(() => {
			void this.refresh();
		}, POLL_MS);
	}

	stop(): void {
		if (this.#pollTimer) clearTimeout(this.#pollTimer);
		this.#pollTimer = null;
	}

	/**
	 * Offline verification of one work unit — statement signature, receipt
	 * (inclusion + checkpoint + delegation), work binding, the user leaf's
	 * KS256 chain, and transcript binding (the check the tamper beat breaks).
	 */
	async verify(work: WorkExportWire): Promise<void> {
		if (!this.identity) return;
		this.verifying = true;
		try {
			// Trust anchors from the browser's OWN custody, never the export's
			// claim of them — the same out-of-band provenance rule as the agent
			// key. Under passkey custody the trust root is the passkey; the
			// envelope signer (the endorsed session key) is resolved from each
			// statement's OWN -65801 endorsement (ADR-0065 §5) — nothing from
			// the export, and nothing from this browser's session key, is
			// trusted for that. Under 4a the root is the WebCrypto key itself.
			const sessionXY = await this.#userRoot.publicKeyXY();
			const passkeyXY = await this.#passkeyRootXY();
			const result = await verifyWorkReceipt(
				// The locally-kept opening rides along when we have it, so the
				// check list gains `input-binding`: this text, and no other, is
				// what the user's root key signed a commitment to (D1/D4).
				{ ...work, input: this.#vault.input(work.workId) ?? undefined },
				hexToBytes(this.identity.publicKeyXY),
				passkeyXY ?? sessionXY
			);
			this.verifications[work.workId] = { ...result, at: Date.now() };
		} catch (err) {
			this.verifications[work.workId] = {
				ok: false,
				checks: [{ name: 'verify', ok: false, detail: String(err) }],
				at: Date.now()
			};
		} finally {
			this.verifying = false;
		}
	}

	async verifyAll(): Promise<void> {
		for (const work of this.works) if (work.state === 'receipted') await this.verify(work);
	}

	/**
	 * The proof bundle (plan §D4) — the demo's closing move.
	 *
	 * Everything an auditor needs, in one file the user holds: the identity
	 * that anchors trust, each turn's envelope, statement, receipt and log
	 * entry, and — only here, never on the lane — the plaintext openings this
	 * browser kept. `scripts/verify-receipts.mjs --export <file>` verifies it
	 * offline, forever, with this service switched off.
	 *
	 * Deliberately the same shape as `GET /receipts` plus `input`, so the
	 * existing verifier reads it unchanged.
	 */
	buildBundle(): Record<string, unknown> | null {
		const exported = this.export;
		if (!exported) return null;
		// Formatted straight into the bundle — the Date never outlives this
		// expression, so there is nothing for a SvelteDate to make reactive.
		// eslint-disable-next-line svelte/prefer-svelte-reactivity
		const exportedAt = new Date().toISOString();
		return {
			kind: 'thinker/proof-bundle/v1',
			exportedAt,
			note: 'Verify offline: scripts/verify-receipts.mjs --export <this file>. The `input` fields are your own copy — they are not held by the service or the log.',
			principal: exported.principal,
			attestationMode: exported.attestationMode,
			identity: exported.identity,
			forestrie: exported.forestrie,
			works: exported.works.map((work) => {
				const input = this.#vault.input(work.workId);
				return input === null ? work : { ...work, input };
			})
		};
	}

	/** Download the bundle as a file. No-op before the first export lands. */
	downloadBundle(): void {
		const bundle = this.buildBundle();
		if (!bundle) return;
		const url = URL.createObjectURL(
			new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' })
		);
		const anchor = document.createElement('a');
		anchor.href = url;
		anchor.download = `scribe-proof-bundle-${this.#session.sub ?? 'export'}.json`;
		anchor.click();
		URL.revokeObjectURL(url);
	}

	/**
	 * Forget the locally-kept message text (D4). LOCAL ONLY: the log entries
	 * these turns produced are permanent by design, and the receipts stay
	 * verifiable — what is lost is this browser's ability to open the
	 * commitments, so download the bundle first if that matters.
	 */
	deleteLocalMessages(): void {
		this.#vault.clear();
	}

	/**
	 * The user's half of T9: authorize the lane's vouched sealer for the
	 * USER's log, signed by the browser-held root key (Phase 4a — the shipped
	 * ES256 `delegateSealing` path, same as the agent's own log) — the DO
	 * never sees the key. Until this runs once per user log, user leaves
	 * sequence but never seal (receipts stay pending); agent leaves are
	 * unaffected.
	 */
	async delegateUserSealing(): Promise<void> {
		const coordinatorUrl = env.PUBLIC_DELEGATION_COORDINATOR_URL ?? '/coordinator';
		const knownSealerKeyB64 = env.PUBLIC_KNOWN_SEALER_KEY;
		if (!knownSealerKeyB64) {
			this.delegation = 'error';
			this.delegationDetail = 'PUBLIC_KNOWN_SEALER_KEY not configured';
			return;
		}
		this.delegation = 'working';
		this.delegationDetail = null;
		// The log is created at the first drain — re-pull the export so a
		// click right after a turn sees a log the panel hasn't polled yet.
		if (!this.userLogId) await this.refresh();
		const userLogId = this.userLogId;
		if (!userLogId) {
			this.delegation = 'error';
			this.delegationDetail =
				'your log does not exist yet — it is created when your first attested turn commits';
			return;
		}
		try {
			// Passkey custody (4.2, ADR-0063): the ceremony signs with the
			// authenticator — two gestures, one per artifact (certificate +
			// on-chain proof). Otherwise the 4a session-root path stands.
			const passkeyXY = await this.#passkeyRootXY();
			const params = { coordinatorUrl, logId: userLogId, knownSealerKeyB64 };
			const result = passkeyXY
				? await delegateSealingWebauthn(
						passkeyXY,
						(challenge) => this.#passkey!.getAssertion(challenge),
						params
					)
				: await delegateSealing(await this.#userRoot.asKeyProvider(), params);
			this.delegation = 'done';
			// The delegation is a LEASE (~6h on the demo lane): keep its expiry
			// so the panel can surface the re-ceremony instead of hiding it (4.3).
			this.#leaseExpiresAt = result.expiresAt;
			// Formatted immediately into a string — the Date never outlives this
			// expression, so there is nothing for a SvelteDate to make reactive.
			// eslint-disable-next-line svelte/prefer-svelte-reactivity
			const expiry = new Date(result.expiresAt * 1000).toLocaleTimeString();
			this.delegationDetail = `sealer ${result.sealerId} until ${expiry}`;
			// Tell the DO: held user leaves release, and collection resumes
			// for anything already waiting on the lane. The reported expiry
			// makes the renewal countdown survive reloads and other tabs.
			try {
				await confirmUserSealingDelegated(
					this.#session.sub!,
					await this.#session.ensure(),
					result.expiresAt
				);
			} catch (err) {
				console.warn('delegation confirmation failed — leaves release on a later drain', err);
			}
			void this.collectNow();
		} catch (err) {
			this.delegation = 'error';
			this.delegationDetail = String(err);
		}
	}
}
