import { env } from '$env/dynamic/public';
import {
	verifyParentPolicyOffline,
	verifyWorkReceipt,
	type ParentPolicyResult,
	type WorkVerifyResult
} from '@forestrie/think-scribe/forestrie/receipt';
import { delegateSealingKs256 } from '@forestrie/think-scribe/forestrie/delegate';
import {
	confirmUserSealingDelegated,
	fetchIdentity,
	fetchReceipts,
	kickReceiptCollection,
	payUserGrant,
	type DemoTurnCounters,
	type IdentityResponse,
	type ReceiptsExport,
	type WorkExportWire
} from './scribe-api.ts';
import type { ScribeSession } from './session.svelte.ts';
import type { DemoWallet } from './wallet.svelte.ts';
import { hexToBytes } from './utils.ts';

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
 * start, the user's wallet address from the wallet itself.
 */
export class ProofPanel {
	#session: ScribeSession;
	#wallet: DemoWallet;
	#pollTimer: ReturnType<typeof setTimeout> | null = null;

	export = $state<ReceiptsExport | null>(null);
	/** Pinned at first fetch — the "known log key" enrolment (FOR-297). */
	identity = $state<IdentityResponse | null>(null);
	verifications = $state<Record<string, WorkVerification>>({});
	refreshing = $state(false);
	verifying = $state(false);
	error = $state<string | null>(null);

	delegation = $state<'idle' | 'working' | 'done' | 'error'>('idle');
	delegationDetail = $state<string | null>(null);

	/** x402 user-grant purchase (W4b): the wallet signs the parked challenge. */
	payment = $state<'idle' | 'paying' | 'paid' | 'error'>('idle');
	paymentDetail = $state<string | null>(null);
	#paying: Promise<void> | null = null;

	/** Offline parent-policy proof (W4d): payment policy as a receipted fact. */
	policy = $state<'idle' | 'verifying' | 'done' | 'error'>('idle');
	policyResult = $state<ParentPolicyResult | null>(null);

	constructor(session: ScribeSession, wallet: DemoWallet) {
		this.#session = session;
		this.#wallet = wallet;
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
		// Buy the user grant if a payment-gated lane parked a challenge (W4b).
		// Fire-and-forget: single-flight inside, and it refreshes on success.
		if (this.payment !== 'error') void this.ensureUserGrantPaid();
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
		// the activation button waits on its id.
		const onboarding = this.export?.attestationMode === 'separate' && this.userLogId === null;
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
			const result = await verifyWorkReceipt(
				work,
				hexToBytes(this.identity.publicKeyXY),
				this.#wallet.addressBytes()
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
	 * The user's half of T9: authorize the lane's vouched sealer for the
	 * USER's log, signed by the wallet in the browser — the DO never sees
	 * the key. Until this runs once per user log, user leaves sequence but
	 * never seal (receipts stay pending); agent leaves are unaffected.
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
			const result = await delegateSealingKs256(
				this.#wallet.privateKeyHex(),
				this.#wallet.addressBytes(),
				{ coordinatorUrl, logId: userLogId, knownSealerKeyB64 }
			);
			this.delegation = 'done';
			// Formatted immediately into a string — the Date never outlives this
			// expression, so there is nothing for a SvelteDate to make reactive.
			// eslint-disable-next-line svelte/prefer-svelte-reactivity
			const expiry = new Date(result.expiresAt * 1000).toLocaleTimeString();
			this.delegationDetail = `sealer ${result.sealerId} until ${expiry}`;
			// Tell the DO: held user leaves release, and collection resumes
			// for anything already waiting on the lane.
			try {
				await confirmUserSealingDelegated(this.#session.sub!, await this.#session.ensure());
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
