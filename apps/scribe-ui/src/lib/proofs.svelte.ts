import { env } from '$env/dynamic/public';
import {
	verifyWorkReceipt,
	type WorkVerifyResult
} from '@forestrie/think-scribe/forestrie/receipt';
import { delegateSealingKs256 } from '@forestrie/think-scribe/forestrie/delegate';
import {
	fetchIdentity,
	fetchReceipts,
	kickReceiptCollection,
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
	const live = (s: string) => s === 'submitted' || s === 'queued' || s === 'registered' || s === 'sequenced';
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

	constructor(session: ScribeSession, wallet: DemoWallet) {
		this.#session = session;
		this.#wallet = wallet;
	}

	get works(): WorkExportWire[] {
		return this.export?.works ?? [];
	}

	get anyInFlight(): boolean {
		return this.works.some(inFlight);
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
		this.#schedulePoll();
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
		if (!this.anyInFlight) return;
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
		const userLogId = this.export?.forestrie.userLogId ?? this.identity?.userLogId;
		if (!knownSealerKeyB64) {
			this.delegation = 'error';
			this.delegationDetail = 'PUBLIC_KNOWN_SEALER_KEY not configured';
			return;
		}
		if (!userLogId) {
			this.delegation = 'error';
			this.delegationDetail = 'no user log yet — send an attested turn first';
			return;
		}
		this.delegation = 'working';
		this.delegationDetail = null;
		try {
			const result = await delegateSealingKs256(
				this.#wallet.privateKeyHex(),
				this.#wallet.addressBytes(),
				{ coordinatorUrl, logId: userLogId, knownSealerKeyB64 }
			);
			this.delegation = 'done';
			this.delegationDetail = `sealer ${result.sealerId} until ${new Date(result.expiresAt * 1000).toLocaleTimeString()}`;
		} catch (err) {
			this.delegation = 'error';
			this.delegationDetail = String(err);
		}
	}
}
