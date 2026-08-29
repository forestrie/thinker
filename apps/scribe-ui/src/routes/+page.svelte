<script lang="ts">
	import { onMount } from 'svelte';
	import { SvelteMap } from 'svelte/reactivity';
	import { DemoWallet } from '$lib/wallet.svelte.ts';
	import { UserRootKey } from '$lib/user-root.ts';
	import { PasskeyRoot } from '$lib/passkey.ts';
	import { ScribeSession } from '$lib/session.svelte.ts';
	import { ScribeChat } from '$lib/chat.svelte.ts';
	import { ProofPanel as ProofPanelState } from '$lib/proofs.svelte.ts';
	import { TurnVault } from '$lib/vault.svelte.ts';
	import { leasePhase } from '$lib/lease.ts';
	import { matchWorkIds } from '$lib/transcript-match.ts';
	import { agentTurnStatus, captionLabel, userTurnStatus } from '$lib/receipt-status.ts';
	import AppHeader from '$lib/components/AppHeader.svelte';
	import ReceiptBanner from '$lib/components/ReceiptBanner.svelte';
	import SetupCard from '$lib/components/setup/SetupCard.svelte';
	import ChatPanel from '$lib/components/chat/ChatPanel.svelte';
	import Composer from '$lib/components/chat/Composer.svelte';
	import ReceiptsDrawer from '$lib/components/receipts/ReceiptsDrawer.svelte';

	const wallet = new DemoWallet();
	const session = new ScribeSession(wallet);
	// The user's per-turn signing key (Phase 4a): a non-extractable WebCrypto
	// P-256 key — the wallet keeps only session auth and x402 payment (Q2
	// custody split). Under passkey custody (4.1, ADR-0064) this key is the
	// SESSION key, endorsed once by the passkey root below; with no
	// authenticator it remains the log root itself (Q4 fallback).
	const userRoot = new UserRootKey();
	// The passkey log root (Phase 4.1): signs ceremonies only — every
	// assertion costs a gesture, so per-turn leaves stay with the session key.
	const passkey = new PasskeyRoot();
	// The user's own copy of their prompts (D4). Keyed to the wallet: a reset
	// identity starts with an empty vault, as it should.
	const vault = new TurnVault(wallet.address);
	const proofs = new ProofPanelState(session, wallet, userRoot, vault, passkey);
	// The proof panel is also the turn's endorsement source (ADR-0065 §2):
	// under passkey custody every envelope carries the passkey's endorsement
	// of the session key before the session key signs it.
	const chat = new ScribeChat(session, userRoot, vault, proofs);

	// A settled turn means new commitments are in flight — pull the export.
	chat.onTurnSettled = () => void proofs.refresh();

	let drawerOpen = $state(false);
	// Slow tick for the lease-driven chips and banner: they display minutes,
	// so 30s keeps them honest without busywork.
	let now = $state(Date.now());
	$effect(() => {
		const timer = setInterval(() => (now = Date.now()), 30_000);
		return () => clearInterval(timer);
	});

	// The page's one state machine: which screen owns the center.
	const phase = $derived.by(
		(): 'preparing' | 'welcome' | 'add-turns' | 'chat' | 'reset' | 'error' => {
			switch (proofs.onboarding) {
				case 'needs-activation':
					return 'welcome';
				case 'reset-required':
					return 'reset';
				case 'error':
					return 'error';
				case 'registered':
					// A parked challenge with no user log and NO conversation yet is
					// the unpaid first batch — the explicit Approve payment step
					// (setup, step 2). Mid-conversation the same wire state is batch
					// exhaustion (the DO clears the log id and parks a fresh
					// challenge): that belongs to the OutOfTurnsBar — a transcript
					// the user is reading must never unmount.
					return proofs.grantChallenge !== null &&
						proofs.userLogId === null &&
						chat.messages.length === 0
						? 'add-turns'
						: 'chat';
				default:
					return 'preparing';
			}
		}
	);

	// Sealing needs one deliberate approval once the log exists, and again
	// when its lease lapses — an ambient banner, never a chat blocker.
	const bannerVariant = $derived.by((): 'first' | 'resume' | null => {
		if (phase !== 'chat') return null;
		if (proofs.userLogId !== null && !proofs.sealingDelegated) return 'first';
		if (proofs.sealingDelegated) {
			const p = leasePhase(proofs.sealingLeaseExpiresAt, now);
			if (p === 'expiring' || p === 'expired') return 'resume';
		}
		return null;
	});

	// Ambient receipt captions: recover each message's workId (local echoes
	// carry it; resynced ones match the vault by text), then read the work's
	// state — user leaf for user bubbles, the work itself for replies.
	const captions = $derived.by(() => {
		const matchable = chat.messages.map((m) => ({
			id: m.id,
			role: m.role,
			workId: m.workId,
			text: m.parts
				.filter((p) => p.type === 'text')
				.map((p) => p.text ?? '')
				.join('')
		}));
		const ids = matchWorkIds(matchable, vault.entries);
		const byWork = new Map(proofs.works.map((w) => [w.workId, w]));
		const out = new SvelteMap<string, { label: string; bad: boolean }>();
		for (const m of matchable) {
			const workId = ids.get(m.id);
			const work = workId ? byWork.get(workId) : undefined;
			if (!work) continue;
			const status = m.role === 'user' ? userTurnStatus(work) : agentTurnStatus(work);
			const label = captionLabel(status, proofs.verifications[work.workId]);
			out.set(m.id, { label, bad: label === 'check failed' || label === 'failed' });
		}
		return out;
	});

	function openReceipts() {
		drawerOpen = true;
		// Re-check the receipts offline so rows can honestly say "verified" —
		// but only when something receipted is still unchecked: verifyAll is
		// sequential and holds the per-row Verify buttons disabled while it runs.
		if (proofs.works.some((w) => w.state === 'receipted' && !proofs.verifications[w.workId]))
			void proofs.verifyAll();
	}

	onMount(() => {
		void (async () => {
			try {
				await session.ensure();
				// Register (or defer) the root FIRST — it is the instance's first
				// touch, so grant-at-bind either sees the pinned root or sees the
				// custody-pending declaration and waits (4.3). Only then may any
				// other route bind the principal.
				await proofs.registerRoot();
				await chat.connect();
				await proofs.refresh();
			} catch {
				// session.error / chat.connectionDetail carry the story
			}
		})();
		return () => {
			chat.disconnect();
			proofs.stop();
		};
	});

	function resetIdentity() {
		void (async () => {
			// Root first: a fresh wallet means a fresh DO instance, and the new
			// instance must pin the NEW root, not resurface the old pair.
			await passkey.reset();
			await userRoot.reset();
			wallet.reset();
			session.clear();
			location.reload();
		})();
	}
</script>

<div class="flex h-dvh flex-col bg-kumo-recessed">
	<AppHeader
		{proofs}
		{chat}
		{session}
		{wallet}
		{now}
		onreceipts={openReceipts}
		onreset={resetIdentity}
	/>

	{#if bannerVariant}
		<ReceiptBanner
			variant={bannerVariant}
			custody={proofs.custody}
			busy={proofs.delegation === 'working'}
			detail={proofs.delegation === 'error' ? proofs.delegationDetail : null}
			onapprove={() => proofs.delegateUserSealing()}
		/>
	{:else if phase === 'chat' && proofs.userGrantError && proofs.userLogId === null && proofs.grantChallenge === null}
		<!-- Grant acquisition is failing and there is no action to offer —
		     say so plainly rather than letting held turns read as breakage. -->
		<div class="flex justify-center px-3 pt-3">
			<div
				class="w-full max-w-3xl rounded-xl border border-kumo-warning/40 bg-kumo-warning-tint px-4 py-2.5 text-[13px] leading-snug text-kumo-default"
			>
				<strong class="font-semibold text-kumo-strong">Your log isn't ready yet</strong>
				— we're retrying automatically. You can keep chatting; your turns are kept safe until it exists.
			</div>
		</div>
	{/if}

	<main class="flex min-h-0 flex-1 flex-col">
		{#if phase === 'chat'}
			<ChatPanel
				{chat}
				{captions}
				outOfTurns={proofs.prepaidTurns === 0 ||
					(proofs.grantChallenge !== null && proofs.userLogId === null)}
				addBusy={proofs.payment === 'paying'}
				addDetail={proofs.payment === 'error' ? proofs.paymentDetail : null}
				onaddturns={() => proofs.topUp()}
			/>
		{:else}
			<div class="flex min-h-0 flex-1 items-center justify-center overflow-y-auto p-4">
				{#if phase === 'preparing'}
					<p class="text-sm text-kumo-subtle">Preparing…</p>
				{:else}
					<SetupCard
						{proofs}
						variant={phase === 'add-turns' ? 'add-turns' : phase === 'welcome' ? 'welcome' : phase}
						onreset={resetIdentity}
					/>
				{/if}
			</div>
			<div class="mx-auto w-full max-w-3xl">
				<Composer
					disabled={true}
					placeholder={phase === 'add-turns'
						? 'Add turns to begin chatting'
						: phase === 'welcome' || phase === 'preparing'
							? 'Start your log to begin chatting'
							: 'Start fresh to continue'}
					onsend={() => {}}
				/>
			</div>
		{/if}
	</main>

	<ReceiptsDrawer {proofs} open={drawerOpen} onclose={() => (drawerOpen = false)} />
</div>
