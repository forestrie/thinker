<script lang="ts">
	import type { ProofPanel } from '$lib/proofs.svelte.ts';
	import type { ScribeChat } from '$lib/chat.svelte.ts';
	import type { ScribeSession } from '$lib/session.svelte.ts';
	import type { DemoWallet } from '$lib/wallet.svelte.ts';
	import { leasePhase } from '$lib/lease.ts';
	import Badge from '$lib/components/ui/Badge.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import ScribeMark from '$lib/components/ScribeMark.svelte';
	import WalletChip from './WalletChip.svelte';
	import { Check, RotateCcw } from '@lucide/svelte';

	let {
		proofs,
		chat,
		session,
		wallet,
		now,
		onreceipts,
		onreset
	}: {
		proofs: ProofPanel;
		chat: ScribeChat;
		session: ScribeSession;
		wallet: DemoWallet;
		/** Slow tick from the page — the lease chip re-derives on it. */
		now: number;
		onreceipts: () => void;
		onreset: () => void;
	} = $props();

	// One place decides what the log chip says, or it will drift: connection
	// trouble outranks everything, then registration, then the lease.
	const logChip = $derived.by(
		(): { label: string; tone: 'success' | 'warning' | 'danger' | 'neutral' } => {
			if (chat.connection === 'error') return { label: 'Connection lost', tone: 'danger' };
			if (proofs.onboarding === 'registered') {
				if (proofs.sealingDelegated && leasePhase(proofs.sealingLeaseExpiresAt, now) === 'expired')
					return { label: 'Log paused', tone: 'warning' };
				return { label: 'Log active', tone: 'success' };
			}
			return { label: 'Setting up', tone: 'neutral' };
		}
	);
</script>

<header
	class="flex items-center justify-between gap-3 border-b border-kumo-line bg-kumo-elevated px-4 py-2.5"
>
	<div class="flex items-center gap-2.5">
		<span class="flex size-8 items-center justify-center rounded-lg bg-kumo-brand text-white">
			<ScribeMark class="size-5" />
		</span>
		<h1 class="text-sm leading-tight font-semibold text-kumo-strong">The Scribe</h1>
	</div>
	<div class="flex items-center gap-2">
		{#if session.error}
			<Badge tone="danger" title={session.error}>auth failed</Badge>
		{/if}
		<Badge tone={logChip.tone}>
			<span class="size-1.5 rounded-full bg-current"></span>
			{logChip.label}
		</Badge>
		{#if proofs.prepaidTurns !== null}
			<Badge tone={proofs.prepaidTurns === 0 ? 'warning' : 'neutral'}>
				<span class="max-sm:hidden">{proofs.prepaidTurns} turns left</span>
				<span class="sm:hidden">{proofs.prepaidTurns} left</span>
			</Badge>
		{/if}
		<Button size="sm" variant="ghost" title="Your receipts" onclick={onreceipts}>
			<Check class="size-3.5" />
			Receipts
		</Button>
		<WalletChip {wallet} grantChallenge={proofs.grantChallenge} />
		<Button
			size="sm"
			variant="ghost"
			title="Forget this identity and start fresh"
			onclick={onreset}
		>
			<RotateCcw class="size-3.5" />
		</Button>
	</div>
</header>
