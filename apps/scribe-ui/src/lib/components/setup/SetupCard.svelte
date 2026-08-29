<script lang="ts">
	import type { ProofPanel } from '$lib/proofs.svelte.ts';
	import Button from '$lib/components/ui/Button.svelte';
	import { Coins, Fingerprint, LoaderCircle } from '@lucide/svelte';

	let {
		proofs,
		variant,
		onreset
	}: {
		proofs: ProofPanel;
		variant: 'welcome' | 'add-turns' | 'reset' | 'error';
		onreset: () => void;
	} = $props();
</script>

<div
	class="flex w-[440px] max-w-full flex-col items-center gap-4 rounded-xl border border-kumo-line bg-kumo-elevated p-9 text-center shadow-sm"
>
	{#if variant === 'welcome'}
		<span
			class="flex size-14 items-center justify-center rounded-full bg-kumo-info-tint text-kumo-brand"
		>
			<Fingerprint class="size-7" />
		</span>
		<div class="space-y-2">
			<h2 class="text-xl font-semibold tracking-tight text-kumo-strong">
				A conversation you can prove
			</h2>
			<p class="text-sm leading-relaxed text-kumo-subtle">
				Every turn is signed — by you and by the Scribe. You keep the receipts, and anyone can check
				them, forever.
			</p>
		</div>
		<div class="mt-1 flex w-full flex-col gap-2">
			<Button
				variant="primary"
				disabled={proofs.activating}
				title="Create a passkey as your log's root key, then approve this browser's signing key"
				onclick={() => proofs.activateWithPasskey()}
			>
				{#if proofs.activating}
					<LoaderCircle class="size-4 animate-spin" />
				{:else}
					<Fingerprint class="size-4" />
				{/if}
				Start with Touch ID
			</Button>
			<Button
				variant="ghost"
				disabled={proofs.activating}
				title="Root your log in this browser's software key instead — one-way: switching to a passkey later means starting a fresh log"
				onclick={() => proofs.continueWithoutPasskey()}
			>
				Use a browser key instead
			</Button>
		</div>
		<p class="text-xs leading-relaxed text-kumo-subtle">
			Two quick Touch ID prompts to start — then none while you chat.
		</p>
		<a
			href="https://github.com/forestrie/thinker/blob/main/docs/why-a-passkey.md"
			target="_blank"
			rel="noreferrer"
			class="text-xs font-medium text-kumo-brand hover:underline"
		>
			Why a passkey?
		</a>
		{#if proofs.onboardingDetail}
			<p class="text-xs text-kumo-danger">{proofs.onboardingDetail}</p>
		{/if}
	{:else if variant === 'add-turns'}
		<span
			class="flex size-14 items-center justify-center rounded-full bg-kumo-info-tint text-kumo-brand"
		>
			<Coins class="size-6" />
		</span>
		<div class="space-y-2">
			<h2 class="text-xl font-semibold tracking-tight text-kumo-strong">Add turns</h2>
			<p class="text-sm leading-relaxed text-kumo-subtle">
				Chat comes in prepaid batches. Approve one small payment and talk freely — no prompts
				between turns.
			</p>
		</div>
		<Button
			variant="primary"
			class="mt-1 w-full"
			disabled={proofs.payment !== 'idle' && proofs.payment !== 'error'}
			onclick={() => void proofs.ensureUserGrantPaid()}
		>
			{#if proofs.payment === 'paying' || proofs.payment === 'processing'}
				<LoaderCircle class="size-4 animate-spin" />
			{/if}
			Approve payment
		</Button>
		{#if proofs.payment === 'processing'}
			<p class="flex items-center gap-1.5 text-xs text-kumo-subtle">
				<LoaderCircle class="size-3 animate-spin" />
				Payment received — sealing your grant into the log (a minute or two)…
			</p>
		{:else if proofs.payment === 'paid'}
			<p class="flex items-center gap-1.5 text-xs text-kumo-subtle">
				<LoaderCircle class="size-3 animate-spin" />
				Payment received — preparing your log…
			</p>
		{:else if proofs.payment === 'error'}
			<p class="text-xs text-kumo-danger">
				Payment didn't go through.
				{#if proofs.paymentDetail}<span class="block">{proofs.paymentDetail}</span>{/if}
			</p>
		{:else}
			<p class="text-xs text-kumo-subtle">USDC on Base Sepolia — test money for now.</p>
		{/if}
		<div class="mt-0.5 flex items-center gap-1.5">
			<span class="size-1.5 rounded-full bg-kumo-success"></span>
			<span class="size-1.5 rounded-full bg-kumo-brand"></span>
			<span class="ml-1 text-[11px] text-kumo-subtle">step 2 of 2</span>
		</div>
	{:else}
		<div class="space-y-2">
			<h2 class="text-xl font-semibold tracking-tight text-kumo-strong">
				{variant === 'reset'
					? 'This log belongs to another key'
					: 'Something went wrong starting your log'}
			</h2>
			<p class="text-sm leading-relaxed text-kumo-subtle">
				{variant === 'reset'
					? 'This log is rooted by a key this browser no longer holds. Start fresh to begin a new one.'
					: (proofs.onboardingDetail ?? 'An unexpected error occurred.')}
			</p>
			{#if variant === 'reset' && proofs.onboardingDetail}
				<p class="text-xs text-kumo-subtle">{proofs.onboardingDetail}</p>
			{/if}
		</div>
		<Button variant="primary" class="mt-1" onclick={onreset}>Start fresh</Button>
	{/if}
</div>
