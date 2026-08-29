<script lang="ts">
	import Button from '$lib/components/ui/Button.svelte';
	import { Clock, Fingerprint, LoaderCircle, Stamp } from '@lucide/svelte';

	let {
		variant,
		custody,
		busy,
		detail = null,
		onapprove
	}: {
		/** 'first' = sealing never authorized; 'resume' = the lease lapsed. */
		variant: 'first' | 'resume';
		custody: 'passkey' | 'session' | null;
		busy: boolean;
		detail?: string | null;
		onapprove: () => void;
	} = $props();
</script>

<div class="flex justify-center px-3 pt-3">
	<div
		class="flex w-full max-w-3xl flex-wrap items-center gap-3 rounded-xl border border-kumo-warning/40 bg-kumo-warning-tint py-2.5 pr-2.5 pl-4"
	>
		{#if variant === 'resume'}
			<Clock class="size-4 shrink-0 text-kumo-warning" />
		{:else}
			<Stamp class="size-4 shrink-0 text-kumo-warning" />
		{/if}
		<span class="min-w-0 flex-1 text-[13px] leading-snug text-kumo-default">
			{#if variant === 'resume'}
				<strong class="font-semibold text-kumo-strong">Welcome back.</strong>
				While you were away your log paused for safety — one approval resumes it.
			{:else}
				One more approval switches on your receipts.
			{/if}
			{#if custody === 'passkey'}
				<span class="text-kumo-subtle">Two quick Touch ID prompts.</span>
			{/if}
		</span>
		<Button variant="primary" size="sm" disabled={busy} onclick={onapprove}>
			{#if busy}
				<LoaderCircle class="size-3.5 animate-spin" />
			{:else if custody === 'passkey'}
				<Fingerprint class="size-3.5" />
			{/if}
			{variant === 'resume' ? 'Resume' : 'Approve receipts'}
		</Button>
		{#if detail}
			<p class="w-full text-xs text-kumo-danger">{detail}</p>
		{/if}
	</div>
</div>
