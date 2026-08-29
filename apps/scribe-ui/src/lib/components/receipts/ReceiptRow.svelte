<script lang="ts">
	import type { WorkExportWire } from '$lib/scribe-api.ts';
	import type { WorkVerification } from '$lib/proofs.svelte.ts';
	import { agentTurnStatus, captionLabel, userTurnStatus } from '$lib/receipt-status.ts';
	import WorkCard from './WorkCard.svelte';
	import { Check, ChevronRight } from '@lucide/svelte';

	let {
		work,
		n,
		keptInput,
		verification,
		canVerify,
		onverify
	}: {
		work: WorkExportWire;
		n: number | null;
		keptInput: string | null;
		verification?: WorkVerification;
		canVerify: boolean;
		onverify: () => void;
	} = $props();

	const userLabel = $derived(captionLabel(userTurnStatus(work), verification));
	const agentLabel = $derived(captionLabel(agentTurnStatus(work), verification));
</script>

{#snippet statusLine(who: string, label: string)}
	<div class="flex items-center gap-2.5 py-0.5">
		{#if label === 'verified' || label === 'receipted'}
			<Check class="size-3.5 shrink-0 text-kumo-success" />
		{:else if label === 'check failed' || label === 'failed'}
			<span class="size-3 shrink-0 rounded-full border-[1.5px] border-kumo-danger"></span>
		{:else}
			<span class="size-3 shrink-0 rounded-full border-[1.5px] border-kumo-interact"></span>
		{/if}
		<span class="flex-1 text-[13px] text-kumo-default">Turn {n ?? '?'} — {who}</span>
		<span
			class="text-[11px] {label === 'check failed' || label === 'failed'
				? 'text-kumo-danger'
				: 'text-kumo-subtle'}">{label}</span
		>
	</div>
{/snippet}

<details class="group rounded-lg hover:bg-kumo-recessed">
	<summary
		class="flex cursor-pointer list-none items-start gap-1 px-2 py-1.5 [&::-webkit-details-marker]:hidden"
	>
		<ChevronRight
			class="mt-1.5 size-3 shrink-0 text-kumo-subtle transition-transform group-open:rotate-90"
		/>
		<div class="min-w-0 flex-1">
			{@render statusLine('you', userLabel)}
			{@render statusLine('the Scribe', agentLabel)}
		</div>
	</summary>
	<div class="px-2 pb-2">
		<WorkCard {work} {keptInput} {verification} {canVerify} {onverify} />
	</div>
</details>
