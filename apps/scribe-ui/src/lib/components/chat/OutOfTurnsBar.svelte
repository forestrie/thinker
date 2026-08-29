<script lang="ts">
	import Button from '$lib/components/ui/Button.svelte';
	import { Coins, LoaderCircle } from '@lucide/svelte';

	let {
		busy,
		detail = null,
		note = null,
		onadd
	}: {
		busy: boolean;
		/** Payment failure detail — the balance hint lives behind the wallet chip. */
		detail?: string | null;
		/** In-progress reassurance (a pending purchase resuming) — quiet, not red. */
		note?: string | null;
		onadd: () => void;
	} = $props();
</script>

<div class="border-t border-kumo-hairline p-3">
	<div
		class="flex flex-wrap items-center gap-3 rounded-xl border border-kumo-warning/40 bg-kumo-warning-tint py-2.5 pr-2.5 pl-4"
	>
		<Coins class="size-4 shrink-0 text-kumo-warning" />
		<span class="min-w-0 flex-1 text-[13px] leading-snug text-kumo-default">
			<strong class="font-semibold text-kumo-strong">You're out of turns.</strong>
			Your log and receipts are untouched.
		</span>
		<Button variant="primary" size="sm" disabled={busy} onclick={onadd}>
			{#if busy}
				<LoaderCircle class="size-3.5 animate-spin" />
			{/if}
			Add more turns
		</Button>
		{#if detail}
			<p class="w-full text-xs text-kumo-danger">{detail}</p>
		{:else if note}
			<p class="w-full text-xs text-kumo-subtle">{note}</p>
		{/if}
	</div>
</div>
