<script lang="ts">
	import type { DemoWallet } from '$lib/wallet.svelte.ts';
	import { shortHex } from '$lib/utils.ts';
	import { usdcBalance, paymentFromChallenge, BASE_SEPOLIA_USDC } from '$lib/usdc.ts';
	import Button from '$lib/components/ui/Button.svelte';
	import { Check, Copy, Wallet } from '@lucide/svelte';

	let {
		wallet,
		grantChallenge = null
	}: {
		wallet: DemoWallet;
		/** A parked x402 challenge names the exact asset + batch price. */
		grantChallenge?: string | null;
	} = $props();

	let open = $state(false);
	let copied = $state(false);
	let balance = $state<number | null>(null);
	let balanceError = $state<string | null>(null);

	const payment = $derived(paymentFromChallenge(grantChallenge));

	// Funding details are depth-on-demand: the balance polls only while the
	// popover is open, instead of the old always-on header poll.
	$effect(() => {
		if (!open) return;
		let cancelled = false;
		const load = async () => {
			try {
				const b = await usdcBalance(wallet.address, payment?.asset ?? BASE_SEPOLIA_USDC);
				if (!cancelled) {
					balance = b;
					balanceError = null;
				}
			} catch (err) {
				if (!cancelled) balanceError = String(err);
			}
		};
		void load();
		const timer = setInterval(() => void load(), 15_000);
		return () => {
			cancelled = true;
			clearInterval(timer);
		};
	});

	function onkeydown(e: KeyboardEvent) {
		if (open && e.key === 'Escape') open = false;
	}

	async function copyAddress() {
		try {
			await navigator.clipboard.writeText(wallet.address);
			copied = true;
			setTimeout(() => (copied = false), 1500);
		} catch {
			// Clipboard blocked (insecure context / permissions) — the full
			// address stays selectable in the popover.
		}
	}
</script>

<svelte:window {onkeydown} />

<div class="relative">
	<button
		type="button"
		onclick={() => (open = !open)}
		title="Wallet — balance and funding"
		aria-expanded={open}
		class="flex items-center gap-1.5 rounded-md border border-kumo-line bg-kumo-recessed px-2 py-1 font-mono text-[11px] text-kumo-default hover:bg-kumo-elevated"
	>
		<Wallet class="size-3 text-kumo-subtle" />
		{shortHex(wallet.address, 6, 4)}
	</button>
	{#if open}
		<div class="fixed inset-0 z-30" onclick={() => (open = false)} aria-hidden="true"></div>
		<div
			class="absolute top-full right-0 z-40 mt-1.5 flex w-72 flex-col gap-2.5 rounded-lg border border-kumo-line bg-kumo-elevated p-3 text-xs shadow-lg"
		>
			<div class="flex items-center justify-between gap-2">
				<span class="text-kumo-subtle">Balance</span>
				<span class={balance === 0 ? 'font-medium text-kumo-warning' : 'text-kumo-default'}>
					{balanceError ? 'unavailable' : balance === null ? '…' : balance.toFixed(2)} USDC
				</span>
			</div>
			<p class="text-kumo-subtle">
				USDC on Base Sepolia — test money. Fund this address to add turns{payment
					? ` ($${payment.usdc.toFixed(2)} per batch)`
					: ''}.
			</p>
			<p class="rounded-md bg-kumo-recessed px-2 py-1.5 font-mono text-[10px] break-all select-all">
				{wallet.address}
			</p>
			<Button size="sm" variant="secondary" onclick={copyAddress}>
				{#if copied}
					<Check class="size-3 text-kumo-success" />
				{:else}
					<Copy class="size-3" />
				{/if}
				Copy address
			</Button>
		</div>
	{/if}
</div>
