<script lang="ts">
	import { onMount } from 'svelte';
	import { DemoWallet } from '$lib/wallet.svelte.ts';
	import { ScribeSession } from '$lib/session.svelte.ts';
	import { ScribeChat } from '$lib/chat.svelte.ts';
	import { ProofPanel as ProofPanelState } from '$lib/proofs.svelte.ts';
	import ChatPanel from '$lib/components/chat/ChatPanel.svelte';
	import ProofPanel from '$lib/components/proof/ProofPanel.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import { shortHex } from '$lib/utils.ts';
	import { Feather, Wallet, RotateCcw } from '@lucide/svelte';

	const wallet = new DemoWallet();
	const session = new ScribeSession(wallet);
	const chat = new ScribeChat(session, wallet);
	const proofs = new ProofPanelState(session, wallet);

	// A settled turn means new commitments are in flight — pull the export.
	chat.onTurnSettled = () => void proofs.refresh();

	onMount(() => {
		void (async () => {
			try {
				await session.ensure();
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
		wallet.reset();
		session.clear();
		location.reload();
	}
</script>

<div class="flex h-dvh flex-col bg-kumo-recessed">
	<header
		class="flex items-center justify-between gap-3 border-b border-kumo-line bg-kumo-elevated px-4 py-2.5"
	>
		<div class="flex items-center gap-2.5">
			<span class="flex size-8 items-center justify-center rounded-lg bg-kumo-brand text-white">
				<Feather class="size-4.5" />
			</span>
			<div>
				<h1 class="text-sm leading-tight font-semibold text-kumo-strong">The Scribe</h1>
				<p class="text-[11px] leading-tight text-kumo-subtle">
					an attested conversation, receipted on a Forestrie transparency log
				</p>
			</div>
		</div>
		<div class="flex items-center gap-2">
			{#if session.error}
				<Badge tone="danger" title={session.error}>auth failed</Badge>
			{/if}
			<Badge tone="neutral" title={wallet.address}>
				<Wallet class="size-3" />
				{shortHex(wallet.address, 6, 4)}
			</Badge>
			<Button size="sm" variant="ghost" title="Forget this identity and start fresh" onclick={resetIdentity}>
				<RotateCcw class="size-3.5" />
			</Button>
		</div>
	</header>

	<main
		class="grid min-h-0 flex-1 grid-cols-1 gap-3 overflow-y-auto p-3 lg:grid-cols-[minmax(0,1fr)_420px] lg:overflow-hidden"
	>
		<ChatPanel {chat} />
		<ProofPanel {proofs} />
	</main>
</div>
