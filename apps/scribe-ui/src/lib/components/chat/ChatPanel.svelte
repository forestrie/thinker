<script lang="ts">
	import { tick } from 'svelte';
	import type { ScribeChat } from '$lib/chat.svelte.ts';
	import MessageBubble from './MessageBubble.svelte';
	import Composer from './Composer.svelte';
	import OutOfTurnsBar from './OutOfTurnsBar.svelte';
	import { LoaderCircle } from '@lucide/svelte';

	let {
		chat,
		captions,
		outOfTurns = false,
		addBusy = false,
		addDetail = null,
		onaddturns
	}: {
		chat: ScribeChat;
		/** messageId → ambient receipt caption (see +page). */
		captions: Map<string, { label: string; bad: boolean }>;
		outOfTurns?: boolean;
		addBusy?: boolean;
		addDetail?: string | null;
		onaddturns: () => void;
	} = $props();

	let scroller = $state<HTMLDivElement | null>(null);

	// Streaming messages surface through streamTick (the map itself is not
	// reactive state); reading the tick here re-derives on every chunk.
	const streaming = $derived.by(() => {
		void chat.streamTick;
		return chat.streamingMessages;
	});

	$effect(() => {
		// Follow the tail as messages append, stream, or grow a caption line
		// (receipts land after the turn — without the captions dependency the
		// last caption can sit under the fold). Only when the user is already
		// at the tail: `captions` is rebuilt by every receipt poll, and
		// unconditionally scrolling here would yank a reader who scrolled up
		// back to the bottom every few seconds.
		void chat.messages.length;
		void chat.streamTick;
		void captions;
		const el = scroller;
		if (!el) return;
		const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 120;
		void tick().then(() => {
			if (nearBottom) el.scrollTo({ top: el.scrollHeight });
		});
	});

	async function onsend(input: string) {
		try {
			await chat.sendTurn(input);
		} catch {
			// surfaced via chat.turnError
		}
	}
</script>

<div class="flex min-h-0 flex-1 flex-col">
	<div bind:this={scroller} class="min-h-0 flex-1 overflow-y-auto">
		<div class="mx-auto flex w-full max-w-3xl flex-col gap-4 p-4">
			{#if chat.messages.length === 0 && streaming.length === 0}
				<div class="m-auto max-w-sm py-16 text-center text-sm text-kumo-subtle">
					<p>Say hello — every turn is signed, both ways.</p>
				</div>
			{/if}
			{#each chat.messages as message (message.id)}
				<MessageBubble {message} caption={captions.get(message.id) ?? null} />
			{/each}
			{#each streaming as message (message.id)}
				<MessageBubble {message} />
			{/each}
			{#if chat.awaiting && streaming.length === 0}
				<div class="flex items-center gap-2 text-xs text-kumo-subtle">
					<LoaderCircle class="size-3.5 animate-spin" />
					waiting for the Scribe…
				</div>
			{/if}
			{#if chat.recovering}
				<div class="flex items-center gap-2 text-xs text-kumo-subtle">
					<LoaderCircle class="size-3.5 animate-spin" />
					recovering the conversation…
				</div>
			{/if}
			{#if chat.turnError}
				<p class="rounded-md bg-kumo-danger-tint px-3 py-2 text-xs text-kumo-danger">
					{chat.turnError}
				</p>
			{/if}
			{#if chat.connectionDetail}
				<p class="rounded-md bg-kumo-danger-tint px-3 py-2 text-xs text-kumo-danger">
					connection: {chat.connectionDetail}
				</p>
			{/if}
		</div>
	</div>

	<div class="mx-auto w-full max-w-3xl">
		{#if outOfTurns}
			<OutOfTurnsBar busy={addBusy} detail={addDetail} onadd={onaddturns} />
		{:else}
			<Composer disabled={chat.connection !== 'connected' || chat.awaiting} {onsend} />
		{/if}
	</div>
</div>
