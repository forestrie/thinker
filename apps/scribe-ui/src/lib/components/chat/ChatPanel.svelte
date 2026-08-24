<script lang="ts">
	import { tick } from 'svelte';
	import type { ScribeChat } from '$lib/chat.svelte.ts';
	import Card from '$lib/components/ui/Card.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import MessageBubble from './MessageBubble.svelte';
	import Composer from './Composer.svelte';
	import { LoaderCircle } from '@lucide/svelte';

	let {
		chat,
		lockNotice = null
	}: {
		chat: ScribeChat;
		/**
		 * Non-null locks the composer with this explanation (4.3): before a
		 * log root is registered, turn admission has nothing to verify a
		 * signed envelope against, so sending would only fail server-side.
		 */
		lockNotice?: string | null;
	} = $props();

	let scroller = $state<HTMLDivElement | null>(null);

	const connectionTone = $derived(
		chat.connection === 'connected' ? 'success' : chat.connection === 'error' ? 'danger' : 'warning'
	);

	// Streaming messages surface through streamTick (the map itself is not
	// reactive state); reading the tick here re-derives on every chunk.
	const streaming = $derived.by(() => {
		void chat.streamTick;
		return chat.streamingMessages;
	});

	$effect(() => {
		// Follow the tail as messages append or stream.
		void chat.messages.length;
		void chat.streamTick;
		void tick().then(() => {
			scroller?.scrollTo({ top: scroller.scrollHeight });
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

<Card class="flex min-h-0 flex-col" title="Conversation">
	{#snippet actions()}
		<Badge tone={connectionTone}>
			<span class="size-1.5 rounded-full bg-current"></span>
			{chat.connection}
		</Badge>
		{#if chat.recovering}
			<Badge tone="warning"><LoaderCircle class="size-3 animate-spin" /> recovering</Badge>
		{/if}
	{/snippet}

	<div bind:this={scroller} class="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-4">
		{#if chat.messages.length === 0 && streaming.length === 0}
			<div class="m-auto max-w-sm text-center text-sm text-kumo-subtle">
				<p class="font-medium text-kumo-default">This conversation is tamper-evident.</p>
				<p class="mt-1.5">
					You sign your input, the Scribe signs its own choices and outputs, and only hashes reach
					the public transparency log — the transcript itself never leaves this session.
				</p>
			</div>
		{/if}
		{#each chat.messages as message (message.id)}
			<MessageBubble {message} />
		{/each}
		{#each streaming as message (message.id)}
			<MessageBubble {message} />
		{/each}
		{#if chat.awaiting && streaming.length === 0}
			<div class="flex items-center gap-2 text-xs text-kumo-subtle">
				<LoaderCircle class="size-3.5 animate-spin" />
				turn admitted — waiting for the Scribe…
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

	{#if lockNotice}
		<p class="border-t border-kumo-line px-4 py-2 text-xs text-kumo-subtle">{lockNotice}</p>
	{/if}
	<Composer
		disabled={chat.connection !== 'connected' || chat.awaiting || lockNotice !== null}
		{onsend}
	/>
</Card>
