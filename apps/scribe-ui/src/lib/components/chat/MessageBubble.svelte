<script lang="ts">
	import { cn } from '$lib/utils.ts';
	import type { ChatMessage } from '$lib/chat.svelte.ts';
	import { Wrench, CircleAlert } from '@lucide/svelte';

	let { message }: { message: ChatMessage } = $props();

	const isUser = $derived(message.role === 'user');
</script>

<div class={cn('flex', isUser ? 'justify-end' : 'justify-start')}>
	<div
		class={cn(
			'max-w-[85%] rounded-2xl px-3.5 py-2 text-sm leading-relaxed',
			isUser
				? 'rounded-br-md bg-kumo-brand text-white'
				: 'rounded-bl-md border border-kumo-hairline bg-kumo-elevated text-kumo-default'
		)}
	>
		{#each message.parts as part, i (i)}
			{#if part.type === 'text'}
				<p class="whitespace-pre-wrap">{part.text}</p>
			{:else if part.type === 'reasoning' && part.text}
				<p class="text-xs text-kumo-subtle italic whitespace-pre-wrap">{part.text}</p>
			{:else if part.type === 'tool'}
				<span
					class={cn(
						'my-1 inline-flex items-center gap-1.5 rounded-md border border-kumo-hairline px-2 py-1 text-xs',
						part.state === 'output-error' ? 'text-kumo-danger' : 'text-kumo-subtle'
					)}
				>
					{#if part.state === 'output-error'}<CircleAlert class="size-3.5" />{:else}<Wrench
							class="size-3.5"
						/>{/if}
					{part.toolName ?? 'tool'}
					{#if part.state === 'input-streaming'}…{/if}
					{#if part.state === 'output-error'}&nbsp;— {part.errorText}{/if}
				</span>
			{/if}
		{/each}
		{#if message.streaming}
			<span class="ml-0.5 inline-block h-3.5 w-1.5 animate-pulse rounded-sm bg-current opacity-60"
			></span>
		{/if}
	</div>
</div>
