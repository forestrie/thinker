<script lang="ts">
	import { cn } from '$lib/utils.ts';
	import type { Snippet } from 'svelte';
	import type { HTMLAttributes } from 'svelte/elements';

	let {
		class: className,
		title,
		actions,
		children,
		...rest
	}: HTMLAttributes<HTMLDivElement> & {
		title?: string;
		actions?: Snippet;
		children?: Snippet;
	} = $props();
</script>

<div
	class={cn('rounded-lg border border-kumo-line bg-kumo-elevated shadow-sm', className)}
	{...rest}
>
	{#if title || actions}
		<div class="flex items-center justify-between gap-2 border-b border-kumo-hairline px-4 py-2.5">
			{#if title}<h2 class="text-sm font-semibold text-kumo-strong">{title}</h2>{/if}
			{#if actions}<div class="flex items-center gap-2">{@render actions()}</div>{/if}
		</div>
	{/if}
	{@render children?.()}
</div>
