<script lang="ts">
	import { cn } from '$lib/utils.ts';
	import type { Snippet } from 'svelte';

	type Tone = 'neutral' | 'info' | 'warning' | 'success' | 'danger' | 'brand';

	let {
		class: className,
		tone = 'neutral',
		title,
		children
	}: {
		class?: string;
		tone?: Tone;
		title?: string;
		children?: Snippet;
	} = $props();

	const tones: Record<Tone, string> = {
		neutral: 'bg-kumo-tint text-kumo-subtle',
		info: 'bg-kumo-info-tint text-kumo-info',
		warning: 'bg-kumo-warning-tint text-kumo-warning',
		success: 'bg-kumo-success-tint text-kumo-success',
		danger: 'bg-kumo-danger-tint text-kumo-danger',
		brand: 'bg-kumo-brand text-white'
	};
</script>

<span
	{title}
	class={cn(
		'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium whitespace-nowrap',
		tones[tone],
		className
	)}
>
	{@render children?.()}
</span>
