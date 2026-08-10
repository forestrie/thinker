<script lang="ts">
	import { cn } from '$lib/utils.ts';
	import type { Snippet } from 'svelte';
	import type { HTMLButtonAttributes } from 'svelte/elements';

	type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';
	type Size = 'sm' | 'md';

	let {
		class: className,
		variant = 'secondary',
		size = 'md',
		children,
		...rest
	}: HTMLButtonAttributes & {
		variant?: Variant;
		size?: Size;
		children?: Snippet;
	} = $props();

	const variants: Record<Variant, string> = {
		primary: 'bg-kumo-brand text-white hover:bg-kumo-brand-hover border-transparent',
		secondary: 'bg-kumo-control text-kumo-strong border-kumo-line hover:bg-kumo-fill-hover',
		ghost: 'bg-transparent text-kumo-default border-transparent hover:bg-kumo-fill',
		danger: 'bg-kumo-danger text-white border-transparent hover:opacity-90'
	};
	const sizes: Record<Size, string> = {
		sm: 'h-7 px-2.5 text-xs',
		md: 'h-9 px-3.5 text-sm'
	};
</script>

<button
	data-kumo-component="button"
	class={cn(
		'inline-flex items-center justify-center gap-1.5 rounded-md border font-medium transition-colors',
		'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-kumo-focus',
		'disabled:pointer-events-none disabled:opacity-50',
		variants[variant],
		sizes[size],
		className
	)}
	{...rest}
>
	{@render children?.()}
</button>
