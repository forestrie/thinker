<script lang="ts">
	// The Scribe's mark: a clay tablet with cuneiform wedges — the original
	// tamper-evident record. Hand-drawn in the lucide idiom (24px grid,
	// stroke-2, round caps) since lucide has no cuneiform tablet.
	let { class: className }: { class?: string } = $props();
</script>

<svg
	viewBox="0 0 24 24"
	fill="none"
	stroke="currentColor"
	stroke-width="2"
	stroke-linecap="round"
	stroke-linejoin="round"
	class={className}
	aria-hidden="true"
>
	<rect x="5" y="3" width="14" height="18" rx="2.5" />
	<g fill="currentColor" stroke="none">
		<path d="M8.5 6.9 11 7.9 8.5 8.9Z" />
		<path d="M13 6.9 15.5 7.9 13 8.9Z" />
		<path d="M8.5 11 11 12 8.5 13Z" />
		<path d="M13 11 15.5 12 13 13Z" />
		<path d="M8.5 15.1 11 16.1 8.5 17.1Z" />
	</g>
</svg>
