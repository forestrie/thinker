<script lang="ts">
	import Button from '$lib/components/ui/Button.svelte';
	import { SendHorizontal, PenLine } from '@lucide/svelte';

	let {
		disabled = false,
		onsend
	}: {
		disabled?: boolean;
		onsend: (input: string) => void;
	} = $props();

	let input = $state('');

	function submit() {
		const text = input.trim();
		if (!text || disabled) return;
		input = '';
		onsend(text);
	}

	function onkeydown(event: KeyboardEvent) {
		if (event.key === 'Enter' && !event.shiftKey) {
			event.preventDefault();
			submit();
		}
	}
</script>

<div class="border-t border-kumo-hairline p-3">
	<div
		class="flex items-end gap-2 rounded-xl border border-kumo-line bg-kumo-base px-3 py-2 focus-within:border-kumo-focus"
	>
		<textarea
			bind:value={input}
			{onkeydown}
			{disabled}
			rows="1"
			placeholder="Say something — your words are signed and committed…"
			class="max-h-40 min-h-[1.75rem] flex-1 resize-none bg-transparent text-sm text-kumo-default outline-none placeholder:text-kumo-placeholder"
		></textarea>
		<Button variant="primary" size="sm" disabled={disabled || !input.trim()} onclick={submit}>
			<SendHorizontal class="size-3.5" />
			Send
		</Button>
	</div>
	<p class="mt-1.5 flex items-center gap-1 text-[11px] text-kumo-subtle">
		<PenLine class="size-3" />
		Each turn is wallet-signed (KS256 COSE) and admitted as an attested work unit.
	</p>
</div>
