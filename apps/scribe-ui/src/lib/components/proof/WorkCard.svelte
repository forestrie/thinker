<script lang="ts">
	import { envelopeClaims } from '$lib/cbor.ts';
	import type { WorkExportWire } from '$lib/scribe-api.ts';
	import type { WorkVerification } from '$lib/proofs.svelte.ts';
	import { b64ToBytes, shortHex } from '$lib/utils.ts';
	import Badge from '$lib/components/ui/Badge.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import { BadgeCheck, ShieldAlert, ShieldCheck, ShieldX, User, Bot } from '@lucide/svelte';

	let {
		work,
		verification,
		canVerify,
		onverify
	}: {
		work: WorkExportWire;
		verification?: WorkVerification;
		canVerify: boolean;
		onverify: () => void;
	} = $props();

	const tones = {
		submitted: 'neutral',
		queued: 'neutral',
		registered: 'info',
		sequenced: 'warning',
		receipted: 'success',
		error: 'danger'
	} as const;

	const claims = $derived(envelopeClaims(b64ToBytes(work.envelopeB64)));
	const input = $derived(typeof claims?.input === 'string' ? claims.input : '(unreadable)');
	const tampered = $derived(
		verification?.checks.some((c) => c.name === 'transcript-binding' && !c.ok) ?? false
	);
</script>

<div class="rounded-lg border border-kumo-hairline bg-kumo-base p-3">
	<div class="flex items-start justify-between gap-2">
		<p class="line-clamp-2 text-xs text-kumo-default" title={input}>“{input}”</p>
		{#if verification}
			{#if verification.ok}
				<Badge tone="success"><ShieldCheck class="size-3" /> verified</Badge>
			{:else if tampered}
				<Badge tone="danger"><ShieldAlert class="size-3" /> tampered</Badge>
			{:else}
				<Badge tone="danger"><ShieldX class="size-3" /> failed</Badge>
			{/if}
		{/if}
	</div>

	<div class="mt-2 flex flex-wrap items-center gap-1.5">
		<span class="font-mono text-[10px] text-kumo-subtle" title={work.workId}>
			work {shortHex(work.workId, 10, 0)}
		</span>
		<Badge tone={tones[work.state]} title={work.error ?? work.entryId ?? undefined}>
			<Bot class="size-3" /> agent · {work.state}
		</Badge>
		{#if work.userLeaf}
			<Badge
				tone={tones[work.userLeaf.state]}
				title={work.userLeaf.error ?? work.userLeaf.entryId ?? undefined}
			>
				<User class="size-3" /> user · {work.userLeaf.state}
			</Badge>
		{/if}
		{#if work.state === 'receipted'}
			<Button size="sm" variant="secondary" class="ml-auto" disabled={!canVerify} onclick={onverify}>
				<BadgeCheck class="size-3.5" />
				{verification ? 'Re-verify' : 'Verify offline'}
			</Button>
		{/if}
	</div>

	{#if work.state === 'error' && work.error}
		<p class="mt-2 rounded-md bg-kumo-danger-tint px-2.5 py-1.5 text-[11px] text-kumo-danger">
			{work.error}
		</p>
	{/if}
	{#if work.userLeaf?.state === 'error' && work.userLeaf.error}
		<p class="mt-2 rounded-md bg-kumo-warning-tint px-2.5 py-1.5 text-[11px] text-kumo-warning">
			user leaf: {work.userLeaf.error}
		</p>
	{/if}

	{#if verification}
		<ul class="mt-2 space-y-1 border-t border-kumo-hairline pt-2">
			{#each verification.checks as check (check.name)}
				<li class="flex items-start gap-1.5 text-[11px]">
					<span class={check.ok ? 'text-kumo-success' : 'text-kumo-danger'}>
						{check.ok ? '✓' : '✗'}
					</span>
					<span class="text-kumo-default">{check.name}</span>
					{#if check.detail}
						<span class="min-w-0 flex-1 truncate text-kumo-subtle" title={check.detail}>
							— {check.detail}
						</span>
					{/if}
				</li>
			{/each}
		</ul>
		{#if tampered}
			<p class="mt-2 rounded-md bg-kumo-danger-tint px-2.5 py-1.5 text-[11px] text-kumo-danger">
				The agent's memory of this turn no longer matches what was committed and receipted — the
				record has been altered after the fact. The log receipt proves which version was real.
			</p>
		{/if}
	{/if}
</div>
