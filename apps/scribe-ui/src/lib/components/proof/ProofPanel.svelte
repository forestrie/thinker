<script lang="ts">
	import type { ProofPanel } from '$lib/proofs.svelte.ts';
	import { shortHex } from '$lib/utils.ts';
	import Card from '$lib/components/ui/Card.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import WorkCard from './WorkCard.svelte';
	import { KeyRound, LoaderCircle, RefreshCw, ShieldCheck, Stamp } from '@lucide/svelte';

	let { proofs }: { proofs: ProofPanel } = $props();

	const receiptedCount = $derived(proofs.works.filter((w) => w.state === 'receipted').length);
</script>

<div class="flex min-h-0 flex-col gap-3">
	<Card title="Forestrie proof">
		{#snippet actions()}
			{#if proofs.anyInFlight}
				<Badge tone="info"><LoaderCircle class="size-3 animate-spin" /> receipts pending</Badge>
			{/if}
			<Button size="sm" variant="ghost" disabled={proofs.refreshing} onclick={() => proofs.collectNow()}>
				<RefreshCw class="size-3.5 {proofs.refreshing ? 'animate-spin' : ''}" />
				Refresh
			</Button>
		{/snippet}

		<div class="space-y-2 p-4 text-xs">
			{#if proofs.identity}
				<div class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-[11px]">
					<span class="text-kumo-subtle">agent kid</span>
					<span class="truncate text-kumo-default" title={proofs.identity.kid}>
						{shortHex(proofs.identity.kid, 16, 6)}
					</span>
					<span class="text-kumo-subtle">custody</span>
					<span class="text-kumo-default">
						{proofs.identity.keyProvider}
						· epoch {proofs.identity.epoch}
						· {proofs.identity.attestationMode} attestation
					</span>
					{#if proofs.export?.forestrie.agentLogId}
						<span class="text-kumo-subtle">agent log</span>
						<span class="truncate text-kumo-default">{proofs.export.forestrie.agentLogId}</span>
					{/if}
					{#if proofs.export?.forestrie.userLogId}
						<span class="text-kumo-subtle">user log</span>
						<span class="truncate text-kumo-default">{proofs.export.forestrie.userLogId}</span>
					{/if}
				</div>
			{:else}
				<p class="text-kumo-subtle">
					No agent identity yet — send a message and the per-user Scribe instance (and its signing
					key) comes into being.
				</p>
			{/if}
			{#if proofs.error}
				<p class="rounded-md bg-kumo-danger-tint px-2.5 py-1.5 text-kumo-danger">{proofs.error}</p>
			{/if}
		</div>
	</Card>

	{#if proofs.export?.attestationMode === 'separate'}
		<Card title="Your log's sealing">
			<div class="space-y-2 p-4 text-xs">
				<p class="text-kumo-subtle">
					Your signed inputs land as their own leaves on a log <em>owned by your wallet</em>. Only
					your key can authorize the lane's sealer to checkpoint it — done here, in the browser;
					the agent never holds your key.
				</p>
				<div class="flex items-center gap-2">
					<Button
						size="sm"
						variant="primary"
						disabled={proofs.delegation === 'working'}
						onclick={() => proofs.delegateUserSealing()}
					>
						{#if proofs.delegation === 'working'}
							<LoaderCircle class="size-3.5 animate-spin" />
						{:else}
							<Stamp class="size-3.5" />
						{/if}
						Authorize sealing
					</Button>
					{#if proofs.delegation === 'done'}
						<Badge tone="success"><KeyRound class="size-3" /> delegated</Badge>
					{/if}
				</div>
				{#if proofs.delegationDetail}
					<p class={proofs.delegation === 'error' ? 'text-kumo-danger' : 'text-kumo-subtle'}>
						{proofs.delegationDetail}
					</p>
				{/if}
			</div>
		</Card>
	{/if}

	<Card title="Attested turns" class="flex min-h-0 flex-1 flex-col">
		{#snippet actions()}
			{#if receiptedCount > 0}
				<Button
					size="sm"
					variant="secondary"
					disabled={proofs.verifying}
					onclick={() => proofs.verifyAll()}
				>
					<ShieldCheck class="size-3.5" />
					Verify all
				</Button>
			{/if}
		{/snippet}
		<div class="min-h-0 flex-1 space-y-2 overflow-y-auto p-3">
			{#if proofs.works.length === 0}
				<p class="p-2 text-center text-xs text-kumo-subtle">
					No committed turns yet. Every message you send becomes a signed, registered,
					independently verifiable work unit — watch them appear here.
				</p>
			{/if}
			{#each [...proofs.works].reverse() as work (work.workId)}
				<WorkCard
					{work}
					verification={proofs.verifications[work.workId]}
					canVerify={!proofs.verifying && proofs.identity !== null}
					onverify={() => proofs.verify(work)}
				/>
			{/each}
		</div>
	</Card>
</div>
