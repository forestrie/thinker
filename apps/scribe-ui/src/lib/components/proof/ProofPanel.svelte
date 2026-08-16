<script lang="ts">
	import type { ProofPanel } from '$lib/proofs.svelte.ts';
	import { shortHex } from '$lib/utils.ts';
	import Card from '$lib/components/ui/Card.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import WorkCard from './WorkCard.svelte';
	import { Coins, KeyRound, LoaderCircle, RefreshCw, ShieldCheck, Stamp } from '@lucide/svelte';

	let { proofs }: { proofs: ProofPanel } = $props();

	const receiptedCount = $derived(proofs.works.filter((w) => w.state === 'receipted').length);
</script>

<div class="flex min-h-0 flex-col gap-3">
	<Card title="Forestrie proof">
		{#snippet actions()}
			{#if proofs.anyInFlight}
				<Badge tone="info"><LoaderCircle class="size-3 animate-spin" /> receipts pending</Badge>
			{/if}
			<Button
				size="sm"
				variant="ghost"
				disabled={proofs.refreshing}
				onclick={() => proofs.collectNow()}
			>
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
		{@const sealingReady = proofs.userLogId !== null}
		{@const activated = proofs.sealingDelegated}
		<Card title="Activate your log">
			<div class="space-y-2 p-4 text-xs">
				<p class="text-kumo-subtle">
					Your signed inputs land as their own leaves on a log <em>owned by your wallet</em>. Only
					your key can authorize the lane's sealer to checkpoint it — done here, in the browser; the
					agent never holds your key. Until then your leaves are held, unregistered.
				</p>
				<div class="flex items-center gap-2">
					<Button
						size="sm"
						variant={sealingReady && !activated ? 'primary' : 'secondary'}
						disabled={!sealingReady || proofs.delegation === 'working'}
						title={sealingReady
							? 'Sign a sealing delegation for your log with your wallet'
							: 'Your log is being created — a moment'}
						onclick={() => proofs.delegateUserSealing()}
					>
						{#if proofs.delegation === 'working'}
							<LoaderCircle class="size-3.5 animate-spin" />
						{:else}
							<Stamp class="size-3.5" />
						{/if}
						{activated ? 'Renew sealing lease' : 'Authorize sealing'}
					</Button>
					{#if activated}
						<Badge tone="success"><KeyRound class="size-3" /> delegated</Badge>
					{:else if sealingReady}
						<Badge tone="warning">activate before chatting</Badge>
					{/if}
				</div>
				{#if !sealingReady}
					<p class="text-kumo-subtle">
						Your log is being created (it needs a grant from the authority — up to a minute). You
						can chat meanwhile; your leaves are held until you authorize.
					</p>
				{:else if proofs.delegationDetail}
					<p class={proofs.delegation === 'error' ? 'text-kumo-danger' : 'text-kumo-subtle'}>
						{proofs.delegationDetail}
					</p>
				{/if}

				<!-- Prepaid turns (W4c/W4d): the purchased batch is the turn budget;
				     top-up repeats the W4b purchase — a new grant and log per batch. -->
				<div class="flex items-center gap-2 border-t border-kumo-line pt-2">
					<Coins class="size-3.5 text-kumo-subtle" />
					{#if proofs.prepaidTurns !== null}
						<span class={proofs.prepaidTurns === 0 ? 'text-kumo-danger' : 'text-kumo-default'}>
							{proofs.prepaidTurns} turn{proofs.prepaidTurns === 1 ? '' : 's'} remaining
						</span>
					{:else}
						<span class="text-kumo-subtle">turns unmetered (no purchased batch yet)</span>
					{/if}
					<Button
						size="sm"
						variant={proofs.prepaidTurns === 0 ? 'primary' : 'secondary'}
						disabled={proofs.payment === 'paying'}
						title="Buy another batch of attested turns (a fresh grant on a fresh log)"
						onclick={() => proofs.topUp()}
					>
						{#if proofs.payment === 'paying'}
							<LoaderCircle class="size-3.5 animate-spin" />
						{:else}
							<Coins class="size-3.5" />
						{/if}
						Top up
					</Button>
					{#if proofs.payment === 'paid'}
						<Badge tone="success">paid</Badge>
					{:else if proofs.payment === 'error'}
						<Badge tone="danger">payment failed</Badge>
					{/if}
				</div>
				{#if proofs.payment === 'error' && proofs.paymentDetail}
					<p class="text-kumo-danger">{proofs.paymentDetail}</p>
				{/if}
			</div>
		</Card>

		<Card title="Payment policy — provable offline">
			<div class="space-y-2 p-4 text-xs">
				<p class="text-kumo-subtle">
					Your grant's <em>parent</em> — the user-authority log — carries the payment requirement in its
					own receipted log entry. Verify it here, in the browser, against the forest root key: the price
					gate is a fact of the log, not a claim of the operator.
				</p>
				<div class="flex items-center gap-2">
					<Button
						size="sm"
						variant="secondary"
						disabled={proofs.policy === 'verifying'}
						onclick={() => proofs.verifyParentPolicy()}
					>
						{#if proofs.policy === 'verifying'}
							<LoaderCircle class="size-3.5 animate-spin" />
						{:else}
							<ShieldCheck class="size-3.5" />
						{/if}
						Verify policy
					</Button>
					{#if proofs.policyResult}
						{#if proofs.policyResult.ok && proofs.policyResult.requiresChildPayment}
							<Badge tone="success">requiresChildPayment · receipt verified</Badge>
						{:else if proofs.policyResult.ok}
							<Badge tone="warning">no payment policy on parent</Badge>
						{:else}
							<Badge tone="danger">verification failed</Badge>
						{/if}
					{/if}
				</div>
				{#if proofs.policyResult}
					<ul class="space-y-1 font-mono text-[11px]">
						{#each proofs.policyResult.checks as check (check.name)}
							<li class={check.ok ? 'text-kumo-subtle' : 'text-kumo-danger'}>
								{check.ok ? '✓' : '✗'}
								{check.name}{check.detail ? ` — ${check.detail}` : ''}
							</li>
						{/each}
					</ul>
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
					No committed turns yet. Every message you send becomes a signed, registered, independently
					verifiable work unit — watch them appear here.
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
