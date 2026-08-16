<script lang="ts">
	import type { ProofPanel } from '$lib/proofs.svelte.ts';
	import { shortHex } from '$lib/utils.ts';
	import Card from '$lib/components/ui/Card.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import WorkCard from './WorkCard.svelte';
	import {
		Coins,
		Download,
		Gauge,
		KeyRound,
		LoaderCircle,
		RefreshCw,
		ShieldCheck,
		Stamp,
		Trash2
	} from '@lucide/svelte';

	let { proofs }: { proofs: ProofPanel } = $props();

	const receiptedCount = $derived(proofs.works.filter((w) => w.state === 'receipted').length);

	// Deleting the local openings cannot be undone and cannot be re-fetched —
	// the service never had them. Confirm, and say exactly what survives.
	function deleteLocal() {
		if (
			confirm(
				'Delete this browser’s copy of your messages?\n\nThis removes only local text. The log entries your turns produced are permanent by design and stay verifiable — but without your copy nobody, including you, can show what the committed hashes stand for. Download the proof bundle first if you want to keep that ability.'
			)
		)
			proofs.deleteLocalMessages();
	}
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

				<!-- Daily demo-turn cap: the global cap is the real spend bound, so
				     surface it plainly — a silent cap reads as breakage. -->
				{#if proofs.demoTurns}
					<div class="flex items-center gap-2 border-t border-kumo-line pt-2">
						<Gauge class="size-3.5 text-kumo-subtle" />
						<span
							class={proofs.demoTurns.global.used >= proofs.demoTurns.global.cap
								? 'text-kumo-danger'
								: 'text-kumo-default'}
						>
							turn {proofs.demoTurns.global.used} of {proofs.demoTurns.global.cap} allowed daily demo
							turns
						</span>
					</div>
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

	<!-- D4/D5: redaction obliges giving the user their own copy, and saying
	     plainly what is kept where. -->
	<Card title="Your copy">
		<div class="space-y-2 p-4 text-xs">
			<p class="text-kumo-subtle">
				The log holds <em>commitments</em>, not words: your wallet signs
				<span class="font-mono">H(nonce ‖ message)</span>, and the agent signs a salted hash of its
				reply. Your message text never reaches the log — this browser keeps the only copy that can
				open those hashes, and the agent's own instance forgets its text after about a week. Please
				don't put personal information in a demo.
			</p>
			<div class="flex flex-wrap items-center gap-2">
				<Button
					size="sm"
					variant="secondary"
					disabled={proofs.export === null}
					title="Download everything an auditor needs, including your openings"
					onclick={() => proofs.downloadBundle()}
				>
					<Download class="size-3.5" />
					Download proof bundle
				</Button>
				<Button
					size="sm"
					variant="ghost"
					disabled={proofs.keptCount === 0}
					title="Remove this browser's copy of your message text"
					onclick={deleteLocal}
				>
					<Trash2 class="size-3.5" />
					Delete my messages
				</Button>
				<span class="text-kumo-subtle">
					{proofs.keptCount} kept locally
				</span>
			</div>
			<p class="text-kumo-subtle">
				The bundle verifies offline, forever, with this service switched off:
				<span class="font-mono text-[10px]">verify-receipts.mjs --export &lt;file&gt;</span>.
				Deleting local text does not and cannot delete log entries — those are permanent by design.
			</p>
		</div>
	</Card>

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
					keptInput={proofs.keptInput(work.workId)}
					verification={proofs.verifications[work.workId]}
					canVerify={!proofs.verifying && proofs.identity !== null}
					onverify={() => proofs.verify(work)}
				/>
			{/each}
		</div>
	</Card>
</div>
