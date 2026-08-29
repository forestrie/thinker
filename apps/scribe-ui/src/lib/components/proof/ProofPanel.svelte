<script lang="ts">
	import type { ProofPanel } from '$lib/proofs.svelte.ts';
	import { leasePhase, leaseRemainingLabel } from '$lib/lease.ts';
	import { endorsementPhase, endorsementRemainingLabel } from '$lib/endorsement.ts';
	import { shortHex } from '$lib/utils.ts';
	import Card from '$lib/components/ui/Card.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import WorkCard from './WorkCard.svelte';
	import {
		Clock,
		Coins,
		Download,
		Fingerprint,
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

	// The lease countdown re-renders on a slow tick — it displays minutes, so
	// 30s keeps it honest without busywork.
	let now = $state(Date.now());
	$effect(() => {
		const timer = setInterval(() => (now = Date.now()), 30_000);
		return () => clearInterval(timer);
	});

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
		{@const lease = activated ? leasePhase(proofs.sealingLeaseExpiresAt, now) : 'unknown'}
		{@const leaseUrgent = lease === 'expiring' || lease === 'expired'}
		{@const endorsement =
			proofs.custody === 'passkey' ? endorsementPhase(proofs.endorsementExpiresAt, now) : 'unknown'}
		<Card title="Activate your log">
			<div class="space-y-2 p-4 text-xs">
				{#if proofs.onboarding === 'needs-activation'}
					<!-- 4.3: the custody choice. Nothing is pinned and no grant is
					     requested until one of these two explicit gestures. -->
					<p class="text-kumo-subtle">
						Your inputs land as their own leaves on a log <em>owned by a key of your choosing</em>.
						A <strong>passkey</strong> (Touch&nbsp;ID / your platform authenticator) keeps that root key
						in hardware: it signs only the big ceremonies, each one a prompt you approve, and it can never
						be exfiltrated by this page. Without one, the root is a software key this browser holds.
					</p>
					<div class="flex flex-wrap items-center gap-2">
						<Button
							size="sm"
							variant="primary"
							disabled={proofs.activating}
							title="Create a passkey as your log's root key, then endorse this browser's signing key with it — two prompts"
							onclick={() => proofs.activateWithPasskey()}
						>
							{#if proofs.activating}
								<LoaderCircle class="size-3.5 animate-spin" />
							{:else}
								<Fingerprint class="size-3.5" />
							{/if}
							Create a passkey & activate
						</Button>
						<Button
							size="sm"
							variant="ghost"
							disabled={proofs.activating}
							title="Root the log in this browser's software key instead (one-way: switching to a passkey later means resetting your identity)"
							onclick={() => proofs.continueWithoutPasskey()}
						>
							Continue without a passkey
						</Button>
					</div>
					<p class="text-kumo-subtle">
						Two prompts now — create the passkey, then endorse this browser's per-turn signing key
						for a week (the endorsement rides inside every leaf you sign; one prompt renews it).
						Continuing without one is one-way: upgrading to a passkey later means resetting your
						identity and starting a fresh log.
					</p>
					{#if proofs.onboardingDetail}
						<p class="text-kumo-danger">{proofs.onboardingDetail}</p>
					{/if}
				{:else if proofs.onboarding === 'reset-required'}
					<p class="text-kumo-danger">
						{proofs.onboardingDetail ?? 'this log is rooted by a key this browser no longer holds'}
					</p>
					<p class="text-kumo-subtle">
						Use the reset button in the header to forget this identity and start a fresh log.
					</p>
				{:else}
					<p class="text-kumo-subtle">
						Your signed inputs land as their own leaves on a log <em
							>owned by {proofs.custody === 'passkey'
								? 'your passkey — a key that never leaves your authenticator'
								: 'a key only this browser holds'}</em
						>. Only that key can authorize the lane's sealer to checkpoint it — done here, in the
						browser; the agent never holds your key. Until then your leaves are held, unregistered.
					</p>
					<div class="flex items-center gap-2">
						<Button
							size="sm"
							variant={sealingReady && (!activated || leaseUrgent) ? 'primary' : 'secondary'}
							disabled={!sealingReady || proofs.delegation === 'working'}
							title={!sealingReady
								? 'Your log is being created — a moment'
								: proofs.custody === 'passkey'
									? 'Sign a sealing delegation with your passkey — two prompts, one per artifact'
									: "Sign a sealing delegation for your log with your browser's root key"}
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
					{#if !sealingReady && proofs.userGrantError}
						<!-- Do NOT fall through to "being created" here: nothing is in
						     flight, and waiting will not help. The DO retries on a
						     cooldown, so say what broke and that it is coming back
						     (plan-2608-11 W4). -->
						<p class="text-kumo-danger">
							Your log could not be created: {proofs.userGrantError}
						</p>
						<p class="text-kumo-subtle">
							Retrying automatically. You can chat meanwhile; your leaves are held until you
							authorize.
						</p>
					{:else if !sealingReady}
						<p class="text-kumo-subtle">
							Your log is being created (it needs a grant from the authority — up to a minute). You
							can chat meanwhile; your leaves are held until you authorize.
						</p>
					{:else if proofs.delegationDetail}
						<p class={proofs.delegation === 'error' ? 'text-kumo-danger' : 'text-kumo-subtle'}>
							{proofs.delegationDetail}
						</p>
					{/if}

					<!-- ADR-0065 §3: the passkey's endorsement of this browser's
					     signing key is a WINDOW (7 days) that canopy admission and
					     every offline verifier enforce — surface it like the lease.
					     A lapsing endorsement renews itself on the next send (one
					     prompt); this button does it now. -->
					{#if proofs.custody === 'passkey'}
						<div class="flex flex-wrap items-center gap-2 border-t border-kumo-line pt-2">
							<Fingerprint class="size-3.5 text-kumo-subtle" />
							{#if endorsement === 'unknown'}
								<span class="text-kumo-subtle">
									signing-key endorsement: window not recorded — your next message re-endorses (one
									passkey prompt)
								</span>
							{:else if endorsement === 'expired'}
								<Badge tone="danger">endorsement expired</Badge>
								<span class="text-kumo-danger">
									your next message re-endorses this browser's signing key (one passkey prompt)
								</span>
							{:else if endorsement === 'expiring'}
								<Badge tone="warning">
									endorsement lapses in {endorsementRemainingLabel(
										proofs.endorsementExpiresAt!,
										now
									)}
								</Badge>
								<span class="text-kumo-subtle"
									>renews on your next message (one passkey prompt)</span
								>
							{:else}
								<span class="text-kumo-default">
									signing-key endorsement: {endorsementRemainingLabel(
										proofs.endorsementExpiresAt!,
										now
									)} left
								</span>
							{/if}
							<Button
								size="sm"
								variant="ghost"
								disabled={proofs.reendorsing}
								title="Have your passkey endorse this browser's signing key for a fresh 7-day window — one prompt"
								onclick={() => proofs.reendorse()}
							>
								{#if proofs.reendorsing}
									<LoaderCircle class="size-3.5 animate-spin" />
								{/if}
								Re-endorse now
							</Button>
						</div>
					{/if}

					<!-- The sealing authorization is a LEASE (~6h on this lane), by
					     design — surface the countdown and the re-ceremony rather
					     than letting receipts silently stall at expiry (4.3). -->
					{#if activated}
						<div class="flex flex-wrap items-center gap-2 border-t border-kumo-line pt-2">
							<Clock class="size-3.5 text-kumo-subtle" />
							{#if proofs.sealingLeaseExpiresAt === null}
								<span class="text-kumo-subtle">
									sealing is delegated as a time-boxed lease (~6h) — its expiry was not recorded;
									renew if receipts stall
								</span>
							{:else if lease === 'expired'}
								<Badge tone="danger">lease expired</Badge>
								<span class="text-kumo-danger">
									new leaves wait until you renew{proofs.custody === 'passkey'
										? ' — a two-prompt passkey ceremony'
										: ''}
								</span>
							{:else if lease === 'expiring'}
								<Badge tone="warning">
									expires in {leaseRemainingLabel(proofs.sealingLeaseExpiresAt, now)}
								</Badge>
								<span class="text-kumo-subtle">
									renew soon{proofs.custody === 'passkey' ? ' — a two-prompt passkey ceremony' : ''}
								</span>
							{:else}
								<span class="text-kumo-default">
									sealing lease: {leaseRemainingLabel(proofs.sealingLeaseExpiresAt, now)} left
								</span>
								<span class="text-kumo-subtle">
									— renewal is deliberate{proofs.custody === 'passkey'
										? ': two passkey prompts, roughly every 6 hours'
										: ', roughly every 6 hours'}
								</span>
							{/if}
						</div>
					{/if}
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
