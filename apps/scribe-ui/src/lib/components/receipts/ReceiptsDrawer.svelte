<script lang="ts">
	import type { ProofPanel } from '$lib/proofs.svelte.ts';
	import { turnNumber } from '$lib/receipt-status.ts';
	import { shortHex } from '$lib/utils.ts';
	import Button from '$lib/components/ui/Button.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import ReceiptRow from './ReceiptRow.svelte';
	import { Download, LoaderCircle, RefreshCw, ShieldCheck, Trash2, X } from '@lucide/svelte';

	let {
		proofs,
		open,
		onclose
	}: {
		proofs: ProofPanel;
		open: boolean;
		onclose: () => void;
	} = $props();

	let heading = $state<HTMLHeadingElement | null>(null);

	// Focus lands on the drawer title when it opens; the opener restores its
	// own focus (the Receipts button keeps focus by default on close). Body
	// scroll locks while the overlay is up.
	$effect(() => {
		if (!open) return;
		heading?.focus();
		const prev = document.body.style.overflow;
		document.body.style.overflow = 'hidden';
		return () => {
			document.body.style.overflow = prev;
		};
	});

	function onkeydown(e: KeyboardEvent) {
		if (open && e.key === 'Escape') onclose();
	}

	const ordered = $derived([...proofs.works].sort((a, b) => b.submittedAt - a.submittedAt));

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

<svelte:window {onkeydown} />

{#if open}
	<div
		class="fixed inset-0 z-40 bg-black/30"
		onclick={onclose}
		aria-hidden="true"
		data-testid="receipts-backdrop"
	></div>
	<div
		role="dialog"
		aria-modal="true"
		aria-label="Your receipts"
		class="fixed inset-y-0 right-0 z-50 flex w-[380px] max-w-full flex-col border-l border-kumo-line bg-kumo-elevated shadow-xl"
	>
		<div class="flex items-center justify-between gap-2 border-b border-kumo-hairline px-4 py-3">
			<h2
				tabindex="-1"
				bind:this={heading}
				class="text-sm font-semibold text-kumo-strong outline-none"
			>
				Your receipts
			</h2>
			<Button size="sm" variant="ghost" title="Close" onclick={onclose}>
				<X class="size-3.5" />
			</Button>
		</div>

		<div class="flex flex-col gap-2 border-b border-kumo-hairline px-4 py-3">
			<p class="text-xs leading-relaxed text-kumo-subtle">
				One receipt per turn. Each proves what was said — and they keep working with the Scribe
				switched off.
			</p>
			<a
				href="https://github.com/forestrie/thinker/blob/main/docs/how-receipts-work.md"
				target="_blank"
				rel="noreferrer"
				class="text-xs font-medium text-kumo-brand hover:underline"
			>
				How receipts work
			</a>
		</div>

		<div class="min-h-0 flex-1 overflow-y-auto p-2">
			{#if ordered.length === 0}
				<p class="p-4 text-center text-xs text-kumo-subtle">
					No receipts yet — they appear as you chat.
				</p>
			{/if}
			{#each ordered as work (work.workId)}
				<ReceiptRow
					{work}
					n={turnNumber(proofs.works, work.workId)}
					keptInput={proofs.keptInput(work.workId)}
					verification={proofs.verifications[work.workId]}
					canVerify={!proofs.verifying && proofs.identity !== null}
					onverify={() => proofs.verify(work)}
				/>
			{/each}
		</div>

		<div class="flex flex-col gap-2.5 border-t border-kumo-hairline px-4 py-3">
			<Button
				size="sm"
				variant="secondary"
				disabled={proofs.export === null}
				title="Download everything an auditor needs, including your own copy of the text"
				onclick={() => proofs.downloadBundle()}
			>
				<Download class="size-3.5" />
				Download receipts
			</Button>
			<p class="text-[11px] leading-relaxed text-kumo-subtle">
				Your message text stays only in this browser ({proofs.keptCount} kept).
				<button
					type="button"
					class="inline-flex items-center gap-1 font-medium text-kumo-danger hover:underline disabled:opacity-50"
					disabled={proofs.keptCount === 0}
					onclick={deleteLocal}
				>
					<Trash2 class="size-3" />
					Delete my copy
				</button>
			</p>

			<!-- Depth on demand: the one surface where protocol vocabulary is
			     allowed to survive. Everything here moved from the old proof
			     panel unchanged in behavior. -->
			<details class="group">
				<summary
					class="cursor-pointer list-none text-[11px] font-medium text-kumo-subtle hover:text-kumo-default [&::-webkit-details-marker]:hidden"
				>
					Advanced
				</summary>
				<div class="mt-2 space-y-3 text-xs">
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
					{/if}

					{#if proofs.export?.attestationMode === 'separate'}
						<div class="flex flex-wrap items-center gap-2">
							<Button
								size="sm"
								variant="secondary"
								disabled={proofs.policy === 'verifying'}
								title="Verify the parent grant's payment policy offline against the forest root key"
								onclick={() => proofs.verifyParentPolicy()}
							>
								{#if proofs.policy === 'verifying'}
									<LoaderCircle class="size-3.5 animate-spin" />
								{:else}
									<ShieldCheck class="size-3.5" />
								{/if}
								Verify payment policy
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
					{/if}

					{#if proofs.demoTurns}
						<p class="text-kumo-subtle">
							demo cap: turn {proofs.demoTurns.global.used} of {proofs.demoTurns.global.cap} allowed today
						</p>
					{/if}

					{#if proofs.userGrantError}
						<p class="text-kumo-danger">user grant: {proofs.userGrantError}</p>
					{/if}
					{#if proofs.error}
						<p class="rounded-md bg-kumo-danger-tint px-2.5 py-1.5 text-kumo-danger">
							{proofs.error}
						</p>
					{/if}

					<div class="flex items-center gap-2">
						<Button
							size="sm"
							variant="ghost"
							disabled={proofs.refreshing}
							title="Ask the service to collect pending receipts now"
							onclick={() => proofs.collectNow()}
						>
							<RefreshCw class="size-3.5 {proofs.refreshing ? 'animate-spin' : ''}" />
							Refresh receipts
						</Button>
						{#if proofs.anyInFlight}
							<Badge tone="info"><LoaderCircle class="size-3 animate-spin" /> collecting</Badge>
						{/if}
					</div>
				</div>
			</details>
		</div>
	</div>
{/if}
