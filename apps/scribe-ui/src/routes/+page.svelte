<script lang="ts">
	import { onMount } from 'svelte';
	import { DemoWallet } from '$lib/wallet.svelte.ts';
	import { UserRootKey } from '$lib/user-root.ts';
	import { PasskeyRoot } from '$lib/passkey.ts';
	import { postUserRoot } from '$lib/scribe-api.ts';
	import { ScribeSession } from '$lib/session.svelte.ts';
	import { ScribeChat } from '$lib/chat.svelte.ts';
	import { ProofPanel as ProofPanelState } from '$lib/proofs.svelte.ts';
	import { TurnVault } from '$lib/vault.svelte.ts';
	import ChatPanel from '$lib/components/chat/ChatPanel.svelte';
	import ProofPanel from '$lib/components/proof/ProofPanel.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import { shortHex } from '$lib/utils.ts';
	import { usdcBalance, paymentFromChallenge, BASE_SEPOLIA_USDC } from '$lib/usdc.ts';
	import ScribeMark from '$lib/components/ScribeMark.svelte';
	import { Wallet, RotateCcw, Copy, Check } from '@lucide/svelte';

	const wallet = new DemoWallet();
	const session = new ScribeSession(wallet);
	// The user's per-turn signing key (Phase 4a): a non-extractable WebCrypto
	// P-256 key — the wallet keeps only session auth and x402 payment (Q2
	// custody split). Under passkey custody (4.1, ADR-0064) this key is the
	// SESSION key, endorsed once by the passkey root below; with no
	// authenticator it remains the log root itself (Q4 fallback).
	const userRoot = new UserRootKey();
	// The passkey log root (Phase 4.1): signs ceremonies only — every
	// assertion costs a gesture, so per-turn leaves stay with the session key.
	const passkey = new PasskeyRoot();
	// The user's own copy of their prompts (D4). Keyed to the wallet: a reset
	// identity starts with an empty vault, as it should.
	const vault = new TurnVault(wallet.address);
	const chat = new ScribeChat(session, userRoot, vault);
	const proofs = new ProofPanelState(session, wallet, userRoot, vault, passkey);

	// A settled turn means new commitments are in flight — pull the export.
	chat.onTurnSettled = () => void proofs.refresh();

	// Funding aid (paid lane): the browser wallet is the x402 payer, so it must
	// hold Base Sepolia USDC. Surface a copyable address and the live balance so
	// the user can fund it from their own wallet and watch it arrive. The exact
	// token + price come from any parked x402 challenge; else the Base Sepolia
	// USDC default.
	let copied = $state(false);
	let balance = $state<number | null>(null);
	let balanceError = $state<string | null>(null);
	const payment = $derived(paymentFromChallenge(proofs.grantChallenge));

	/**
	 * Onboard the user's log root (4.1, ADR-0064). Passkey path: create (or
	 * load) the passkey, endorse the session key (one gesture, cached after),
	 * post root + session + endorsement. Any refusal — no authenticator, a
	 * cancelled gesture, a legacy instance whose pinned root is the session
	 * key (409) — falls back to the 4a shape, which stands unchanged (Q4).
	 */
	async function registerUserRoot(): Promise<void> {
		const sessionHex = await userRoot.publicKeyXYHex();
		if (PasskeyRoot.supported()) {
			try {
				const rootHex = await passkey.publicKeyXYHex();
				if (rootHex) {
					const endorsementB64 = await passkey.ensureEndorsement(await userRoot.publicKeyXY());
					await postUserRoot(session.sub!, session.token!, rootHex, {
						sessionPublicKeyXY: sessionHex,
						endorsementB64
					});
					return;
				}
			} catch {
				// Fall through to the session-root shape. NOTE: on a fresh
				// instance this pins the session key as ROOT, and a later
				// passkey upgrade needs the identity-reset flow (ADR-0064
				// consequences) — 4.3 moves creation behind an explicit gesture.
			}
		}
		await postUserRoot(session.sub!, session.token!, sessionHex);
	}

	async function copyAddress() {
		try {
			await navigator.clipboard.writeText(wallet.address);
			copied = true;
			setTimeout(() => (copied = false), 1500);
		} catch {
			// Clipboard blocked (insecure context / permissions) — the full
			// address is still selectable via the title tooltip.
		}
	}

	async function refreshBalance() {
		try {
			balance = await usdcBalance(wallet.address, payment?.asset ?? BASE_SEPOLIA_USDC);
			balanceError = null;
		} catch (err) {
			balanceError = String(err);
		}
	}

	onMount(() => {
		void (async () => {
			try {
				await session.ensure();
				// Register the root FIRST — it is the instance's first touch, so
				// the DO pins it before grant-at-bind issues grant_user over it
				// (a 409 here means this browser lost the pinned root: reset).
				await registerUserRoot();
				await chat.connect();
				await proofs.refresh();
			} catch {
				// session.error / chat.connectionDetail carry the story
			}
		})();
		void refreshBalance();
		const balanceTimer = setInterval(() => void refreshBalance(), 15_000);
		return () => {
			clearInterval(balanceTimer);
			chat.disconnect();
			proofs.stop();
		};
	});

	function resetIdentity() {
		void (async () => {
			// Root first: a fresh wallet means a fresh DO instance, and the new
			// instance must pin the NEW root, not resurface the old pair.
			await passkey.reset();
			await userRoot.reset();
			wallet.reset();
			session.clear();
			location.reload();
		})();
	}
</script>

<div class="flex h-dvh flex-col bg-kumo-recessed">
	<header
		class="flex items-center justify-between gap-3 border-b border-kumo-line bg-kumo-elevated px-4 py-2.5"
	>
		<div class="flex items-center gap-2.5">
			<span class="flex size-8 items-center justify-center rounded-lg bg-kumo-brand text-white">
				<ScribeMark class="size-5" />
			</span>
			<div>
				<h1 class="text-sm leading-tight font-semibold text-kumo-strong">The Scribe</h1>
				<p class="text-[11px] leading-tight text-kumo-subtle">
					an attested conversation, receipted on a Forestrie transparency log
				</p>
			</div>
		</div>
		<div class="flex items-center gap-2">
			{#if session.error}
				<Badge tone="danger" title={session.error}>auth failed</Badge>
			{/if}
			<!-- USDC balance on Base Sepolia — this wallet pays for grants, so fund
			     it if it reads 0. Shows the batch price when a challenge is parked. -->
			<Badge
				tone={balance !== null && balance === 0 ? 'warning' : 'neutral'}
				title={balanceError
					? `balance unavailable: ${balanceError}`
					: `USDC on Base Sepolia — fund this wallet to buy grants${
							payment ? ` ($${payment.usdc.toFixed(2)} per batch)` : ''
						}`}
			>
				{balance === null ? '…' : balance.toFixed(2)} USDC
			</Badge>
			<!-- Click to copy the full address, so the user can send funds to it. -->
			<button
				type="button"
				onclick={copyAddress}
				title="Copy full address — {wallet.address}"
				class="flex items-center gap-1.5 rounded-md border border-kumo-line bg-kumo-recessed px-2 py-1 font-mono text-[11px] text-kumo-default hover:bg-kumo-elevated"
			>
				<Wallet class="size-3 text-kumo-subtle" />
				{shortHex(wallet.address, 6, 4)}
				{#if copied}
					<Check class="size-3 text-kumo-success" />
				{:else}
					<Copy class="size-3 text-kumo-subtle" />
				{/if}
			</button>
			<Button
				size="sm"
				variant="ghost"
				title="Forget this identity and start fresh"
				onclick={resetIdentity}
			>
				<RotateCcw class="size-3.5" />
			</Button>
		</div>
	</header>

	<main
		class="grid min-h-0 flex-1 grid-cols-1 gap-3 overflow-y-auto p-3 lg:grid-cols-[minmax(0,1fr)_420px] lg:overflow-hidden"
	>
		<ChatPanel {chat} />
		<ProofPanel {proofs} />
	</main>
</div>
