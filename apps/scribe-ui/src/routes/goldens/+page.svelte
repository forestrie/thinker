<script lang="ts">
	import { dev } from '$app/environment';
	import {
		createCaptureIdentity,
		captureGolden,
		type CaptureIdentity,
		type GoldenCapture
	} from '$lib/goldens.ts';

	let identity: CaptureIdentity | null = $state(null);
	let golden: GoldenCapture | null = $state(null);
	let busy = $state(false);
	let error = $state('');
	let copied = $state(false);

	async function onCreate() {
		busy = true;
		error = '';
		try {
			identity = await createCaptureIdentity();
			if (!identity) error = 'authenticator refused, or produced a non-P-256 credential';
		} catch (e) {
			error = String(e);
		} finally {
			busy = false;
		}
	}

	async function onCapture() {
		if (!identity) return;
		busy = true;
		error = '';
		try {
			golden = await captureGolden(identity);
		} catch (e) {
			error = String(e);
		} finally {
			busy = false;
		}
	}

	function goldenJson(): string {
		return JSON.stringify(golden, null, 2) + '\n';
	}

	function onDownload() {
		const blob = new Blob([goldenJson()], { type: 'application/json' });
		const a = document.createElement('a');
		a.href = URL.createObjectURL(blob);
		a.download = 'webauthn-real-authenticator-golden.json';
		a.click();
		URL.revokeObjectURL(a.href);
	}

	async function onCopy() {
		await navigator.clipboard.writeText(goldenJson());
		copied = true;
		setTimeout(() => (copied = false), 1500);
	}
</script>

<div class="mx-auto max-w-2xl space-y-6 p-8 font-mono text-sm">
	<h1 class="text-lg font-bold">WebAuthn golden capture (plan-2608-13 · 5.1)</h1>
	{#if !dev}
		<p>Dev-only harness. Run <code>pnpm dev</code> and open this page there.</p>
	{:else}
		<p class="opacity-80">
			Captures a real-authenticator delegation golden via the REAL
			<code>delegateSealingWebauthn</code> ceremony (mock coordinator, fixed fixture scope). Two authenticator
			prompts: the certificate's envelope assertion, then the on-chain proof's assertion. The credential
			is a throwaway — it never touches the scribe's own custody record. Both artifacts are verified through
			the contract mirrors before download is offered.
		</p>

		<div class="space-y-2">
			<button
				class="rounded border px-3 py-2 disabled:opacity-40"
				onclick={onCreate}
				disabled={busy || !!identity}
			>
				1 · Create throwaway capture passkey
			</button>
			{#if identity}
				<div>
					root x‖y: <code>{identity.rootPublicKeyXY.length} bytes ok</code> · rpId:
					<code>{identity.rpId}</code>
				</div>
			{/if}
		</div>

		<div class="space-y-2">
			<button
				class="rounded border px-3 py-2 disabled:opacity-40"
				onclick={onCapture}
				disabled={busy || !identity || !!golden}
			>
				2 · Run ceremony (two authenticator prompts)
			</button>
		</div>

		{#if error}
			<p class="text-red-600">{error}</p>
		{/if}

		{#if golden}
			<div class="space-y-2">
				<p class="text-green-700">
					Both artifacts verified (UV enforced). challenge indices:
					<code>{golden.onchain.challengeIndex}/{golden.onchain.typeIndex}</code>
				</p>
				<div class="flex gap-2">
					<button class="rounded border px-3 py-2" onclick={onDownload}>Download JSON</button>
					<button class="rounded border px-3 py-2" onclick={onCopy}>
						{copied ? 'Copied' : 'Copy JSON'}
					</button>
				</div>
				<pre class="max-h-96 overflow-auto rounded border p-3 text-xs">{goldenJson()}</pre>
			</div>
		{/if}
	{/if}
</div>
