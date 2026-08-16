/**
 * Base Sepolia USDC funding helpers.
 *
 * On a paid lane the demo's browser wallet IS the x402 payer, so it must hold
 * USDC on Base Sepolia to buy a user grant. These read the wallet's balance so
 * the user can watch funds arrive before paying, and read the exact token /
 * price out of a parked x402 challenge so the balance is always for the token
 * the lane actually charges in.
 */

/**
 * Circle's USDC on Base Sepolia (6 decimals) — the fallback token when no x402
 * challenge is parked yet. The live challenge's `asset` overrides this.
 */
export const BASE_SEPOLIA_USDC = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
/** Public Base Sepolia JSON-RPC — read-only balance queries, no key needed. */
export const BASE_SEPOLIA_RPC = 'https://sepolia.base.org';
const USDC_DECIMALS = 6;

/** Format a raw 6-decimal USDC amount as a short human string. */
function formatUsdc(raw: bigint): number {
	return Number(raw) / 10 ** USDC_DECIMALS;
}

/** ERC-20 `balanceOf(address)` (selector 0x70a08231) via a single eth_call. */
export async function usdcBalance(
	owner: string,
	token: string = BASE_SEPOLIA_USDC,
	rpc: string = BASE_SEPOLIA_RPC
): Promise<number> {
	const data = `0x70a08231${owner.replace(/^0x/, '').toLowerCase().padStart(64, '0')}`;
	const res = await fetch(rpc, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 1,
			method: 'eth_call',
			params: [{ to: token, data }, 'latest']
		})
	});
	const json = (await res.json()) as { result?: string; error?: { message?: string } };
	if (json.error) throw new Error(json.error.message ?? 'eth_call failed');
	return formatUsdc(BigInt(json.result && json.result !== '0x' ? json.result : '0x0'));
}

/**
 * The exact payment token + price out of a parked `X-PAYMENT-REQUIRED` challenge
 * (base64 JSON, the `exact` scheme option). Null when there's no challenge or it
 * can't be parsed — the caller then falls back to {@link BASE_SEPOLIA_USDC}.
 */
export function paymentFromChallenge(
	challengeB64: string | null
): { asset: string; usdc: number } | null {
	if (!challengeB64) return null;
	try {
		const decoded = JSON.parse(atob(challengeB64)) as {
			accepts?: Array<{ scheme: string; asset: string; amount: string }>;
		};
		const exact = (decoded.accepts ?? []).find((o) => o.scheme === 'exact');
		if (!exact) return null;
		return { asset: exact.asset, usdc: formatUsdc(BigInt(exact.amount)) };
	} catch {
		return null;
	}
}
