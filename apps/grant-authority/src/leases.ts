/**
 * Auth-log sealing leases — the gap the 2026-08-10 outage exposed.
 *
 * Grant issuance blocks on the grant's inclusion receipt, which needs the
 * issuing auth log sealed. The lease provision.sh signs at `up` time expires
 * (~6h) and nothing renewed it, so every grant request eventually 502'd with
 * "grant receipt timed out (auth-log seal)". The authority holds K(L) for BOTH
 * its auth logs, so it renews each lease itself.
 *
 * The local service used `setInterval(...).unref()`, which does not exist in
 * workerd. Renewal now happens in three places, same as before:
 *   - on the cron trigger (replacing the interval)
 *   - just-in-time before each issuance (this is what actually protects a turn)
 *   - implicitly on cold start, via the just-in-time check
 *
 * Expiry is persisted in KV rather than an in-process Map: a module-scope Map
 * dies with the isolate, so every cold start would re-POST a delegation
 * certificate to the coordinator. Renewal is idempotent so that was merely
 * wasteful, not wrong — but it is visible in the coordinator's rate limits.
 *
 * Cross-isolate renewals can still race: two isolates can both decide a lease
 * needs renewing and both call delegateSealing. That is safe — the call is
 * idempotent — and there is no lock here, deliberately, rather than a
 * single-flight guard that only works within one isolate and reads like one
 * that works everywhere.
 */
import { delegateSealing } from '@forestrie/think-scribe/forestrie/delegate';
import type { IssuerStore } from './state.ts';

/** Renew when the lease has less runway than this (seconds). */
const RENEW_MARGIN_S = 1800;

export interface LeaseContext {
	coordinatorUrl: string;
	knownSealerKeyB64: string;
	/** The authority key as a KeyProvider — see sign-grant.authorityKeyProvider. */
	keys: Parameters<typeof delegateSealing>[0];
	store: IssuerStore;
}

/**
 * Renew one auth log's sealing lease if it is inside the margin. Never throws:
 * a failed renewal degrades to the timeout the caller already handles, and the
 * next check retries. Losing the service over a renewal would be worse than a
 * slow grant.
 */
export async function renewLeaseIfNeeded(ctx: LeaseContext, logId: string): Promise<void> {
	const expiresAt = await ctx.store.getLeaseExpiry(logId);
	if (expiresAt - Date.now() / 1000 > RENEW_MARGIN_S) return;

	try {
		const result = await delegateSealing(ctx.keys, {
			coordinatorUrl: ctx.coordinatorUrl,
			logId,
			knownSealerKeyB64: ctx.knownSealerKeyB64
		});
		await ctx.store.putLeaseExpiry(logId, result.expiresAt);
		console.log(
			`auth-log ${logId} sealing lease renewed — sealer ${result.sealerId}, expires ${new Date(
				result.expiresAt * 1000
			).toISOString()}`
		);
	} catch (err) {
		console.error(
			`auth-log ${logId} sealing renewal failed (grants may time out until it succeeds):`,
			err
		);
	}
}

export async function renewAllLeases(ctx: LeaseContext, logIds: string[]): Promise<void> {
	await Promise.all(logIds.map((id) => renewLeaseIfNeeded(ctx, id)));
}
