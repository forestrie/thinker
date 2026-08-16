/**
 * Grant issuance: build → register → wait out sequencing and the covering seal
 * → splice the inclusion receipt into the COSE Sign1.
 *
 * Ported from scripts/grant-authority.mjs. Two things changed for workerd, both
 * forced by the platform rather than preference:
 *
 * **A bounded deadline.** The local service polled for up to 240s at 2-3s
 * intervals — worst case ~200 subrequests in one request, well over the Workers
 * Free limit of 50 (Paid is 1000, which is why this needs Workers Paid at all).
 * The deadline here is 60s with the poll backing off after 30s, which keeps the
 * subrequest count around 20.
 *
 * **Resumable registration.** Cutting the deadline creates a hazard the local
 * service never had to think about: if we time out AFTER the lane accepted the
 * registration, a naive retry builds a brand-new grant on a brand-new log —
 * orphaning the accepted one and, on a paid lane, burning the payment. So the
 * in-flight record is persisted BEFORE polling starts, and a later call resumes
 * the same statusUrl instead of re-registering. This is the one piece of the
 * port that is genuinely new logic rather than a translation.
 */
import {
	bytesToForestrieGrantBase64,
	dataLogCreateExtendFlags,
	HEADER_IDTIMESTAMP,
	HEADER_RECEIPT
} from '@forestrie/grant-builder';
import {
	encodeCborDeterministic,
	encodeGrantPayloadV0Canonical,
	mergeUnprotectedIntoCoseSign1,
	uuidToBytes
} from '@forestrie/encoding';
import {
	forestrieGrantAuthorization,
	interpretRegisterRedirect,
	parseEntryIdFromReceiptLocation,
	RECEIPT_LOCATION_RE
} from '@forestrie/scrapi-client';
import { signGrantPayload } from './sign-grant.ts';
import type { InFlightRegistration, IssuerStore } from './state.ts';
import { b64ToBytes, bytesToB64 } from './bytes.ts';

/** Overall budget for one issuance attempt. See the module note on limits. */
const DEADLINE_MS = 60_000;
/** Poll interval before and after the backoff point. */
const POLL_FAST_MS = 2_000;
const POLL_SLOW_MS = 5_000;
const BACKOFF_AFTER_MS = 30_000;

/** One of the two issuance parents (W4b.1). Same key owns both logs. */
export interface IssuanceAuthority {
	logId: string;
	grantB64: string;
}

export interface IssueContext {
	baseUrl: string;
	rootLogId: string;
	privateKey: CryptoKey;
	store: IssuerStore;
	fetchImpl?: typeof fetch;
}

/** The lane answered 402: the caller must pay before the grant can register. */
export class PaymentRequired extends Error {
	constructor(readonly challengeB64: string) {
		super('register-grant requires payment');
	}
}

/** The deadline expired with the registration still in flight. Safe to retry. */
export class IssuancePending extends Error {
	constructor() {
		super('grant registration still pending — retry to resume');
	}
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Build and sign a creation grant endorsing `grantData` on a fresh data log
 * owned by `authority`. `maxHeight > 0` sizes the grant to a purchased batch
 * (user grants, W4a); 0 leaves it unbounded (agent grants).
 *
 * Signing is cheap and stateless — the expensive register/seal is separate, so
 * a resume never re-signs.
 */
export async function buildCreationGrant(
	authority: IssuanceAuthority,
	grantData: Uint8Array,
	maxHeight: number,
	privateKey: CryptoKey
): Promise<{ logId: string; sign1: Uint8Array; grantBase64: string }> {
	const logId = crypto.randomUUID();
	const payloadBytes = encodeGrantPayloadV0Canonical({
		logId: uuidToBytes(logId),
		ownerLogId: uuidToBytes(authority.logId),
		grant: dataLogCreateExtendFlags(),
		maxHeight,
		minGrowth: 0,
		grantData
	});
	const sign1 = await signGrantPayload(payloadBytes, privateKey);
	return { logId, sign1, grantBase64: bytesToForestrieGrantBase64(sign1) };
}

/**
 * POST a built grant to `/register/{R}/grants` under `authority`'s parent grant.
 *
 * Done raw rather than through the stock `registerGrant` because that throws on
 * any non-303 and so cannot see the x402 gate: when the parent carries
 * GF_CHILD_PAYMENT_REQUIRED and the lane admits `paid`/`either`, register-grant
 * answers 402 with an X-PAYMENT-REQUIRED challenge that has to reach the
 * browser wallet (W4b — the authority is the registrar, the browser is payer).
 */
async function registerGrantRaw(
	ctx: IssueContext,
	authority: IssuanceAuthority,
	grantBase64: string,
	xPayment?: string
): Promise<
	{ status: 'receipt'; statusUrl: string } | { status: 'payment_required'; challengeB64: string }
> {
	const headers: Record<string, string> = {
		Authorization: forestrieGrantAuthorization(grantBase64),
		'Content-Type': 'application/cbor'
	};
	if (xPayment) headers['X-PAYMENT'] = xPayment;

	const doFetch = ctx.fetchImpl ?? fetch;
	const res = await doFetch(`${ctx.baseUrl.replace(/\/$/, '')}/register/${ctx.rootLogId}/grants`, {
		method: 'POST',
		headers,
		redirect: 'manual',
		body: encodeCborDeterministic({ parentGrant: b64ToBytes(authority.grantB64) }) as BodyInit
	});

	if (res.status === 402) {
		const challengeB64 = res.headers.get('x-payment-required');
		if (!challengeB64)
			throw new Error('register-grant 402 without X-PAYMENT-REQUIRED challenge header');
		return { status: 'payment_required', challengeB64 };
	}
	const { statusUrl } = interpretRegisterRedirect(
		{
			status: res.status,
			location: res.headers.get('location') ?? undefined,
			body: new Uint8Array(await res.arrayBuffer())
		},
		ctx.baseUrl
	);
	return { status: 'receipt', statusUrl };
}

/**
 * Poll sequencing then the receipt, within the deadline.
 *
 * The two GETs are issued here rather than through the scrapi-client's
 * `queryRegistrationOnce` / `resolveReceiptOnce` for one reason: those helpers
 * close over the GLOBAL fetch and take no override, so using them would make
 * `ctx.fetchImpl` a half-truth — the register call stubbed, the polling silently
 * hitting the network. The library's *pure* contract parsers
 * (`RECEIPT_LOCATION_RE`, `parseEntryIdFromReceiptLocation`) are still the
 * authority on what a Location means; only the transport is ours.
 */
async function awaitReceipt(
	ctx: IssueContext,
	statusUrl: string,
	deadline: number,
	startedAt: number
): Promise<{ receipt: Uint8Array; entryIdHex: string }> {
	const doFetch = ctx.fetchImpl ?? fetch;
	const pollDelay = () => (Date.now() - startedAt > BACKOFF_AFTER_MS ? POLL_SLOW_MS : POLL_FAST_MS);
	const wait = async (ms: number) => sleep(Math.max(0, Math.min(ms, deadline - Date.now())));

	// 1. Sequencing: the status URL 303s to itself until sequenced, then 303s to
	//    the permanent receipt URL.
	let receiptUrl: string;
	let entryIdHex: string;
	for (;;) {
		if (Date.now() > deadline) throw new IssuancePending();
		const res = await doFetch(statusUrl, { redirect: 'manual' });
		if (res.status !== 303)
			throw new Error(`grant status: HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);

		const location = res.headers.get('location');
		if (location && RECEIPT_LOCATION_RE.test(location)) {
			receiptUrl = location;
			entryIdHex = parseEntryIdFromReceiptLocation(location);
			break;
		}
		const retryAfter = Number(res.headers.get('retry-after'));
		await wait(Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : pollDelay());
	}

	// 2. The receipt 404s until the covering checkpoint is sealed (T9) — that is
	//    the minutes-latent step, and the reason this whole path is resumable.
	for (;;) {
		if (Date.now() > deadline) throw new IssuancePending();
		const res = await doFetch(receiptUrl, { redirect: 'manual' });
		if (res.status === 200) return { receipt: new Uint8Array(await res.arrayBuffer()), entryIdHex };
		if (res.status !== 404) throw new Error(`grant receipt: HTTP ${res.status}`);
		await wait(pollDelay());
	}
}

/** Splice the inclusion receipt into the Sign1 → completed transparent statement. */
function complete(sign1: Uint8Array, receipt: Uint8Array, entryIdHex: string): string {
	const idtimestamp = new Uint8Array(8);
	const hexPrefix = entryIdHex.slice(0, 16);
	for (let i = 0; i < 8; i++)
		idtimestamp[i] = Number.parseInt(hexPrefix.slice(i * 2, i * 2 + 2), 16);
	const completed = mergeUnprotectedIntoCoseSign1(
		sign1,
		new Map<number, Uint8Array>([
			[HEADER_RECEIPT, receipt],
			[HEADER_IDTIMESTAMP, idtimestamp]
		])
	);
	return bytesToForestrieGrantBase64(completed);
}

/**
 * Build (or resume), register and complete a creation grant.
 *
 * Resume path: if an in-flight record exists for this subject, its statusUrl is
 * polled instead of registering again — see the module note. The record is
 * written before the first poll and cleared only once the receipt is in hand.
 */
export async function issueCreationGrant(
	ctx: IssueContext,
	authority: IssuanceAuthority,
	kind: 'agent' | 'user',
	subject: string,
	grantData: Uint8Array,
	maxHeight: number,
	xPayment?: string
): Promise<{ logId: string; grantB64: string; maxHeight: number }> {
	const startedAt = Date.now();
	const deadline = startedAt + DEADLINE_MS;

	const resumed = await ctx.store.getInFlight(kind, subject);
	let inFlight: InFlightRegistration;

	if (resumed) {
		inFlight = resumed;
	} else {
		const built = await buildCreationGrant(authority, grantData, maxHeight, ctx.privateKey);
		const submitted = await registerGrantRaw(ctx, authority, built.grantBase64, xPayment);
		if (submitted.status === 'payment_required') throw new PaymentRequired(submitted.challengeB64);

		inFlight = {
			logId: built.logId,
			sign1B64: bytesToB64(built.sign1),
			statusUrl: submitted.statusUrl,
			startedAt,
			maxHeight
		};
		// Persist BEFORE polling: everything after this point is recoverable.
		await ctx.store.putInFlight(kind, subject, inFlight);
	}

	const { receipt, entryIdHex } = await awaitReceipt(ctx, inFlight.statusUrl, deadline, startedAt);
	const grantB64 = complete(b64ToBytes(inFlight.sign1B64), receipt, entryIdHex);

	await ctx.store.deleteInFlight(kind, subject);
	return { logId: inFlight.logId, grantB64, maxHeight: inFlight.maxHeight ?? maxHeight };
}
