/**
 * The grant-issuing authority as a Cloudflare Worker (M5, plan §11 O5/O4).
 *
 * Holds K(L) of BOTH authority logs and issues *creation grants* that endorse a
 * signer by creating a fresh data log whose `grantData` names it — the role
 * provision.sh played by hand.
 *
 * Two-parent topology (plan-2608-09 W4b.1, ARC-0029 §2 corollary A): the payment
 * bit lives on the PARENT and gates every child uniformly, so agent grants land
 * under the bit-free agent-authority log and user grants under the
 * user-authority log carrying GF_CHILD_PAYMENT_REQUIRED. Agents stay ungated by
 * topology — never by an operator bypass token (canopy C7/C10).
 *
 *   POST /grants/agent {publicKeyXY}  grantData = 64-byte ES256 x‖y (agent kid)
 *   POST /grants/user  {address}      grantData = 20-byte KS256 wallet address
 *   GET  /healthz                     liveness + the log ids it is wired to
 *
 * ## Deployment posture
 *
 * `workers_dev: false` — reachable only through the scribe worker's service
 * binding. GRANT_AUTHORITY_TOKEN is MANDATORY rather than optional as it was
 * locally: an unauthenticated grant faucet on a public URL would let anyone mint
 * writer credentials against a live canopy lane. The service refuses to serve
 * anything but /healthz without it, rather than silently running open the way
 * the local script did (`if (AUTHORITY_TOKEN && ...)`).
 */
import { bytesToB64, hexToBytes } from './bytes.ts';
import {
	IssuancePending,
	PaymentRequired,
	issueCreationGrant,
	type IssuanceAuthority,
	type IssueContext
} from './issue.ts';
import { renewAllLeases, renewLeaseIfNeeded, type LeaseContext } from './leases.ts';
import { authorityKeyProvider, importAuthorityKey, type AuthorityKeyPair } from './sign-grant.ts';
import { kvIssuerStore } from './state.ts';

export interface AuthorityEnv {
	AUTHORITY: KVNamespace;

	/** K(L) of both authority logs, as a private JWK. THE crown-jewel secret. */
	AUTHORITY_ES256_JWK: string;
	/** Mandatory bearer. Absent = the service refuses everything but /healthz. */
	GRANT_AUTHORITY_TOKEN?: string;
	/** Operator token for the coordinator public-root upload (user grants only). */
	COORDINATOR_APP_TOKEN?: string;

	FORESTRIE_BASE_URL: string;
	DELEGATION_COORDINATOR_URL: string;
	KNOWN_SEALER_KEY: string;

	ROOT_LOG_ID: string;
	AGENT_AUTH_LOG_ID: string;
	USER_AUTH_LOG_ID: string;
	AGENT_AUTH_GRANT_B64: string;
	USER_AUTH_GRANT_B64: string;

	/** Batch size stamped on user grants as maxHeight (W4a). Default 16. */
	USER_GRANT_BATCH_TURNS?: string;
}

/**
 * Per-isolate key memo. Importing is cheap but not free, and every request
 * needs the handle; the scalar itself is never in scope after import.
 */
let keysPromise: Promise<AuthorityKeyPair> | undefined;
function authorityKeys(env: AuthorityEnv): Promise<AuthorityKeyPair> {
	keysPromise ??= importAuthorityKey(env.AUTHORITY_ES256_JWK);
	return keysPromise;
}

function config(env: AuthorityEnv) {
	const missing = (
		[
			'FORESTRIE_BASE_URL',
			'DELEGATION_COORDINATOR_URL',
			'KNOWN_SEALER_KEY',
			'ROOT_LOG_ID',
			'AGENT_AUTH_LOG_ID',
			'USER_AUTH_LOG_ID',
			'AGENT_AUTH_GRANT_B64',
			'USER_AUTH_GRANT_B64'
		] as const
	).filter((k) => !env[k]);
	if (missing.length)
		throw new Error(`grant-authority is not configured: missing ${missing.join(', ')}`);

	const agentAuthority: IssuanceAuthority = {
		logId: env.AGENT_AUTH_LOG_ID,
		grantB64: env.AGENT_AUTH_GRANT_B64
	};
	const userAuthority: IssuanceAuthority = {
		logId: env.USER_AUTH_LOG_ID,
		grantB64: env.USER_AUTH_GRANT_B64
	};
	return {
		agentAuthority,
		userAuthority,
		batchTurns: Number(env.USER_GRANT_BATCH_TURNS ?? '16')
	};
}

async function contexts(env: AuthorityEnv): Promise<{ issue: IssueContext; lease: LeaseContext }> {
	const keys = await authorityKeys(env);
	const store = kvIssuerStore(env.AUTHORITY);
	return {
		issue: {
			baseUrl: env.FORESTRIE_BASE_URL,
			rootLogId: env.ROOT_LOG_ID,
			privateKey: keys.privateKey,
			store
		},
		lease: {
			coordinatorUrl: env.DELEGATION_COORDINATOR_URL,
			knownSealerKeyB64: env.KNOWN_SEALER_KEY,
			keys: authorityKeyProvider(keys),
			store
		}
	};
}

/**
 * Register a KS256-owned log's public root with the coordinator (operator
 * action). canopy only auto-forwards 64-byte ES256 owner keys, so a user log
 * owned by a 20-byte wallet address needs this hop before it can be sealed.
 */
async function uploadKs256PublicRoot(
	env: AuthorityEnv,
	logId: string,
	address: Uint8Array
): Promise<void> {
	if (!env.COORDINATOR_APP_TOKEN)
		throw new Error('COORDINATOR_APP_TOKEN not set — cannot register the user log public root');
	const res = await fetch(`${env.DELEGATION_COORDINATOR_URL}/api/logs/${logId}/public-root`, {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${env.COORDINATOR_APP_TOKEN}`,
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ alg: -65799, key: bytesToB64(address) })
	});
	if (!res.ok)
		throw new Error(
			`public-root upload failed: HTTP ${res.status} ${(await res.text()).slice(0, 200)}`
		);
}

async function handleAgentGrant(
	env: AuthorityEnv,
	body: Record<string, unknown>
): Promise<Response> {
	const xyHex = String(body.publicKeyXY ?? '');
	if (!/^[0-9a-f]{128}$/i.test(xyHex))
		return Response.json(
			{ error: 'publicKeyXY must be 128 hex chars (64-byte ES256 x||y)' },
			{ status: 400 }
		);
	const kidHex = xyHex.slice(0, 64).toLowerCase();

	const { agentAuthority } = config(env);
	const { issue, lease } = await contexts(env);

	const cached = await issue.store.getIssued('agent', kidHex);
	if (cached) return Response.json({ ...cached, preIssued: true });

	// Just-in-time: cheap while the lease has runway, and closes the window
	// between cron ticks after a long idle stretch.
	await renewLeaseIfNeeded(lease, agentAuthority.logId);

	const issued = await issueCreationGrant(
		issue,
		agentAuthority,
		'agent',
		kidHex,
		hexToBytes(xyHex),
		0
	);
	const record = {
		kind: 'agent' as const,
		subject: kidHex,
		logId: issued.logId,
		grantB64: issued.grantB64
	};
	await issue.store.putIssued(record);
	console.log(`issued grant_agent kid=${kidHex.slice(0, 16)}… log=${issued.logId}`);
	return Response.json({ ...record, kid: kidHex, preIssued: false }, { status: 201 });
}

async function handleUserGrant(
	env: AuthorityEnv,
	body: Record<string, unknown>
): Promise<Response> {
	const addrHex = String(body.address ?? '')
		.replace(/^0x/, '')
		.toLowerCase();
	if (!/^[0-9a-f]{40}$/.test(addrHex))
		return Response.json(
			{ error: 'address must be a 20-byte hex KS256 wallet address' },
			{ status: 400 }
		);
	const subject = `0x${addrHex}`;

	const { userAuthority, batchTurns } = config(env);
	const { issue, lease } = await contexts(env);

	// `renew` (W4c top-up): the caller's batch is spent — issue a FRESH grant on
	// a fresh log (O3) rather than the cached one.
	const renew = body.renew === true;
	if (!renew) {
		const cached = await issue.store.getIssued('user', subject);
		if (cached) return Response.json({ ...cached, address: subject, preIssued: true });
	}

	await renewLeaseIfNeeded(lease, userAuthority.logId);

	const address = hexToBytes(addrHex);
	const xPayment = typeof body.xPayment === 'string' && body.xPayment ? body.xPayment : undefined;

	let issued;
	try {
		issued = await issueCreationGrant(
			issue,
			userAuthority,
			'user',
			subject,
			address,
			batchTurns,
			xPayment
		);
	} catch (err) {
		if (err instanceof PaymentRequired)
			return Response.json(
				{
					paymentRequired: true,
					challengeB64: err.challengeB64,
					address: subject,
					maxHeight: batchTurns
				},
				{ status: 402 }
			);
		throw err;
	}

	await uploadKs256PublicRoot(env, issued.logId, address);
	const record = {
		kind: 'user' as const,
		subject,
		logId: issued.logId,
		grantB64: issued.grantB64,
		maxHeight: issued.maxHeight
	};
	await issue.store.putIssued(record);
	console.log(
		`issued grant_user addr=${subject} log=${issued.logId}${xPayment ? ' (x402 paid)' : ''}`
	);
	return Response.json({ ...record, address: subject, preIssued: false }, { status: 201 });
}

export default {
	async fetch(request: Request, env: AuthorityEnv): Promise<Response> {
		const url = new URL(request.url);

		if (request.method === 'GET' && url.pathname === '/healthz')
			return Response.json({
				ok: true,
				agentAuthLogId: env.AGENT_AUTH_LOG_ID ?? null,
				userAuthLogId: env.USER_AUTH_LOG_ID ?? null,
				rootLogId: env.ROOT_LOG_ID ?? null,
				authenticated: Boolean(env.GRANT_AUTHORITY_TOKEN)
			});

		// Mandatory, unlike the local script where it was opt-in. A deployed
		// authority with no token is an open grant faucet, so refuse to serve
		// rather than serve open.
		if (!env.GRANT_AUTHORITY_TOKEN)
			return Response.json(
				{ error: 'authority is not configured with a bearer token' },
				{ status: 503 }
			);
		if (request.headers.get('authorization') !== `Bearer ${env.GRANT_AUTHORITY_TOKEN}`)
			return Response.json({ error: 'bad authority token' }, { status: 401 });

		if (request.method !== 'POST' || !['/grants/agent', '/grants/user'].includes(url.pathname))
			return Response.json({ error: 'unknown route' }, { status: 404 });

		let body: Record<string, unknown>;
		try {
			body = (await request.json()) as Record<string, unknown>;
		} catch {
			return Response.json({ error: 'body must be JSON' }, { status: 400 });
		}

		try {
			return url.pathname === '/grants/agent'
				? await handleAgentGrant(env, body)
				: await handleUserGrant(env, body);
		} catch (err) {
			if (err instanceof IssuancePending)
				// Not an error: the registration is accepted and persisted, and the
				// caller's retry resumes it rather than minting a second grant.
				return Response.json({ error: err.message, pending: true }, { status: 504 });
			console.error(`${request.method} ${url.pathname} failed:`, err);
			return Response.json({ error: String(err) }, { status: 502 });
		}
	},

	/** Replaces the local service's setInterval lease renewer. */
	async scheduled(_event: ScheduledController, env: AuthorityEnv): Promise<void> {
		const { agentAuthority, userAuthority } = config(env);
		const { lease } = await contexts(env);
		await renewAllLeases(lease, [agentAuthority.logId, userAuthority.logId]);
	}
} satisfies ExportedHandler<AuthorityEnv>;
