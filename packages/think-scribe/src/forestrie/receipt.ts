/**
 * Offline receipt verification for a Scribe work unit (plan T8, §2) — the
 * Auditor stand-in primitive behind `scripts/verify-receipts.sh`, and the
 * seam the proof panel (MU) and the Auditor agent (direction B) reuse.
 *
 * Deliberately a subpath export (`@forestrie/think-scribe/forestrie/receipt`),
 * NOT re-exported from the package index: it pulls @forestrie/receipt-verify
 * (and transitively chain-rpc), which the Scribe worker bundle never needs —
 * the DO only collects receipt bytes, it does not verify them.
 *
 * Trust model (cut 1): "known log key" (FOR-297). The agent's data log is
 * owned by the agent key itself (provision.sh `grant`), so the receipt's
 * delegation certificate is verified under the agent's ES256 public key and
 * the sealer key extracted from it — fully offline, log absent. The binding
 * "this key owns that log" is asserted by key provenance (obtain publicKeyXY
 * out of band, e.g. from GET /identity at enrolment time — not from the same
 * export you are auditing); the genesis-trust-root walk is a later rung.
 */
import {
	checkDelegationConstraints,
	decodeForestrieGrantCose,
	entryIdHexToIdtimestampBe8,
	importEs256PublicKeyFromGrantDataXy64,
	parseReceipt,
	univocityLeafHash,
	verifyGrantReceiptOfflineWithKeys,
	verifyReceiptOfflineWithKeys
} from '@forestrie/receipt-verify';
import {
	PAYLOAD_DELEGATED_KEY,
	decodeDelegatedCoseKeyFromBytes,
	parseDelegatedCoseKeyFromPayload,
	parseDelegationCertificate,
	verifyDelegationCertificateKs256
} from '@forestrie/delegation-cose';
import { calculateRoot, verifyInclusion, type Hasher } from '@forestrie/merklelog';
import { verifyCoseSign1WithParsedKey } from '@forestrie/encoding';
import { cborDecode, cborEncode, type CborMap } from './cbor.ts';
import { sha256Hex } from '../attestation.ts';

const ALG = 1;
const KID = 4;
const ES256 = -7;

export class ReceiptError extends Error {}

/** A COSE Sign1 signed statement, opened for inspection and verification. */
export interface ParsedStatement {
	protectedHeader: CborMap;
	/** Signer kid from the protected header (agent: x-coordinate first-32). */
	kid: Uint8Array;
	payload: Uint8Array;
	/** The work-statement JSON claims, if the payload parses as JSON. */
	payloadJson: Record<string, unknown> | null;
	signature: Uint8Array;
	/** Sig_structure bytes — what the signature is actually over. */
	sigStructure: Uint8Array;
}

export function parseSignedStatement(statement: Uint8Array): ParsedStatement {
	let decoded;
	try {
		decoded = cborDecode(statement);
	} catch (err) {
		throw new ReceiptError(`statement is not decodable CBOR: ${err}`);
	}
	if (!Array.isArray(decoded) || decoded.length !== 4)
		throw new ReceiptError('statement is not a COSE Sign1 4-array');
	const [protectedBytes, , payload, signature] = decoded;
	if (
		!(protectedBytes instanceof Uint8Array) ||
		!(payload instanceof Uint8Array) ||
		!(signature instanceof Uint8Array)
	)
		throw new ReceiptError('statement protected/payload/signature must be byte strings');

	const header = cborDecode(protectedBytes);
	if (!(header instanceof Map) || header.get(ALG) !== ES256)
		throw new ReceiptError('statement alg must be ES256 (-7)');
	const kid = header.get(KID);
	if (!(kid instanceof Uint8Array)) throw new ReceiptError('statement kid must be a byte string');

	let payloadJson: Record<string, unknown> | null = null;
	try {
		const parsed: unknown = JSON.parse(new TextDecoder().decode(payload));
		if (parsed && typeof parsed === 'object' && !Array.isArray(parsed))
			payloadJson = parsed as Record<string, unknown>;
	} catch {
		// Non-JSON payloads are legal COSE; binding checks will just fail.
	}

	const sigStructure = cborEncode(['Signature1', protectedBytes, new Uint8Array(0), payload]);
	return { protectedHeader: header, kid, payload, payloadJson, signature, sigStructure };
}

/** Verify the agent's ES256 signature on a parsed statement (T5). */
export async function verifyStatementSignature(
	parsed: ParsedStatement,
	publicKeyXY: Uint8Array
): Promise<boolean> {
	if (publicKeyXY.length !== 64) throw new ReceiptError('agent public key must be 64 bytes x‖y');
	const point = new Uint8Array(65);
	point[0] = 0x04;
	point.set(publicKeyXY, 1);
	const key = await crypto.subtle.importKey(
		'raw',
		point as BufferSource,
		{ name: 'ECDSA', namedCurve: 'P-256' },
		false,
		['verify']
	);
	return crypto.subtle.verify(
		{ name: 'ECDSA', hash: 'SHA-256' },
		key,
		parsed.signature as BufferSource,
		parsed.sigStructure as BufferSource
	);
}

/**
 * One work unit as the Scribe exports it (`GET /receipts`). Everything the
 * auditor needs travels together; `currentOutputText` is what the DO
 * *currently* claims the assistant said for this turn's leaf — recomputed
 * live from its session store at export time, which is exactly the field
 * the tamper beat drives apart from the receipted commitment.
 */
export interface WorkExport {
	workId: string;
	state: string;
	envelopeB64: string;
	statementB64?: string;
	entryId?: string;
	receiptB64?: string;
	leafId?: string;
	currentOutputText?: string | null;
	/** O4 separate mode: the envelope's own leaf on the user's log (M5). */
	userLeaf?: UserLeafExport | null;
}

export interface UserLeafExport {
	state: string;
	entryId?: string;
	receiptB64?: string;
	error?: string;
}

export interface WorkCheck {
	name: string;
	ok: boolean;
	detail?: string;
}

export interface WorkVerifyResult {
	ok: boolean;
	checks: WorkCheck[];
}

function decodeBase64(value: string): Uint8Array {
	const bin = atob(value);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

/**
 * Verify one receipted work unit fully offline. Checks, in dependency order:
 *
 *  1. statement-signature — the agent's ES256 COSE Sign1 verifies under the
 *     caller-trusted key, and the statement kid matches it.
 *  2. receipt — inclusion proof + sealed checkpoint + delegation certificate
 *     verify under the same key as log owner (known-log-key rung).
 *  3. work-binding — workId = SHA-256(user envelope); the committed
 *     statement names that workId and embeds that exact envelope (§7).
 *  4. transcript-binding — SHA-256 of the DO's currently-claimed output text
 *     equals the committed outputHash. This is the check the tamper beat
 *     breaks: rewrite the DO's memory and the receipts no longer match.
 */
export async function verifyWorkReceipt(
	work: WorkExport,
	agentPublicKeyXY: Uint8Array,
	/** The user's 20-byte wallet address — trust root for the user leaf (O4). */
	userAddress20?: Uint8Array | null
): Promise<WorkVerifyResult> {
	const checks: WorkCheck[] = [];
	const fail = (name: string, detail: string): WorkVerifyResult => {
		checks.push({ name, ok: false, detail });
		return { ok: false, checks };
	};

	if (!work.statementB64 || !work.receiptB64 || !work.entryId)
		return fail(
			'artifacts',
			`work ${work.workId.slice(0, 12)}… is not receipted (state=${work.state})`
		);

	let parsed: ParsedStatement;
	const statement = decodeBase64(work.statementB64);
	try {
		parsed = parseSignedStatement(statement);
	} catch (err) {
		return fail('statement-signature', String(err));
	}
	const kidHex = [...parsed.kid].map((b) => b.toString(16).padStart(2, '0')).join('');
	const keyXHex = [...agentPublicKeyXY.slice(0, parsed.kid.length)]
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
	const sigOk = kidHex === keyXHex && (await verifyStatementSignature(parsed, agentPublicKeyXY));
	checks.push({
		name: 'statement-signature',
		ok: sigOk,
		detail: sigOk ? `kid ${kidHex.slice(0, 16)}…` : 'agent signature/kid mismatch'
	});

	let receiptOk = false;
	let receiptDetail: string;
	try {
		const result = await verifyReceiptOfflineWithKeys({
			receiptCbor: decodeBase64(work.receiptB64),
			payload: statement,
			idtimestampBe8: entryIdHexToIdtimestampBe8(work.entryId),
			trustKeys: [await importEs256PublicKeyFromGrantDataXy64(agentPublicKeyXY)]
		});
		receiptOk = result.ok;
		receiptDetail = result.ok
			? `entry ${work.entryId}`
			: `${result.stage}: ${result.reason ?? 'failed'}`;
	} catch (err) {
		receiptDetail = String(err);
	}
	checks.push({ name: 'receipt', ok: receiptOk, detail: receiptDetail });

	const envelope = decodeBase64(work.envelopeB64);
	const claims = parsed.payloadJson ?? {};
	const workIdOk =
		(await sha256Hex(envelope)) === work.workId &&
		claims.workId === work.workId &&
		claims.userEnvelope === work.envelopeB64;
	checks.push({
		name: 'work-binding',
		ok: workIdOk,
		detail: workIdOk
			? `workId ${work.workId.slice(0, 16)}…`
			: 'workId/envelope do not match the committed statement'
	});

	if (work.userLeaf) {
		const userChecks = await verifyUserLeafReceipt(
			work.envelopeB64,
			work.userLeaf,
			userAddress20 ?? null
		);
		checks.push(...userChecks.checks);
	}

	if (typeof work.currentOutputText === 'string') {
		const currentHash = await sha256Hex(new TextEncoder().encode(work.currentOutputText));
		const outputOk = currentHash === claims.outputHash;
		checks.push({
			name: 'transcript-binding',
			ok: outputOk,
			detail: outputOk
				? `outputHash ${currentHash.slice(0, 16)}…`
				: `DO claims ${currentHash.slice(0, 16)}… but the receipted statement commits ${String(claims.outputHash).slice(0, 16)}… — the record has been tampered`
		});
	} else {
		checks.push({
			name: 'transcript-binding',
			ok: true,
			detail: 'skipped — no current transcript claim in the export'
		});
	}

	return { ok: checks.every((c) => c.ok), checks };
}

/**
 * Payment-policy flag predicates on the 8-byte grant flag field, mirroring
 * `@forestrie/grant-builder` `requiresChildPayment` (adr-0062): GF_DERIVED is
 * canopy wire byte 3 mask 0x04 (univocity bit 34), GF_CHILD_PAYMENT_REQUIRED
 * byte 3 mask 0x08 (bit 35). The policy holds only when BOTH are set.
 */
function requiresChildPaymentFlags(grantFlags: Uint8Array): boolean {
	const b3 = grantFlags[3] ?? 0;
	return (b3 & 0x04) !== 0 && (b3 & 0x08) !== 0;
}

export interface ParentPolicyResult {
	ok: boolean;
	/** The decoded parent's payment policy bit (the demo's honesty beat). */
	requiresChildPayment: boolean;
	/** The parent (authority) log the grant creates, canonical uuid. */
	authorityLogId: string;
	checks: WorkCheck[];
}

/** Decode base64 (standard or url-safe, as grant b64 travels) to bytes. */
function decodeGrantBase64(value: string): Uint8Array {
	return decodeBase64(value.replace(/-/g, '+').replace(/_/g, '/'));
}

/**
 * Offline proof that a user grant's PARENT carries the payment policy
 * (plan-2608-09 W4d, ARC-0029 §2): decode the completed user-authority
 * creation grant, read `requiresChildPayment` off its flag bytes, and verify
 * its inclusion receipt under the forest ROOT key (the parent registered
 * into the root log, so the root K(L) anchors its delegation certificate —
 * the same "known log key" rung as the agent leaf). Together: "payment is
 * required for user grants" is a receipt-provable fact of the log, not an
 * operator claim.
 */
export async function verifyParentPolicyOffline(
	parentGrantB64: string,
	rootPublicKeyXY: Uint8Array
): Promise<ParentPolicyResult> {
	const checks: WorkCheck[] = [];
	const done = (requiresChildPayment: boolean, authorityLogId = ''): ParentPolicyResult => ({
		ok: checks.every((c) => c.ok),
		requiresChildPayment,
		authorityLogId,
		checks
	});

	let bytes: Uint8Array;
	let grant: ReturnType<typeof decodeForestrieGrantCose>['grant'];
	let idtimestampBe8: Uint8Array;
	try {
		bytes = decodeGrantBase64(parentGrantB64);
		({ grant, idtimestampBe8 } = decodeForestrieGrantCose(bytes));
	} catch (err) {
		checks.push({ name: 'parent-grant', ok: false, detail: `undecodable: ${err}` });
		return done(false);
	}
	const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
	const logIdHex = hex(grant.logId);
	const authorityLogId = `${logIdHex.slice(0, 8)}-${logIdHex.slice(8, 12)}-${logIdHex.slice(12, 16)}-${logIdHex.slice(16, 20)}-${logIdHex.slice(20)}`;
	const bit = requiresChildPaymentFlags(grant.grant);
	checks.push({
		name: 'parent-policy',
		ok: true,
		detail: bit
			? `parent ${authorityLogId} carries requiresChildPayment (flags ${hex(grant.grant)})`
			: `parent ${authorityLogId} has NO payment policy (flags ${hex(grant.grant)})`
	});

	// The completed grant carries its own inclusion receipt (unprotected 396).
	const decoded = cborDecode(bytes);
	const unprotected = Array.isArray(decoded) ? decoded[1] : undefined;
	const receiptCbor = unprotected instanceof Map ? unprotected.get(396) : undefined;
	if (!(receiptCbor instanceof Uint8Array)) {
		checks.push({
			name: 'parent-receipt',
			ok: false,
			detail: 'grant carries no inclusion receipt (unprotected header 396)'
		});
		return done(bit, authorityLogId);
	}
	try {
		const result = await verifyGrantReceiptOfflineWithKeys({
			receiptCbor,
			grant,
			idtimestampBe8,
			trustKeys: [await importEs256PublicKeyFromGrantDataXy64(rootPublicKeyXY)]
		});
		checks.push({
			name: 'parent-receipt',
			ok: result.ok,
			detail: result.ok
				? 'inclusion receipt verifies under the forest root key'
				: `${result.stage}: ${result.reason ?? 'failed'}`
		});
	} catch (err) {
		checks.push({ name: 'parent-receipt', ok: false, detail: String(err) });
	}
	return done(bit, authorityLogId);
}

/** Browser/worker-safe SHA-256 Hasher for the merklelog proof math. */
function subtleHasher(): Hasher {
	let chunks: Uint8Array[] = [];
	return {
		reset() {
			chunks = [];
		},
		update(data: Uint8Array) {
			chunks.push(data);
		},
		async digest() {
			let total = 0;
			for (const c of chunks) total += c.length;
			const buf = new Uint8Array(total);
			let offset = 0;
			for (const c of chunks) {
				buf.set(c, offset);
				offset += c.length;
			}
			chunks = [];
			return new Uint8Array(await crypto.subtle.digest('SHA-256', buf as BufferSource));
		}
	};
}

/**
 * Offline verification of the USER's leaf (O4 separate mode, M5): the signed
 * envelope registered under `grant_user` on a log OWNED by the user's wallet
 * key. `@forestrie/receipt-verify`'s delegation resolution is ES256-only
 * ("KS256-rooted delegation is a server-only concern"), so this walks the
 * KS256 rung explicitly with the same published primitives:
 *
 *  1. the receipt's label-1000 delegation certificate verifies under the
 *     USER's address (delegation-cose KS256 EOA recovery) — the wallet, and
 *     only the wallet, authorized the sealer for this log;
 *  2. the certificate's coverage/expiry window admits the leaf
 *     (checkDelegationConstraints — leaf time, never wall-clock);
 *  3. the receipt COSE Sign1 verifies under the DELEGATED sealer key;
 *  4. the leaf `H(idtimestamp ‖ H(envelope))` is included under the signed
 *     peak (merklelog inclusion).
 *
 * Trust root = the user's wallet address, exactly as the agent leaf's root
 * is the agent key ("known log key" rung, FOR-297).
 */
export async function verifyUserLeafReceipt(
	envelopeB64: string,
	userLeaf: UserLeafExport,
	userAddress20: Uint8Array | null
): Promise<WorkVerifyResult> {
	const checks: WorkCheck[] = [];
	const fail = (name: string, detail: string): WorkVerifyResult => {
		checks.push({ name, ok: false, detail });
		return { ok: false, checks };
	};

	if (userLeaf.state !== 'receipted' || !userLeaf.receiptB64 || !userLeaf.entryId) {
		checks.push({
			name: 'user-leaf',
			ok: true,
			detail: `skipped — user leaf is ${userLeaf.state}${userLeaf.error ? ` (${userLeaf.error})` : ''}, not verifiable yet`
		});
		return { ok: true, checks };
	}
	if (!userAddress20 || userAddress20.length !== 20)
		return fail('user-leaf', 'no user wallet address to anchor trust');

	const receiptCbor = decodeBase64(userLeaf.receiptB64);
	let parsed: ReturnType<typeof parseReceipt>;
	try {
		parsed = parseReceipt(receiptCbor);
	} catch (err) {
		return fail('user-leaf-receipt', `receipt malformed: ${err}`);
	}

	// 1. KS256 delegation certificate under the user's wallet address.
	const unprotectedHeader = parsed.coseSign1[1];
	const headerMap =
		unprotectedHeader instanceof Map
			? unprotectedHeader
			: new Map(Object.entries(unprotectedHeader ?? {}).map(([k, v]) => [Number(k), v]));
	const certificate = headerMap.get(1000);
	if (!(certificate instanceof Uint8Array))
		return fail('user-leaf-delegation', 'receipt carries no delegation certificate (label 1000)');
	// No initializer: every path out of the catch returns, so TS's control-flow
	// analysis proves this is assigned before use, and there is no dead `false`
	// for a reader to mistake for a default.
	let certOk: boolean;
	try {
		certOk = await verifyDelegationCertificateKs256(certificate, userAddress20);
	} catch (err) {
		return fail('user-leaf-delegation', `certificate verification failed: ${err}`);
	}
	let addrHex = '';
	for (const b of userAddress20) addrHex += b.toString(16).padStart(2, '0');
	checks.push({
		name: 'user-leaf-delegation',
		ok: certOk,
		detail: certOk
			? `sealer authorized by wallet 0x${addrHex}`
			: "delegation certificate does not verify under the user's wallet"
	});
	if (!certOk) return { ok: false, checks };

	// Delegated sealer key from the certificate payload (label 5) — either an
	// embedded-bytes COSE key or (as the lane emits) an inline COSE key map
	// {1: kty, -1: crv, -2: x, -3: y}.
	const certDecoded = cborDecode(certificate);
	if (!Array.isArray(certDecoded) || !(certDecoded[2] instanceof Uint8Array))
		return fail('user-leaf-delegation', 'certificate is not a COSE Sign1');
	const certPayload = cborDecode(certDecoded[2]);
	const delegatedKeyRaw =
		certPayload instanceof Map ? certPayload.get(PAYLOAD_DELEGATED_KEY) : undefined;
	let delegated: { x: Uint8Array; y: Uint8Array };
	if (delegatedKeyRaw instanceof Uint8Array) {
		delegated = parseDelegatedCoseKeyFromPayload(decodeDelegatedCoseKeyFromBytes(delegatedKeyRaw));
	} else if (delegatedKeyRaw instanceof Map) {
		const x = delegatedKeyRaw.get(-2);
		const y = delegatedKeyRaw.get(-3);
		if (
			!(x instanceof Uint8Array) ||
			!(y instanceof Uint8Array) ||
			x.length !== 32 ||
			y.length !== 32
		)
			return fail('user-leaf-delegation', 'delegated COSE key map lacks 32-byte x/y');
		delegated = { x, y };
	} else {
		return fail('user-leaf-delegation', 'certificate carries no delegated key (label 5)');
	}

	// 2. Coverage/expiry window against the leaf (leaf time, not wall-clock).
	const idtimestampBe8 = entryIdHexToIdtimestampBe8(userLeaf.entryId);
	let idtimestamp = 0n;
	for (const b of idtimestampBe8) idtimestamp = (idtimestamp << 8n) | BigInt(b);
	const info = parseDelegationCertificate(certificate);
	const leafMmrIndex = parsed.proof.mmrIndex ?? parsed.proof.leafIndex ?? 0n;
	const window = checkDelegationConstraints(
		{
			mmrStart: BigInt(info.mmrStart),
			mmrEnd: BigInt(info.mmrEnd),
			issuedAt: info.issuedAt,
			expiresAt: info.expiresAt
		},
		leafMmrIndex,
		idtimestamp
	);
	checks.push({
		name: 'user-leaf-window',
		ok: window.ok,
		detail: window.ok ? `leaf ${leafMmrIndex} within certificate window` : window.reason
	});
	if (!window.ok) return { ok: false, checks };

	// 3+4. Receipt signature under the delegated key; inclusion under the peak.
	const hasher = subtleHasher();
	const envelope = decodeBase64(envelopeB64);
	const inner = new Uint8Array(await crypto.subtle.digest('SHA-256', envelope as BufferSource));
	const leafHash = await univocityLeafHash(idtimestampBe8, inner);
	const leafIdx = parsed.proof.leafIndex ?? parsed.proof.mmrIndex ?? 0n;
	const peak =
		parsed.explicitPeak !== null
			? parsed.explicitPeak
			: await calculateRoot(hasher, leafHash, parsed.proof, leafIdx);
	const sealerKey = { x: delegated.x, y: delegated.y, curve: 'P-256' as const };
	let sigOk = await verifyCoseSign1WithParsedKey(receiptCbor, sealerKey, {
		detachedPayload: peak
	});
	if (!sigOk && parsed.explicitPeak !== null)
		sigOk = await verifyCoseSign1WithParsedKey(receiptCbor, sealerKey);
	checks.push({
		name: 'user-leaf-signature',
		ok: sigOk,
		detail: sigOk
			? `entry ${userLeaf.entryId}`
			: 'receipt signature does not verify under the delegated sealer key'
	});
	if (!sigOk) return { ok: false, checks };

	const inclusionOk = await verifyInclusion(hasher, leafHash, parsed.proof, peak);
	checks.push({
		name: 'user-leaf-inclusion',
		ok: inclusionOk,
		detail: inclusionOk
			? 'envelope leaf included under the sealed peak'
			: 'inclusion proof failed — the user leaf is not under the signed peak'
	});

	return { ok: checks.every((c) => c.ok), checks };
}
