import {
	assembleSessionKeyEndorsement,
	buildSessionKeyEndorsementTbs,
	spkiToPublicKeyXY,
	webauthnSignatureToP1363LowS
} from '@forestrie/think-scribe/forestrie/passkey';
import type { WebauthnAssertionResult } from '@forestrie/think-scribe/forestrie/delegate';
import { bytesToB64, bytesToHex } from './utils.ts';

const DB_NAME = 'scribe-passkey';
const STORE = 'keys';
const RECORD_KEY = 'current';

interface PasskeyRecord {
	/** rawId of the credential — names the key to `navigator.credentials.get`. */
	credentialId: ArrayBuffer;
	/** The passkey's 64-byte P-256 x‖y — the user's LOG ROOT (grantData). */
	publicKeyXY: Uint8Array;
	/**
	 * The cached session-key endorsement (ADR-0064): ONE onboarding gesture,
	 * ever — the artifact is durable by design (offline verifiers hold it
	 * forever via /receipts), so re-posting it costs nothing. Re-endorsement
	 * happens only when the session key it names changes (rotation).
	 */
	endorsementB64?: string;
	/** Hex x‖y of the session key the cached endorsement signs. */
	endorsedSessionXYHex?: string;
}

/**
 * The user's passkey log root (plan-2608-13 Phase 4.1, ADR-0064): the
 * authenticator's hardware key owns the log and signs CEREMONIES only —
 * every assertion costs a gesture, so the 4a WebCrypto pair stays the
 * silent per-turn signer, demoted to a session key this passkey endorses
 * once. Where no authenticator exists the 4a shape stands unchanged.
 */
export class PasskeyRoot {
	#record: PasskeyRecord | null = null;
	#loading: Promise<PasskeyRecord | null> | null = null;

	/** WebAuthn availability — the 4.1 feature gate (fall back to 4a). */
	static supported(): boolean {
		return typeof PublicKeyCredential !== 'undefined' && !!navigator.credentials;
	}

	/**
	 * Load the stored record — NEVER creates. Creation costs a user gesture
	 * and pins a custody shape, so it happens only through {@link create},
	 * behind the explicit "Activate your log" click (4.3): the pre-4.3
	 * load-or-create here is what silently pinned session roots on browsers
	 * that refused a page-load `credentials.create()`.
	 */
	async ensure(): Promise<PasskeyRecord | null> {
		if (this.#record) return this.#record;
		this.#loading ??= idbGet()
			.then((record) => (this.#record = record))
			.finally(() => {
				this.#loading = null;
			});
		return this.#loading;
	}

	/**
	 * Load-or-create — THE onboarding gesture (4.3). Must be called from a
	 * user activation (browsers refuse `credentials.create()` without one).
	 * A null return means the authenticator refused or produced a non-P-256
	 * credential — the caller offers the 4a fallback rather than taking it.
	 */
	async create(): Promise<PasskeyRecord | null> {
		const existing = await this.ensure();
		if (existing) return existing;
		const record = await createPasskey();
		if (record) {
			await idbPut(record);
			this.#record = record;
		}
		return record;
	}

	async publicKeyXYHex(): Promise<string | null> {
		const record = await this.ensure();
		return record ? bytesToHex(record.publicKeyXY) : null;
	}

	/**
	 * The stored root — the probe for "is this browser under passkey
	 * custody?" (verify paths, delegation dispatch, the 4.3 boot decision).
	 * Null until the activation ceremony has run.
	 */
	async currentPublicKeyXY(): Promise<Uint8Array | null> {
		return (await this.ensure())?.publicKeyXY ?? null;
	}

	/**
	 * One assertion ceremony over a 32-byte challenge — the
	 * `SignWebauthnAssertion` seam `delegateSealingWebauthn` consumes, and
	 * the endorsement gesture below. Signature is returned low-s P1363.
	 */
	async getAssertion(challenge: Uint8Array): Promise<WebauthnAssertionResult> {
		const record = await this.ensure();
		if (!record) throw new Error('no passkey available');
		const credential = (await navigator.credentials.get({
			publicKey: {
				challenge: challenge as BufferSource,
				allowCredentials: [{ type: 'public-key', id: record.credentialId }],
				// The demo requires UV end-to-end (Q3 grant flag; the DO's
				// endorsement default) — ask the authenticator for it outright.
				userVerification: 'required'
			}
		})) as PublicKeyCredential | null;
		if (!credential) throw new Error('assertion ceremony was refused');
		const response = credential.response as AuthenticatorAssertionResponse;
		return {
			authenticatorData: new Uint8Array(response.authenticatorData),
			clientDataJSON: new Uint8Array(response.clientDataJSON),
			signature: webauthnSignatureToP1363LowS(new Uint8Array(response.signature))
		};
	}

	/**
	 * The onboarding endorsement (ADR-0064 §2): the passkey signs the session
	 * key once, in the ADR-0063 envelope with the typed payload. Cached — the
	 * gesture repeats only when the session key changes.
	 */
	async ensureEndorsement(sessionPublicKeyXY: Uint8Array): Promise<string> {
		const record = await this.ensure();
		if (!record) throw new Error('no passkey available');
		const sessionHex = bytesToHex(sessionPublicKeyXY);
		if (record.endorsementB64 && record.endorsedSessionXYHex === sessionHex)
			return record.endorsementB64;

		const tbs = buildSessionKeyEndorsementTbs({
			rootPublicKeyX: record.publicKeyXY.slice(0, 32),
			sessionPublicKeyXY
		});
		const challenge = new Uint8Array(
			await crypto.subtle.digest('SHA-256', tbs.sigStructureBytes as BufferSource)
		);
		const assertion = await this.getAssertion(challenge);
		const endorsementB64 = bytesToB64(
			assembleSessionKeyEndorsement({
				tbs,
				authenticatorData: assertion.authenticatorData,
				clientDataJSON: assertion.clientDataJSON,
				signature: assertion.signature
			})
		);
		record.endorsementB64 = endorsementB64;
		record.endorsedSessionXYHex = sessionHex;
		await idbPut(record);
		return endorsementB64;
	}

	/**
	 * Forget the local record (identity reset). The resident credential may
	 * survive in the authenticator — the platform owns its lifecycle — but a
	 * fresh record means a fresh `create()`, i.e. a new root for the new DO.
	 */
	async reset(): Promise<void> {
		this.#record = null;
		try {
			await idbDelete();
		} catch {
			// A failed delete resurfaces the OLD record next load — harmless,
			// reset is followed by a wallet reset (new DO instance).
		}
	}
}

async function createPasskey(): Promise<PasskeyRecord | null> {
	let credential: PublicKeyCredential | null;
	try {
		credential = (await navigator.credentials.create({
			publicKey: {
				challenge: crypto.getRandomValues(new Uint8Array(32)),
				rp: { name: 'The Scribe' },
				user: {
					id: crypto.getRandomValues(new Uint8Array(16)),
					name: 'scribe-user',
					displayName: 'Scribe user'
				},
				// ES256 only: the log root must be P-256 (ARC-0010 passkey branch).
				pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
				authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' }
			}
		})) as PublicKeyCredential | null;
	} catch {
		// Refused / cancelled / no authenticator — the 4a fallback stands.
		return null;
	}
	if (!credential) return null;
	const response = credential.response as AuthenticatorAttestationResponse;
	// getPublicKey() spares us parsing the attestationObject CBOR; absent on
	// very old runtimes, in which case we treat passkeys as unsupported.
	const spki = typeof response.getPublicKey === 'function' ? response.getPublicKey() : null;
	if (!spki) return null;
	const publicKeyXY = await spkiToPublicKeyXY(new Uint8Array(spki));
	if (!publicKeyXY) return null;
	return { credentialId: credential.rawId, publicKeyXY };
}

// --- IndexedDB plumbing, promisified and failure-tolerant -------------------

function openDb(): Promise<IDBDatabase | null> {
	return new Promise((resolve) => {
		let request: IDBOpenDBRequest;
		try {
			request = indexedDB.open(DB_NAME, 1);
		} catch {
			resolve(null);
			return;
		}
		request.onupgradeneeded = () => request.result.createObjectStore(STORE);
		request.onsuccess = () => resolve(request.result);
		request.onerror = () => resolve(null);
	});
}

async function idbGet(): Promise<PasskeyRecord | null> {
	const db = await openDb();
	if (!db) return null;
	return new Promise((resolve) => {
		const tx = db.transaction(STORE, 'readonly').objectStore(STORE).get(RECORD_KEY);
		tx.onsuccess = () => {
			db.close();
			const value = tx.result as PasskeyRecord | undefined;
			resolve(value && value.publicKeyXY instanceof Uint8Array ? value : null);
		};
		tx.onerror = () => {
			db.close();
			resolve(null);
		};
	});
}

async function idbPut(record: PasskeyRecord): Promise<void> {
	const db = await openDb();
	if (!db) return;
	await new Promise<void>((resolve) => {
		const tx = db.transaction(STORE, 'readwrite').objectStore(STORE).put(record, RECORD_KEY);
		tx.onsuccess = () => {
			db.close();
			resolve();
		};
		tx.onerror = () => {
			db.close();
			resolve();
		};
	});
}

async function idbDelete(): Promise<void> {
	const db = await openDb();
	if (!db) return;
	await new Promise<void>((resolve) => {
		const tx = db.transaction(STORE, 'readwrite').objectStore(STORE).delete(RECORD_KEY);
		tx.onsuccess = () => {
			db.close();
			resolve();
		};
		tx.onerror = () => {
			db.close();
			resolve();
		};
	});
}
