import type { KeyProvider } from '@forestrie/think-scribe/forestrie/delegate';
import { bytesToHex } from './utils.ts';

const DB_NAME = 'scribe-user-root';
const STORE = 'keys';
const RECORD_KEY = 'current';

/**
 * The user's log root K(L) (plan-2608-13 Phase 4a, Q4 option A): a
 * non-extractable WebCrypto P-256 key held by the browser and nothing else.
 * It replaces the demo wallet as the ROOT of the user's log — the wallet
 * stays for wcc-1 session auth and x402 payment (Q2 custody split) — and is
 * the runtime fallback shape the passkey root (Phase 4.1+) degrades to when
 * no authenticator is available.
 *
 * The pair persists as a CryptoKeyPair in IndexedDB (structured clone keeps
 * the private key non-extractable — there are no scalar bytes to read, here
 * or anywhere). Where IndexedDB is unavailable the pair is ephemeral for the
 * page's lifetime; the DO refuses a second root (TOFU pin), so a lost pair
 * means resetting the identity, which the UI already offers.
 */
export class UserRootKey {
	#pair: CryptoKeyPair | null = null;
	#publicKeyXY: Uint8Array | null = null;
	#loading: Promise<void> | null = null;

	/** Load-or-generate, single-flight. Callers await this via the getters. */
	async #ensure(): Promise<void> {
		if (this.#pair) return;
		this.#loading ??= this.#load().finally(() => {
			this.#loading = null;
		});
		await this.#loading;
	}

	async #load(): Promise<void> {
		let pair = await idbGet();
		if (!pair) {
			pair = await generatePair();
			await idbPut(pair);
		}
		this.#pair = pair;
		this.#publicKeyXY = await exportXY(pair.publicKey);
	}

	/** The 64-byte P-256 public key x‖y — `grantData` for `grant_user`. */
	async publicKeyXY(): Promise<Uint8Array> {
		await this.#ensure();
		return this.#publicKeyXY!;
	}

	async publicKeyXYHex(): Promise<string> {
		return bytesToHex(await this.publicKeyXY());
	}

	/** ECDSA P-256/SHA-256 over `bytes` → 64-byte IEEE P1363 r‖s. */
	async sign(bytes: Uint8Array): Promise<Uint8Array> {
		await this.#ensure();
		const sig = await crypto.subtle.sign(
			{ name: 'ECDSA', hash: 'SHA-256' },
			this.#pair!.privateKey,
			bytes as BufferSource
		);
		return new Uint8Array(sig);
	}

	/**
	 * Forget this root and mint a fresh one — part of the identity reset only:
	 * the DO pins the first root it sees, so a new root needs a new instance.
	 */
	async reset(): Promise<void> {
		this.#pair = null;
		this.#publicKeyXY = null;
		try {
			await idbDelete();
		} catch {
			// A failed delete just means the OLD pair resurfaces on next load —
			// harmless, since reset is followed by a wallet reset (new DO).
		}
	}

	/**
	 * This root as the {@link KeyProvider} seam `delegateSealing` consumes.
	 * Only `signingKeyPair` does real work there; the rest satisfy the
	 * interface honestly. `rotate` is refused: rotating the ROOT means a new
	 * log (the grant names the key), which is the identity-reset flow.
	 */
	async asKeyProvider(): Promise<KeyProvider> {
		await this.#ensure();
		const pair = this.#pair!;
		const xy = this.#publicKeyXY!;
		return {
			kid: () => xy.slice(0, 32),
			publicKeyXY: () => Promise.resolve(xy),
			sign: (bytes: Uint8Array) => this.sign(bytes),
			rotate: () => Promise.reject(new Error('user root does not rotate — reset the identity')),
			signingKeyPair: () => Promise.resolve(pair)
		};
	}
}

async function generatePair(): Promise<CryptoKeyPair> {
	return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
		'sign',
		'verify'
	]);
}

async function exportXY(publicKey: CryptoKey): Promise<Uint8Array> {
	// 65-byte uncompressed point 0x04 ‖ x ‖ y.
	const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
	return raw.slice(1);
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

async function idbGet(): Promise<CryptoKeyPair | null> {
	const db = await openDb();
	if (!db) return null;
	return new Promise((resolve) => {
		const tx = db.transaction(STORE, 'readonly').objectStore(STORE).get(RECORD_KEY);
		tx.onsuccess = () => {
			db.close();
			const value = tx.result as CryptoKeyPair | undefined;
			resolve(value && value.privateKey instanceof CryptoKey ? value : null);
		};
		tx.onerror = () => {
			db.close();
			resolve(null);
		};
	});
}

async function idbPut(pair: CryptoKeyPair): Promise<void> {
	const db = await openDb();
	if (!db) return;
	await new Promise<void>((resolve) => {
		const tx = db.transaction(STORE, 'readwrite').objectStore(STORE).put(pair, RECORD_KEY);
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
