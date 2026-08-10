import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from './utils.ts';

const STORAGE_KEY = 'scribe:demo-wallet-key';

function eip191Digest(message: string): Uint8Array {
	const body = new TextEncoder().encode(message);
	const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
	const data = new Uint8Array(prefix.length + body.length);
	data.set(prefix);
	data.set(body, prefix.length);
	return keccak_256(data);
}

/**
 * The demo wallet (plan §4): a browser-resident secp256k1 key standing in
 * for the user's real wallet, persisted in localStorage so the same user
 * (and so the same DO instance, `user-<address>`) returns across reloads.
 * It signs everything the wcc-1 choreography needs — the session challenge
 * (EIP-191), the per-turn input envelope (KS256 COSE), and the sealing
 * delegation for the user's own log — all client-side; neither the worker
 * nor the DO ever sees the key.
 */
export class DemoWallet {
	#priv: Uint8Array;
	/** Lowercase 0x address — the wcc-1 principal `sub` and the COSE kid. */
	address = $state('');

	constructor() {
		const stored = typeof localStorage !== 'undefined' ? localStorage.getItem(STORAGE_KEY) : null;
		if (stored && /^[0-9a-f]{64}$/.test(stored)) {
			this.#priv = hexToBytes(stored);
		} else {
			this.#priv = crypto.getRandomValues(new Uint8Array(32));
			localStorage?.setItem(STORAGE_KEY, bytesToHex(this.#priv));
		}
		this.address = this.#deriveAddress();
	}

	#deriveAddress(): string {
		const pub = secp256k1.getPublicKey(this.#priv, false);
		return `0x${bytesToHex(keccak_256(pub.slice(1)).slice(-20))}`;
	}

	/** The 20 address bytes — the trust root for user-leaf verification. */
	addressBytes(): Uint8Array {
		return hexToBytes(this.address);
	}

	/** Forget this identity and mint a fresh one (a brand-new DO instance). */
	reset(): void {
		this.#priv = crypto.getRandomValues(new Uint8Array(32));
		localStorage?.setItem(STORAGE_KEY, bytesToHex(this.#priv));
		this.address = this.#deriveAddress();
	}

	/**
	 * EIP-191 personal_sign over a UTF-8 message → 65-byte r‖s‖v hex with
	 * v = 27/28, the layout the worker's wcc-1 verifier recovers.
	 */
	signPersonal(message: string): string {
		const recovered = secp256k1.sign(eip191Digest(message), this.#priv, {
			format: 'recovered',
			prehash: false
		});
		const sig = new Uint8Array(65);
		sig.set(recovered.slice(1), 0);
		sig[64] = recovered[0]! + 27;
		return `0x${bytesToHex(sig)}`;
	}

	/**
	 * Raw keccak-digest signature → 65-byte r‖s‖recovery (recovery raw 0/1,
	 * NOT +27) — the canopy KS256 COSE signature layout.
	 */
	signDigestKs256(digest: Uint8Array): Uint8Array {
		const recovered = secp256k1.sign(digest, this.#priv, {
			format: 'recovered',
			prehash: false
		});
		const sig = new Uint8Array(65);
		sig.set(recovered.slice(1), 0);
		sig[64] = recovered[0]!;
		return sig;
	}

	/**
	 * The raw key hex — needed ONLY by delegateSealingKs256 (the published
	 * delegation-cose builders take the key, not a signer callback). Scoped
	 * to that call; nothing else reads it.
	 */
	privateKeyHex(): string {
		return bytesToHex(this.#priv);
	}
}
