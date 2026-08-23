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

// --- EIP-3009 / x402 payer (plan-2608-09 W4b) ------------------------------
// The browser wallet is the payer in the authority-proxied 402 flow: it signs
// an EIP-3009 `transferWithAuthorization` against canopy's `X-PAYMENT-REQUIRED`
// challenge (USDC on Base Sepolia). Ported from the canopy e2e-kit signer
// (`x402-payer-e2e.ts`, same EIP-712 encoding) — the facilitator submits the
// gasless transfer, so the wallet only signs; no chain call happens here.

interface X402Option {
	scheme: string;
	network: string;
	payTo: string;
	asset: string;
	amount: string;
	maxTimeoutSeconds?: number;
	extra?: { name?: string; version?: string };
}

function encodeUint256(value: bigint): Uint8Array {
	return hexToBytes(value.toString(16).padStart(64, '0'));
}

function encodeAddress(value: string): Uint8Array {
	const bytes = hexToBytes(value);
	const padded = new Uint8Array(32);
	padded.set(bytes, 32 - bytes.length);
	return padded;
}

function hashType(typeString: string): Uint8Array {
	return keccak_256(new TextEncoder().encode(typeString));
}

function concat32(parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.length * 32);
	parts.forEach((p, i) => out.set(p, i * 32));
	return out;
}

/** EIP-712 signing digest for EIP-3009 transferWithAuthorization. */
function transferWithAuthorizationDigest(args: {
	domain: { name: string; version: string; chainId: bigint; verifyingContract: string };
	from: string;
	to: string;
	value: bigint;
	validAfter: bigint;
	validBefore: bigint;
	nonce: string;
}): Uint8Array {
	const domainSeparator = keccak_256(
		concat32([
			hashType(
				'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
			),
			keccak_256(new TextEncoder().encode(args.domain.name)),
			keccak_256(new TextEncoder().encode(args.domain.version)),
			encodeUint256(args.domain.chainId),
			encodeAddress(args.domain.verifyingContract)
		])
	);
	const structHash = keccak_256(
		concat32([
			hashType(
				'TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)'
			),
			encodeAddress(args.from),
			encodeAddress(args.to),
			encodeUint256(args.value),
			encodeUint256(args.validAfter),
			encodeUint256(args.validBefore),
			hexToBytes(args.nonce)
		])
	);
	const combined = new Uint8Array(2 + 32 + 32);
	combined.set([0x19, 0x01], 0);
	combined.set(domainSeparator, 2);
	combined.set(structHash, 34);
	return keccak_256(combined);
}

/**
 * The demo wallet (plan §4): a browser-resident secp256k1 key standing in
 * for the user's real wallet, persisted in localStorage so the same user
 * (and so the same DO instance, `user-<address>`) returns across reloads.
 * Since plan-2608-13 Phase 4a its remit is the Q2 custody split: wcc-1
 * session auth (EIP-191 challenge) and x402 payment (EIP-3009 needs
 * secp256k1 regardless). The user LOG — envelope signing and the sealing
 * delegation — is rooted in the WebCrypto P-256 `UserRootKey` instead; the
 * wallet key signs client-side and never leaves this module.
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
	 * Sign canopy's x402 `X-PAYMENT-REQUIRED` challenge (plan-2608-09 W4b):
	 * decode the `exact` option, sign an EIP-3009 `transferWithAuthorization`
	 * for the demanded USDC amount, and return the `X-PAYMENT` header value
	 * (base64 JSON). The authority resubmits register-grant with it. Mirrors
	 * the canopy e2e-kit `signX402PaymentE2e` payload shape.
	 */
	signX402Payment(challengeB64: string): string {
		const decoded = JSON.parse(atob(challengeB64)) as { accepts?: X402Option[] };
		const chosen = (decoded.accepts ?? []).find((o) => o.scheme === 'exact');
		if (!chosen) throw new Error("X-PAYMENT-REQUIRED has no 'exact' scheme option");
		if (!chosen.extra?.name || !chosen.extra?.version)
			throw new Error('challenge lacks EIP-712 domain name/version in extra');

		const from = this.address;
		const nonce = `0x${bytesToHex(crypto.getRandomValues(new Uint8Array(32)))}`;
		const now = Math.floor(Date.now() / 1000);
		const validAfter = BigInt(now - 600);
		const validBefore = BigInt(now + (chosen.maxTimeoutSeconds ?? 300));

		const digest = transferWithAuthorizationDigest({
			domain: {
				name: chosen.extra.name,
				version: chosen.extra.version,
				chainId: BigInt(chosen.network.split(':')[1]!),
				verifyingContract: chosen.asset
			},
			from,
			to: chosen.payTo,
			value: BigInt(chosen.amount),
			validAfter,
			validBefore,
			nonce
		});
		// r‖s‖v with v = recovery + 27 — the EIP-3009 signature layout the
		// facilitator recovers (same as signPersonal's recovery handling).
		const recovered = secp256k1.sign(digest, this.#priv, { format: 'recovered', prehash: false });
		const sig = new Uint8Array(65);
		sig.set(recovered.slice(1), 0);
		sig[64] = recovered[0]! + 27;

		const payload = {
			x402Version: 2,
			payload: {
				authorization: {
					from,
					to: chosen.payTo,
					value: chosen.amount,
					validAfter: validAfter.toString(),
					validBefore: validBefore.toString(),
					nonce
				},
				signature: `0x${bytesToHex(sig)}`
			},
			resource: {
				url: '',
				description: 'forestrie user grant purchase',
				mimeType: 'application/json'
			},
			accepted: {
				scheme: 'exact',
				network: chosen.network,
				asset: chosen.asset,
				amount: chosen.amount,
				payTo: chosen.payTo,
				maxTimeoutSeconds: chosen.maxTimeoutSeconds ?? 300,
				extra: chosen.extra
			}
		};
		return btoa(JSON.stringify(payload));
	}
}
