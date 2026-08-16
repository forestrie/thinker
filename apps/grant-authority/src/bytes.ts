/**
 * Byte helpers. The local service used Node's `Buffer` throughout; workerd has
 * no Buffer, so these are the same three conversions the Scribe already carries
 * (packages/think-scribe/src/forestrie/delegate.ts) rather than a new idiom.
 */

export function b64ToBytes(b64: string): Uint8Array {
	// Node's Buffer accepted both standard and url-safe base64; atob does not,
	// and grants travel in both forms depending on who minted them.
	const normalised = b64.replace(/-/g, '+').replace(/_/g, '/');
	const padded = normalised + '='.repeat((4 - (normalised.length % 4)) % 4);
	const bin = atob(padded);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

export function bytesToB64(bytes: Uint8Array): string {
	let bin = '';
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
}

export function bytesToHex(bytes: Uint8Array): string {
	let out = '';
	for (const b of bytes) out += b.toString(16).padStart(2, '0');
	return out;
}

export function hexToBytes(hex: string): Uint8Array {
	const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
	const out = new Uint8Array(clean.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
	return out;
}
