/**
 * Minimal deterministic CBOR encoder — just the subset the user envelope
 * needs (unsigned/negative ints, text, bytes, arrays, canonically-sorted
 * maps). Mirrors the encoder the worker-side smoke tests use; the envelope
 * profile is fixed (canopy KS256 COSE Sign1), so a full CBOR library is
 * not warranted client-side.
 */
type CborValue = number | string | Uint8Array | CborValue[] | Map<CborValue, CborValue>;

function head(major: number, arg: number, out: number[]): void {
	const mt = major << 5;
	if (arg < 24) out.push(mt | arg);
	else if (arg < 0x100) out.push(mt | 24, arg);
	else if (arg < 0x10000) out.push(mt | 25, arg >> 8, arg & 0xff);
	else out.push(mt | 26, (arg >>> 24) & 0xff, (arg >>> 16) & 0xff, (arg >>> 8) & 0xff, arg & 0xff);
}

function encodeInto(value: CborValue, out: number[]): number[] {
	if (typeof value === 'number') {
		if (!Number.isSafeInteger(value)) throw new Error('cbor: only integers');
		if (value >= 0) head(0, value, out);
		else head(1, -1 - value, out);
	} else if (typeof value === 'string') {
		const bytes = new TextEncoder().encode(value);
		head(3, bytes.length, out);
		for (const b of bytes) out.push(b);
	} else if (value instanceof Uint8Array) {
		head(2, value.length, out);
		for (const b of value) out.push(b);
	} else if (Array.isArray(value)) {
		head(4, value.length, out);
		for (const item of value) encodeInto(item, out);
	} else if (value instanceof Map) {
		const entries = [...value.entries()].map(([k, v]) => ({ kb: encodeInto(k, []), v }));
		entries.sort((a, b) => {
			const len = Math.min(a.kb.length, b.kb.length);
			for (let i = 0; i < len; i++) if (a.kb[i] !== b.kb[i]) return a.kb[i]! - b.kb[i]!;
			return a.kb.length - b.kb.length;
		});
		head(5, entries.length, out);
		for (const { kb, v } of entries) {
			for (const b of kb) out.push(b);
			encodeInto(v, out);
		}
	} else {
		throw new Error(`cbor: unencodable value`);
	}
	return out;
}

export function cborEncode(value: CborValue): Uint8Array {
	return Uint8Array.from(encodeInto(value, []));
}

/**
 * Matching minimal decoder — enough to open a COSE Sign1 envelope and read
 * its JSON payload for display (ints, bytes, text, arrays, maps).
 */
export function cborDecode(bytes: Uint8Array): unknown {
	let at = 0;
	const arg = (info: number): number => {
		if (info < 24) return info;
		if (info === 24) return bytes[at++]!;
		if (info === 25) {
			const v = (bytes[at]! << 8) | bytes[at + 1]!;
			at += 2;
			return v;
		}
		if (info === 26) {
			const v =
				bytes[at]! * 0x1000000 + ((bytes[at + 1]! << 16) | (bytes[at + 2]! << 8) | bytes[at + 3]!);
			at += 4;
			return v;
		}
		throw new Error('cbor: unsupported length');
	};
	const one = (): unknown => {
		const initial = bytes[at++];
		if (initial === undefined) throw new Error('cbor: truncated');
		const major = initial >> 5;
		const info = initial & 0x1f;
		switch (major) {
			case 0:
				return arg(info);
			case 1:
				return -1 - arg(info);
			case 2: {
				const len = arg(info);
				const out = bytes.slice(at, at + len);
				at += len;
				return out;
			}
			case 3: {
				const len = arg(info);
				const out = new TextDecoder().decode(bytes.slice(at, at + len));
				at += len;
				return out;
			}
			case 4: {
				const len = arg(info);
				const out: unknown[] = [];
				for (let i = 0; i < len; i++) out.push(one());
				return out;
			}
			case 5: {
				const len = arg(info);
				const out = new Map<unknown, unknown>();
				for (let i = 0; i < len; i++) {
					const k = one();
					out.set(k, one());
				}
				return out;
			}
			default:
				throw new Error(`cbor: unsupported major type ${major}`);
		}
	};
	return one();
}

/** The JSON claims inside a COSE Sign1 envelope (display only). */
export function envelopeClaims(envelope: Uint8Array): Record<string, unknown> | null {
	try {
		const decoded = cborDecode(envelope);
		if (!Array.isArray(decoded) || !(decoded[2] instanceof Uint8Array)) return null;
		const parsed: unknown = JSON.parse(new TextDecoder().decode(decoded[2]));
		return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: null;
	} catch {
		return null;
	}
}
