/**
 * Minimal deterministic CBOR encoder — just the subset COSE Sign1 needs
 * (RFC 8949 core deterministic encoding: shortest-form heads, definite
 * lengths). Encode-only by design: the SCRAPI write path never has to
 * parse CBOR (registration responses carry their data in HTTP headers),
 * so a dependency-free ~100 lines beats a bundled decoder.
 */

export type CborValue =
  | number // integers only (float encoding deliberately unsupported)
  | string
  | Uint8Array
  | CborValue[]
  | CborMap;

/** Map with integer keys (COSE headers, CWT claims). Insertion order kept. */
export type CborMap = Map<number, CborValue>;

function head(major: number, arg: number, out: number[]): void {
  if (!Number.isSafeInteger(arg) || arg < 0)
    throw new RangeError(`cbor: unencodable length/int ${arg}`);
  const mt = major << 5;
  if (arg < 24) out.push(mt | arg);
  else if (arg < 0x100) out.push(mt | 24, arg);
  else if (arg < 0x10000) out.push(mt | 25, arg >> 8, arg & 0xff);
  else if (arg < 0x100000000)
    out.push(mt | 26, (arg >>> 24) & 0xff, (arg >>> 16) & 0xff, (arg >>> 8) & 0xff, arg & 0xff);
  else {
    // > 32 bits: split via BigInt for exactness
    const big = BigInt(arg);
    out.push(mt | 27);
    for (let shift = 56n; shift >= 0n; shift -= 8n)
      out.push(Number((big >> shift) & 0xffn));
  }
}

function encodeInto(value: CborValue, out: number[]): void {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new RangeError("cbor: non-integer number");
    if (value >= 0) head(0, value, out);
    else head(1, -1 - value, out);
    return;
  }
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    head(3, bytes.length, out);
    for (const b of bytes) out.push(b);
    return;
  }
  if (value instanceof Uint8Array) {
    head(2, value.length, out);
    for (const b of value) out.push(b);
    return;
  }
  if (Array.isArray(value)) {
    head(4, value.length, out);
    for (const item of value) encodeInto(item, out);
    return;
  }
  // Map — deterministic key order (ascending on the encoded key bytes is the
  // RFC rule; for int keys, numeric ascending with negatives after positives
  // matches it, which sorting on encoded bytes gives us for free).
  const entries = [...value.entries()].map(([k, v]) => {
    const kb: number[] = [];
    encodeInto(k, kb);
    return { kb, v };
  });
  entries.sort((a, b) => {
    const len = Math.min(a.kb.length, b.kb.length);
    for (let i = 0; i < len; i++)
      if (a.kb[i] !== b.kb[i]) return a.kb[i]! - b.kb[i]!;
    return a.kb.length - b.kb.length;
  });
  head(5, entries.length, out);
  for (const { kb, v } of entries) {
    out.push(...kb);
    encodeInto(v, out);
  }
}

export function cborEncode(value: CborValue): Uint8Array {
  const out: number[] = [];
  encodeInto(value, out);
  return Uint8Array.from(out);
}
