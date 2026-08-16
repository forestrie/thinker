/**
 * The hand-rolled deterministic CBOR codec every COSE artifact in the system
 * rests on. These tests pin the two properties the wire format depends on:
 * shortest-form heads (RFC 8949 core deterministic encoding) and deterministic
 * map key ordering. Get either wrong and signatures stop verifying — silently,
 * and only against other implementations.
 */
import { describe, expect, it } from 'vitest';
import { cborDecode, cborEncode, type CborMap } from '../src/forestrie/cbor.ts';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

describe('head encoding — shortest form', () => {
	it.each([
		[0, '00'],
		[23, '17'],
		[24, '1818'],
		[255, '18ff'],
		[256, '190100'],
		[65535, '19ffff'],
		[65536, '1a00010000'],
		[4294967295, '1affffffff'],
		[4294967296, '1b0000000100000000']
	])('encodes uint %i as %s', (value, expected) => {
		expect(hex(cborEncode(value))).toBe(expected);
	});

	it.each([
		[-1, '20'],
		[-24, '37'],
		[-25, '3818'],
		// KS256 — the alg every user envelope carries.
		[-65799, '3a00010106']
	])('encodes negative %i as %s', (value, expected) => {
		expect(hex(cborEncode(value))).toBe(expected);
	});
});

describe('deterministic map ordering', () => {
	it('sorts integer keys ascending regardless of insertion order', () => {
		const m: CborMap = new Map();
		m.set(4, 0);
		m.set(1, 0);
		m.set(3, 0);
		// a3 = map(3), then keys in order 01, 03, 04
		expect(hex(cborEncode(m))).toBe('a3010003000400');
	});

	it('orders positive keys before negative ones (encoded-byte order)', () => {
		const m: CborMap = new Map();
		m.set(-7, 0);
		m.set(1, 0);
		// map(2)=a2, then key 01 -> value 00, key 26 (-7) -> value 00
		expect(hex(cborEncode(m))).toBe('a201002600');
	});

	it('is insertion-order independent', () => {
		const a: CborMap = new Map([
			[1, 'x'],
			[2, 'y']
		]);
		const b: CborMap = new Map([
			[2, 'y'],
			[1, 'x']
		]);
		expect(hex(cborEncode(a))).toBe(hex(cborEncode(b)));
	});
});

describe('round-trip', () => {
	it('survives a nested array/map/bstr/tstr structure', () => {
		const value = [
			'Signature1',
			new Uint8Array([1, 2, 3]),
			new Map<number, unknown>([
				[1, -7],
				[4, new Uint8Array(32)]
			]),
			[0, 23, 24, -1]
		];
		expect(cborDecode(cborEncode(value as never))).toEqual(value);
	});

	it('round-trips the empty map and empty bstr', () => {
		expect(cborDecode(cborEncode(new Map()))).toEqual(new Map());
		expect(cborDecode(cborEncode(new Uint8Array(0)))).toEqual(new Uint8Array(0));
	});
});

describe('encoder rejections', () => {
	it.each([
		['a float', 1.5],
		['NaN', Number.NaN],
		['a value above MAX_SAFE_INTEGER', Number.MAX_SAFE_INTEGER + 2]
	])('throws RangeError on %s', (_label, value) => {
		expect(() => cborEncode(value)).toThrow(RangeError);
	});
});

describe('decoder rejections', () => {
	it('rejects trailing bytes after the top-level item', () => {
		expect(() => cborDecode(new Uint8Array([0x00, 0x00]))).toThrow(/trailing bytes/);
	});

	it('rejects truncated input', () => {
		// 0x41 = bstr of length 1, but no payload byte follows.
		expect(() => cborDecode(new Uint8Array([0x41]))).toThrow(/truncated/);
	});

	it('rejects indefinite-length items (additional info 31)', () => {
		expect(() => cborDecode(new Uint8Array([0x5f]))).toThrow(/unsupported additional info/);
	});

	it('rejects major type 7 (float/simple)', () => {
		expect(() => cborDecode(new Uint8Array([0xf5]))).toThrow(/unsupported major type/);
	});

	it('rejects non-integer map keys', () => {
		// a1 (map(1)) 61 61 ("a") 00 — a text key
		expect(() => cborDecode(new Uint8Array([0xa1, 0x61, 0x61, 0x00]))).toThrow(
			/only integer map keys/
		);
	});

	it('rejects 64-bit values above MAX_SAFE_INTEGER', () => {
		const bytes = new Uint8Array([0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
		expect(() => cborDecode(bytes)).toThrow(/exceeds safe integer/);
	});
});
