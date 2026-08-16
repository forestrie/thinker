import { describe, expect, it } from 'vitest';
import { b64ToBytes, bytesToB64, bytesToHex, hexToBytes, shortHex } from './utils.ts';

describe('hex codec', () => {
	it('round-trips every byte value', () => {
		const all = Uint8Array.from({ length: 256 }, (_, i) => i);
		expect(hexToBytes(bytesToHex(all))).toEqual(all);
	});

	it('pads single-digit bytes', () => {
		expect(bytesToHex(new Uint8Array([0, 1, 15, 16]))).toBe('00010f10');
	});

	it('tolerates a 0x prefix on decode', () => {
		expect(hexToBytes('0xdeadbeef')).toEqual(hexToBytes('deadbeef'));
	});
});

describe('base64 codec', () => {
	it('round-trips binary that is not valid UTF-8', () => {
		const bytes = new Uint8Array([0x00, 0xff, 0x80, 0x7f, 0xfe]);
		expect(b64ToBytes(bytesToB64(bytes))).toEqual(bytes);
	});

	it('encodes the empty array to the empty string', () => {
		expect(bytesToB64(new Uint8Array(0))).toBe('');
	});
});

describe('shortHex', () => {
	it('passes short values through untouched', () => {
		expect(shortHex('0x1234')).toBe('0x1234');
	});

	it('elides the middle of a long value', () => {
		expect(shortHex(`0x${'ab'.repeat(20)}`)).toBe('0xababab…abab');
	});

	it('omits the tail when tail is 0', () => {
		expect(shortHex(`0x${'ab'.repeat(20)}`, 8, 0)).toBe('0xababab…');
	});
});
