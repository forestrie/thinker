/**
 * Cross-encoder drift guard.
 *
 * There are TWO independently hand-rolled deterministic CBOR encoders in this
 * repo — this one, and packages/think-scribe/src/forestrie/cbor.ts — and they
 * sign the SAME artifact: the browser builds a KS256 user envelope here, and
 * the Scribe DO re-derives the Sig_structure over there to verify it. Nothing
 * noticed if they diverged, and the failure mode is "the DO rejects every turn
 * from the browser" with no obvious cause.
 *
 * These tests assert byte-identical output for the structures that actually
 * ride the wire.
 */
import { describe, expect, it } from 'vitest';
import { cborEncode as uiEncode, cborDecode as uiDecode, envelopeClaims } from './cbor.ts';
import { cborEncode as workerEncode } from '@forestrie/think-scribe/forestrie/cbor';

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

const KS256 = -65799;

describe('agrees with the worker encoder byte-for-byte', () => {
	it('on the KS256 protected header', () => {
		const header = new Map<number, unknown>([
			[1, KS256],
			[3, 'application/json'],
			[4, new Uint8Array(20).fill(0xab)]
		]);
		expect(hex(uiEncode(header as never))).toBe(hex(workerEncode(header as never)));
	});

	it('on the Signature1 Sig_structure', () => {
		const protectedBytes = new Uint8Array([0xa1, 0x01, 0x3a, 0x00, 0x01, 0x01, 0x06]);
		const payload = new TextEncoder().encode('{"input":"hi"}');
		const structure = ['Signature1', protectedBytes, new Uint8Array(0), payload];
		expect(hex(uiEncode(structure as never))).toBe(hex(workerEncode(structure as never)));
	});

	it('on a full COSE Sign1 4-array', () => {
		const sign1 = [
			new Uint8Array([0xa1, 0x01, 0x26]),
			new Map(),
			new TextEncoder().encode('payload'),
			new Uint8Array(65).fill(7)
		];
		expect(hex(uiEncode(sign1 as never))).toBe(hex(workerEncode(sign1 as never)));
	});

	it('on maps whose keys need reordering', () => {
		const m = new Map<number, unknown>([
			[4, new Uint8Array(2)],
			[1, KS256],
			[3, 'text']
		]);
		expect(hex(uiEncode(m as never))).toBe(hex(workerEncode(m as never)));
	});

	it('on the head-size boundaries the envelope can actually hit', () => {
		// 23/24 and 255/256 are where the head encoding changes width; a payload
		// crossing one of these is where a divergent encoder would first show up.
		for (const length of [0, 23, 24, 255, 256, 1000]) {
			const bytes = new Uint8Array(length).fill(1);
			expect(hex(uiEncode(bytes))).toBe(hex(workerEncode(bytes)));
		}
	});
});

describe('round-trip', () => {
	it('decodes what it encodes', () => {
		const value = ['Signature1', new Uint8Array([1, 2, 3]), new Uint8Array(0), 42];
		expect(uiDecode(uiEncode(value as never))).toEqual(value);
	});
});

describe('documented gaps in the UI encoder', () => {
	// The worker encoder guards both of these; this one does not. Pinning
	// CURRENT behaviour so the difference is visible rather than surprising —
	// neither is reachable from the fixed envelope profile.
	it('has no 64-bit head branch (worker encoder does)', () => {
		const big = 2 ** 32;
		expect(hex(workerEncode(big))).toBe('1b0000000100000000');
		expect(hex(uiEncode(big))).not.toBe(hex(workerEncode(big)));
	});

	it('rejects non-integers, like the worker encoder', () => {
		expect(() => uiEncode(1.5)).toThrow(/only integers/);
	});
});

describe('envelopeClaims', () => {
	it('returns null for bytes that are not an envelope', () => {
		expect(envelopeClaims(new Uint8Array([0xff, 0xff]))).toBeNull();
	});
});
