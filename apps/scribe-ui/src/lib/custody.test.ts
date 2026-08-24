import { describe, expect, it } from 'vitest';
import { bootRegistration } from './custody.ts';

describe('the 4.3 boot decision', () => {
	// THE tripwire 4.3 kills: WebAuthn available + no passkey yet must defer.
	// A bare post here would TOFU-pin session custody and force an identity
	// reset to ever upgrade (ADR-0064 consequences).
	it('never bare-posts when a passkey could still be created', () => {
		expect(bootRegistration({ webauthnSupported: true, hasPasskeyRecord: false })).toBe('defer');
	});

	it('re-posts the endorsed shape silently when the passkey exists', () => {
		expect(bootRegistration({ webauthnSupported: true, hasPasskeyRecord: true })).toBe(
			'endorsed-post'
		);
	});

	it('falls back to the 4a session root only where WebAuthn cannot exist', () => {
		expect(bootRegistration({ webauthnSupported: false, hasPasskeyRecord: false })).toBe(
			'bare-post'
		);
	});

	// A record with no WebAuthn support is a degraded runtime (or a wiped
	// feature flag); the record names the pinned root, so still post endorsed —
	// assertions will fail loudly rather than silently re-rooting.
	it('prefers the record over the support probe', () => {
		expect(bootRegistration({ webauthnSupported: false, hasPasskeyRecord: true })).toBe(
			'endorsed-post'
		);
	});
});
