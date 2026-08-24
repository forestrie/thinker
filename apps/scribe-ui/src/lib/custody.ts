/**
 * The 4.3 boot decision (plan-2608-13): what may the page do about the user's
 * log root at load time, with NO user gesture available?
 *
 * A pure predicate rather than a branch in the mount handler because it pins
 * the tripwire 4.3 exists to kill: a browser that supports WebAuthn but has
 * no passkey yet must NEVER have its session key posted as root at page load.
 * That post would TOFU-pin session custody, and the later passkey upgrade
 * needs a full identity reset (ADR-0064 consequences). See custody.test.ts.
 */
export type BootRegistration =
	/** A passkey record exists: re-post the endorsed shape, gesture-free. */
	| 'endorsed-post'
	/** No WebAuthn here, ever: the 4a session root is the only shape. */
	| 'bare-post'
	/**
	 * WebAuthn is available but no passkey exists: declare the custody choice
	 * PENDING to the DO and wait for the explicit "Activate your log" gesture
	 * (or the explicit continue-without-passkey opt-out).
	 */
	| 'defer';

export function bootRegistration(state: {
	webauthnSupported: boolean;
	hasPasskeyRecord: boolean;
}): BootRegistration {
	if (state.hasPasskeyRecord) return 'endorsed-post';
	if (!state.webauthnSupported) return 'bare-post';
	return 'defer';
}
