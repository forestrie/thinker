import { describe, expect, it } from 'vitest';
import { isPendingIssuance } from './payment-pending.ts';

// The authority's exact pending body (grant-authority issue.ts →
// IssuancePending → index.ts 504 handler).
const AUTHORITY_BODY = JSON.stringify({
	error: 'grant registration still pending — retry to resume',
	pending: true
});

// What the browser's ScribeApiError actually carries after the full chain:
// GrantRequestError wraps the 504 body (sliced to 200), forestrieProblem
// relays String(err) as a 500, expectJson slices to 300.
const grantRequestMessage = `grant authority /grants/user: HTTP 504 ${AUTHORITY_BODY}`.slice(
	0,
	'grant authority /grants/user: HTTP 504 '.length + 200
);
const BROWSER_MESSAGE = `Error: Error: ${grantRequestMessage}`.slice(0, 300);

describe('isPendingIssuance', () => {
	it('matches the exact string the browser receives', () => {
		expect(isPendingIssuance(BROWSER_MESSAGE)).toBe(true);
	});

	it('still matches if the JSON tail were truncated away', () => {
		// The prose alternative sits in the first 60 chars of the body, so it
		// survives any plausible tightening of the slice caps.
		expect(isPendingIssuance('HTTP 504 {"error":"grant registration still pending')).toBe(true);
	});

	it('does not match real failures', () => {
		expect(
			isPendingIssuance('Error: grant authority /grants/user: HTTP 502 {"error":"boom"}')
		).toBe(false);
		expect(isPendingIssuance('payment settlement failed: insufficient funds')).toBe(false);
		expect(isPendingIssuance('')).toBe(false);
	});
});
