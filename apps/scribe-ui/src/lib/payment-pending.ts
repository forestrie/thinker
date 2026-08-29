/**
 * Recognise the grant authority's "issuance pending" answer in the error
 * message the browser receives. The chain is long and lossy — authority 504
 * JSON → GrantRequestError message (sliced to 200) → the DO's problem relay →
 * ScribeApiError text (sliced to 300) — so this lives as a pure, tested
 * module: the test pins the exact wire string against any future change to
 * those slices or status mappings. Pending is NOT a failure: registration and
 * settled payment are persisted at the authority, and a retry resumes them.
 */
export function isPendingIssuance(message: string): boolean {
	return /"pending":\s*true|registration still pending/.test(message);
}
