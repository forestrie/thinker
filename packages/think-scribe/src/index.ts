export {
	Scribe,
	DEFAULT_MODEL_ID,
	DEFAULT_DEMO_DAILY_TURN_CAP,
	DEFAULT_DEMO_USER_DAILY_TURN_CAP,
	PRINCIPAL_HEADER,
	type ScribeEnv
} from './scribe.ts';
export { DemoBudget } from './demo-budget.ts';
export {
	applyDailyCaps,
	readDailyCaps,
	admit as admitDailyCap,
	peek as peekDailyCap,
	utcDay,
	counterKey,
	parseCap,
	USER_TURNS_PREFIX,
	GLOBAL_TURNS_PREFIX,
	type CounterStore,
	type CapStatus,
	type AdmitResult,
	type CapConfig,
	type CapContext,
	type CapDecision,
	type DailyCapCounters
} from './demo-cap.ts';
export { bytesToHex, hexToBytes, type KeyProvider } from './keys/provider.ts';
export { DoResidentKeyProvider } from './keys/do-resident.ts';
export {
	KmsSeedKeyProvider,
	deriveAgentKey,
	localSeedCustodianMac,
	custodianMacInfo,
	type CustodianMac,
	type DerivedAgentKey
} from './keys/kms-seed.ts';
export { buildSignedStatement } from './forestrie/cose.ts';
export {
	ConfiguredGrantProvider,
	GrantAuthorityClient,
	GrantRequestError,
	StubPaymentProvider,
	type GrantProvider,
	type IssuedGrant,
	type PaymentProvider,
	type UserGrantResult
} from './forestrie/grant.ts';
export {
	fetchReceipt,
	queryRegistration,
	registerStatement,
	ScrapiError,
	type RegisterAccepted,
	type RegistrationStatus,
	type ReceiptStatus
} from './forestrie/register.ts';
export {
	delegateSealing,
	delegateSealingKs256,
	DelegateError,
	type DelegateSealingParams,
	type DelegateSealingResult
} from './forestrie/delegate.ts';
export {
	buildUserEnvelope,
	buildUserEnvelopeEs256,
	verifyUserEnvelope,
	verifyUserEnvelopeEs256,
	verifyAttestedInput,
	verifyAttestedInputEs256,
	userEnvelopeAlg,
	inputCommitment,
	EnvelopeError,
	COSE_ALG_KS256,
	COSE_ALG_ES256,
	INPUT_COMMITMENT_DOMAIN,
	MAX_INPUT_BYTES,
	type EnvelopeClaims,
	type Es256EnvelopeSigner,
	type VerifiedEnvelope,
	type VerifiedEnvelopeEs256
} from './forestrie/envelope.ts';
export {
	buildWorkStatementPayload,
	newSaltHex,
	outputCommitment,
	saltedCommitmentHex,
	sha256Hex,
	OUTPUT_COMMITMENT_DOMAIN,
	WORK_STATEMENT_TYPE,
	type CommittedStep,
	type WorkStatementInput
} from './attestation.ts';
export {
	planRetentionSweep,
	workIndexKey,
	parseWorkIndexKey,
	MAX_WORK_RECORDS,
	RETENTION_MS,
	WORK_INDEX_PREFIX,
	type RetentionPlan
} from './retention.ts';
export { cborEncode, cborDecode, type CborValue, type CborMap } from './forestrie/cbor.ts';
