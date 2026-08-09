export {
  Scribe,
  DEFAULT_MODEL_ID,
  PRINCIPAL_HEADER,
  type ScribeEnv,
} from "./scribe.ts";
export { bytesToHex, hexToBytes, type KeyProvider } from "./keys/provider.ts";
export { DoResidentKeyProvider } from "./keys/do-resident.ts";
export {
  KmsSeedKeyProvider,
  deriveAgentKey,
  localSeedCustodianMac,
  custodianMacInfo,
  type CustodianMac,
  type DerivedAgentKey,
} from "./keys/kms-seed.ts";
export { buildSignedStatement } from "./forestrie/cose.ts";
export {
  ConfiguredGrantProvider,
  GrantAuthorityClient,
  GrantRequestError,
  StubPaymentProvider,
  type GrantProvider,
  type IssuedGrant,
  type PaymentProvider,
} from "./forestrie/grant.ts";
export {
  fetchReceipt,
  queryRegistration,
  registerStatement,
  ScrapiError,
  type RegisterAccepted,
  type RegistrationStatus,
  type ReceiptStatus,
} from "./forestrie/register.ts";
export {
  delegateSealing,
  delegateSealingKs256,
  DelegateError,
  type DelegateSealingParams,
  type DelegateSealingResult,
} from "./forestrie/delegate.ts";
export {
  buildUserEnvelope,
  verifyUserEnvelope,
  EnvelopeError,
  COSE_ALG_KS256,
  type EnvelopeClaims,
  type VerifiedEnvelope,
} from "./forestrie/envelope.ts";
export {
  buildWorkStatementPayload,
  sha256Hex,
  WORK_STATEMENT_TYPE,
  type CommittedStep,
  type WorkStatementInput,
} from "./attestation.ts";
export { cborEncode, cborDecode, type CborValue, type CborMap } from "./forestrie/cbor.ts";
