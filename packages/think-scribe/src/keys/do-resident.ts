import type { KeyProvider } from "./provider.ts";

/**
 * C2 — the agent statement key is born and lives inside the user's DO
 * (plan §8, D4 "tolerated" custody for cut 1).
 *
 * Spike S1 (2026-08-09): workerd CANNOT structured-clone a CryptoKey into
 * DO storage — `storage.put(cryptoKey)` throws DataCloneError regardless of
 * extractability. So this provider uses the plan's fallback shape:
 * generate extractable → `wrapKey(pkcs8)` under an AES-GCM KEK (from the
 * Secrets Store / `.dev.vars`) → persist only the ciphertext → `unwrapKey`
 * to a NON-extractable handle on load. Plaintext key material never touches
 * storage, and the in-memory handle cannot be exported.
 */

const CURRENT_EPOCH_KEY = "scribe:keys:current-epoch";
const recordKey = (epoch: number) => `scribe:keys:epoch:${epoch}`;

interface StoredKeyRecord {
  wrappedPkcs8: Uint8Array;
  iv: Uint8Array;
  publicKeyXY: Uint8Array; // 64-byte x‖y
  createdAt: number;
}

const EC_ALG = { name: "ECDSA", namedCurve: "P-256" } as const;
const SIGN_ALG = { name: "ECDSA", hash: "SHA-256" } as const;

async function importKek(kekRaw: Uint8Array): Promise<CryptoKey> {
  if (kekRaw.length !== 32)
    throw new Error(`DoResidentKeyProvider: KEK must be 32 bytes, got ${kekRaw.length}`);
  return crypto.subtle.importKey("raw", kekRaw as BufferSource, { name: "AES-GCM" }, false, [
    "wrapKey",
    "unwrapKey",
  ]);
}

async function generateRecord(kek: CryptoKey): Promise<{
  record: StoredKeyRecord;
  privateKey: CryptoKey;
}> {
  const pair = (await crypto.subtle.generateKey(EC_ALG, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.wrapKey("pkcs8", pair.privateKey, kek, {
    name: "AES-GCM",
    iv,
  });
  // 65-byte uncompressed SEC1 point; drop the 0x04 prefix for x‖y.
  const raw = new Uint8Array(
    (await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer,
  );
  const record: StoredKeyRecord = {
    wrappedPkcs8: new Uint8Array(wrapped),
    iv,
    publicKeyXY: raw.slice(1),
    createdAt: Date.now(),
  };
  // Re-unwrap so the handle we keep is non-extractable even in the
  // generating isolate.
  const privateKey = await unwrapRecord(record, kek);
  return { record, privateKey };
}

async function unwrapRecord(record: StoredKeyRecord, kek: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.unwrapKey(
    "pkcs8",
    record.wrappedPkcs8 as BufferSource,
    kek,
    { name: "AES-GCM", iv: record.iv as BufferSource },
    EC_ALG,
    false,
    ["sign"],
  );
}

export class DoResidentKeyProvider implements KeyProvider {
  private constructor(
    private readonly storage: DurableObjectStorage,
    private readonly kek: CryptoKey,
    private currentEpoch: number,
    private privateKey: CryptoKey,
    private xy: Uint8Array,
  ) {}

  /**
   * Load (or on first touch, create) the current-epoch key for this DO.
   * `kekRaw` is the 32-byte AES-GCM key-encryption key.
   */
  static async load(
    storage: DurableObjectStorage,
    kekRaw: Uint8Array,
  ): Promise<DoResidentKeyProvider> {
    const kek = await importKek(kekRaw);
    let epoch = (await storage.get<number>(CURRENT_EPOCH_KEY)) ?? 0;
    let record = epoch > 0 ? await storage.get<StoredKeyRecord>(recordKey(epoch)) : undefined;
    let privateKey: CryptoKey;
    if (!record) {
      epoch = epoch > 0 ? epoch : 1;
      const created = await generateRecord(kek);
      record = created.record;
      privateKey = created.privateKey;
      await storage.put(recordKey(epoch), record);
      await storage.put(CURRENT_EPOCH_KEY, epoch);
    } else {
      privateKey = await unwrapRecord(record, kek);
    }
    return new DoResidentKeyProvider(storage, kek, epoch, privateKey, record.publicKeyXY);
  }

  epoch(): number {
    return this.currentEpoch;
  }

  kid(): Uint8Array {
    return this.xy.slice(0, 32);
  }

  async publicKeyXY(): Promise<Uint8Array> {
    return this.xy;
  }

  async sign(bytes: Uint8Array): Promise<Uint8Array> {
    const sig = await crypto.subtle.sign(SIGN_ALG, this.privateKey, bytes as BufferSource);
    return new Uint8Array(sig); // 64-byte P1363 r‖s
  }

  async rotate(epoch: number): Promise<void> {
    if (epoch <= this.currentEpoch)
      throw new Error(
        `rotate: epoch ${epoch} must exceed current epoch ${this.currentEpoch}`,
      );
    const { record, privateKey } = await generateRecord(this.kek);
    // Previous epochs are kept for N/N−1 grant overlap (plan §8).
    await this.storage.put(recordKey(epoch), record);
    await this.storage.put(CURRENT_EPOCH_KEY, epoch);
    this.currentEpoch = epoch;
    this.privateKey = privateKey;
    this.xy = record.publicKeyXY;
  }
}
