// derive-agent-kid — the O5 counterfactual: compute the agent's kid OFFLINE
// from the custodian seed + userSub + epoch, before the DO ever runs, so the
// authority can pre-issue `grant_agent` on it (plan §11 O5, C3).
//
// Uses the exact same derivation as the worker's KmsSeedKeyProvider (imports
// the TS source via node type stripping; node >= 22.18).
//
// Usage:
//   derive-agent-kid.mjs --user-sub <sub> [--epoch N] [--seed-b64 <base64>]
//
// The 32-byte seed comes from --seed-b64, env KMS_SEED_SECRET, or the
// KMS_SEED_SECRET line of apps/scribe-worker/.dev.vars — matching what the
// dev worker derives with.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  deriveAgentKey,
  localSeedCustodianMac,
} from "../packages/think-scribe/src/keys/kms-seed.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

const args = process.argv.slice(2);
const opt = {};
for (let i = 0; i < args.length; i++) {
  if (!args[i].startsWith("--")) {
    console.error(`derive-agent-kid: unexpected argument ${args[i]}`);
    process.exit(2);
  }
  opt[args[i].slice(2)] = args[i + 1];
  i++;
}
if (!opt["user-sub"]) {
  console.error("derive-agent-kid: --user-sub required");
  process.exit(2);
}
const epoch = Number(opt.epoch ?? "1");

let seedB64 = opt["seed-b64"] ?? process.env.KMS_SEED_SECRET;
if (!seedB64) {
  try {
    const devVars = readFileSync(
      join(ROOT, "apps", "scribe-worker", ".dev.vars"),
      "utf8",
    );
    seedB64 = devVars
      .split("\n")
      .find((l) => l.startsWith("KMS_SEED_SECRET="))
      ?.slice("KMS_SEED_SECRET=".length)
      .trim();
  } catch {
    // fall through to the error below
  }
}
if (!seedB64) {
  console.error(
    "derive-agent-kid: no seed (--seed-b64, env KMS_SEED_SECRET, or .dev.vars)",
  );
  process.exit(2);
}

const seed = Uint8Array.from(Buffer.from(seedB64, "base64"));
const derived = await deriveAgentKey(
  localSeedCustodianMac(seed),
  opt["user-sub"],
  epoch,
);
const hex = (b) => Buffer.from(b).toString("hex");
console.log(
  JSON.stringify(
    {
      userSub: opt["user-sub"],
      epoch,
      kid: hex(derived.kid),
      publicKeyXY: hex(derived.publicKeyXY),
    },
    null,
    2,
  ),
);
