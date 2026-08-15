#!/usr/bin/env bash
# provision.sh — stand up (or reuse) a univocity instance, log hierarchy, and
# agent statement grant via the ietf-126-demo `forestrie` CLI, then emit the
# non-secret wiring into config/instance.jsonc (plan §6, §11 O6).
#
# The Scribe is a registrant against this instance (D5/D6): it never deploys,
# seals, or issues grants itself. This script is the "mandate concern" stand-in
# — it plays three provisioning-held roles:
#
#   root.es256.pem       forest bootstrap / root log K(L)   (deploy artifact)
#   authority.es256.pem  AUTH log K(L) — issues statement grants (T4)
#   steward.es256.pem    DATA log K(L) — holds the sealing delegation (T9)
#
# The agent's signing key is born inside the user's DO (C2) and is endorsed
# after the fact: `grant <x||y hex>` registers an extend-only writer grant on
# the data log whose grantData names the agent key (issuer != endorsed signer,
# ARC-0019 §6.3). Registration always goes via the ROOT log path — the grant
# routes the statement to the data log.
#
# Commands:
#   up             deploy + onboard + delegate + root/auth/data logs (idempotent)
#   grant <xyhex>  endorse an agent signer (64-byte ES256 x||y, hex) on the data log
#   config         write config/instance.jsonc (+ cache genesis.cbor alongside)
#   status         print the provisioned identifiers
#
# Requires: doppler auth for canopy/dev (or DEPLOYER_KEY in the env), openssl,
# jq, uuidgen, curl. Lane endpoints default to lane A; override via env.
set -euo pipefail
cd "$(dirname "$0")/.."

# --- lane + tooling (override via env) ---------------------------------------
FORESTRIE_CLI="${FORESTRIE_CLI:-$HOME/Dev/personal/forestrie/ietf-126-demo/forestrie}"
FORESTRIE_BASE_URL="${FORESTRIE_BASE_URL:-https://api-a.forest-2.forestrie.dev}"
DELEGATION_COORDINATOR_URL="${DELEGATION_COORDINATOR_URL:-https://coordinator-a.forest-2.forestrie.dev}"
LOG_STORE_URL="${LOG_STORE_URL:-https://pub-d7bc2e23615b4cd1a80a0944c3cd3507.r2.dev}"
RPC_URL="${RPC_URL:-https://sepolia.base.org}"
CHAIN_ID="${CHAIN_ID:-84532}"
# Registrar's public voucher key (vouches for the lane's sealer) — not a secret.
KNOWN_SEALER_KEY="${KNOWN_SEALER_KEY:-z1YarLKXrsRe5egrwrFfbeYadd9lOqplKxbRuMGymHUOSY7YAfdOhhPWb3H72TrPMiMLw0CBMpDPXUGMEvbkOQ==}"
OWNER_ADDRESS="${OWNER_ADDRESS:-0xdA30dB778C4aAE42BfAE2e81d4b12dEb0725F98C}"

P=".provision"
ROOT_PEM="$P/root.es256.pem"
AUTHORITY_PEM="$P/authority.es256.pem"
STEWARD_PEM="$P/steward.es256.pem"
DEPLOYMENT="$P/deployment.json"
GENESIS="$P/genesis.cbor"
IDS="$P/ids.env"

die() { printf 'provision.sh: %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }
have() { [ -s "$1" ]; }

[ -x "$FORESTRIE_CLI" ] || die "forestrie CLI not found at $FORESTRIE_CLI (set FORESTRIE_CLI)"
mkdir -p "$P"

deployer_key() {
  if [ -n "${DEPLOYER_KEY:-}" ]; then printf '%s' "$DEPLOYER_KEY"; else
    doppler secrets get DEPLOY_KEY --project canopy --config dev --plain \
      || die "no DEPLOYER_KEY in env and doppler fetch failed"
  fi
}

gen_pem() { # gen_pem <path> — P-256 private key, created once
  have "$1" && return 0
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null
  chmod 600 "$1"
}

load_ids() { [ -f "$IDS" ] && source "$IDS" || true; }
save_ids() { # save_ids VAR...
  : > "$IDS"
  local v
  for v in "$@"; do printf 'export %s=%q\n' "$v" "${!v}" >> "$IDS"; done
}

# --- up ----------------------------------------------------------------------
cmd_up() {
  load_ids

  step "keys (authority, steward)"
  gen_pem "$AUTHORITY_PEM"
  gen_pem "$STEWARD_PEM"

  if have "$DEPLOYMENT"; then
    step "deploy — reusing $DEPLOYMENT"
  else
    step "deploy — fresh univocity instance (Base Sepolia)"
    "$FORESTRIE_CLI" deploy --bootstrap-alg es256 \
      --bootstrap-es256-generate --bootstrap-es256-pem-out "$ROOT_PEM" \
      --owner-address "$OWNER_ADDRESS" --deployer-key "$(deployer_key)" \
      --rpc-url "$RPC_URL" --out "$DEPLOYMENT"
  fi
  UNIVOCITY_ADDRESS=$(jq -r .imutableUnivocity "$DEPLOYMENT")
  ROOT_LOG_ID=$(jq -r .genesisLogId "$DEPLOYMENT")

  if have "$GENESIS"; then
    step "onboard — reusing $GENESIS"
  else
    step "onboard — request token (x402) + POST genesis"
    local token
    token=$("$FORESTRIE_CLI" onboard-request --base-url "$FORESTRIE_BASE_URL" \
      --deployment "$DEPLOYMENT" --bootstrap-pem "$ROOT_PEM" \
      --label thinker-scribe --contact-email robinbryce@gmail.com \
      --payer-key "$(deployer_key)")
    "$FORESTRIE_CLI" onboard-genesis --base-url "$FORESTRIE_BASE_URL" \
      --deployment "$DEPLOYMENT" --bootstrap-pem "$ROOT_PEM" \
      --chain-id "$CHAIN_ID" --coordinator-url "$DELEGATION_COORDINATOR_URL" \
      --onboard-token "$token" --out "$GENESIS"
  fi

  step "delegate root sealing (before first write — T9)"
  "$FORESTRIE_CLI" delegate --coordinator-url "$DELEGATION_COORDINATOR_URL" \
    --log-id "$ROOT_LOG_ID" --sign-with "$ROOT_PEM" \
    --known-sealer-key "$KNOWN_SEALER_KEY"

  if have "$P/root-grant.b64"; then
    step "root grant — reusing"
  else
    step "root grant (self-referential)"
    "$FORESTRIE_CLI" create-log --base-url "$FORESTRIE_BASE_URL" \
      --owner-log "$ROOT_LOG_ID" --new-log "$ROOT_LOG_ID" \
      --sign-with "$ROOT_PEM" --self-referential \
      --out-b64 "$P/root-grant.b64"
  fi

  if [ -z "${AUTH_LOG_ID:-}" ]; then AUTH_LOG_ID=$(uuidgen | tr 'A-Z' 'a-z'); fi
  if [ -z "${DATA_LOG_ID:-}" ]; then DATA_LOG_ID=$(uuidgen | tr 'A-Z' 'a-z'); fi
  save_ids UNIVOCITY_ADDRESS ROOT_LOG_ID AUTH_LOG_ID DATA_LOG_ID

  if have "$P/auth-grant.b64"; then
    step "auth log — reusing $AUTH_LOG_ID"
  else
    step "auth log $AUTH_LOG_ID (prepare → delegate → create)"
    # --child-payment-required (adr-0062, plan-2608-09 W4a): the AUTH grant
    # carries GF_DERIVED|GF_CHILD_PAYMENT_REQUIRED, so user grants registered
    # under it at runtime x402-402 once the lane's REGISTER_GRANT_ADMISSION
    # flips (W5). Needs forestrie-cli >= the PR#47 build (v0.6.0 lacks it).
    local common=(--base-url "$FORESTRIE_BASE_URL" \
      --owner-log "$ROOT_LOG_ID" --new-log "$AUTH_LOG_ID" --auth-log \
      --child-payment-required \
      --signer-pem "$AUTHORITY_PEM" --sign-with "$ROOT_PEM" \
      --parent-grant-b64 "$(cat "$P/root-grant.b64")" \
      --out-b64 "$P/auth-grant.b64")
    "$FORESTRIE_CLI" create-log --prepare "${common[@]}"
    "$FORESTRIE_CLI" delegate --coordinator-url "$DELEGATION_COORDINATOR_URL" \
      --log-id "$AUTH_LOG_ID" --sign-with "$AUTHORITY_PEM" \
      --known-sealer-key "$KNOWN_SEALER_KEY"
    "$FORESTRIE_CLI" create-log "${common[@]}"
  fi

  if have "$P/data-grant.b64"; then
    step "data log — reusing $DATA_LOG_ID"
  else
    step "data log $DATA_LOG_ID (prepare → delegate → create)"
    local common=(--base-url "$FORESTRIE_BASE_URL" \
      --owner-log "$AUTH_LOG_ID" --new-log "$DATA_LOG_ID" \
      --bootstrap-log "$ROOT_LOG_ID" --data-log \
      --signer-pem "$STEWARD_PEM" --sign-with "$AUTHORITY_PEM" \
      --parent-grant-b64 "$(cat "$P/auth-grant.b64")" \
      --out-b64 "$P/data-grant.b64")
    "$FORESTRIE_CLI" create-log --prepare "${common[@]}"
    "$FORESTRIE_CLI" delegate --coordinator-url "$DELEGATION_COORDINATOR_URL" \
      --log-id "$DATA_LOG_ID" --sign-with "$STEWARD_PEM" \
      --known-sealer-key "$KNOWN_SEALER_KEY"
    "$FORESTRIE_CLI" create-log "${common[@]}"
  fi

  if have "$P/data-opened"; then
    step "data log — already opened"
  else
    # An extend-only writer grant (cmd_grant) can only attach once the log has
    # MMRS data, so the steward makes the first write under the creation grant.
    step "open data log — first write by steward under the creation grant"
    printf '{"thinker":"data-log-open","dataLogId":"%s"}' "$DATA_LOG_ID" > "$P/open.json"
    "$FORESTRIE_CLI" sign-statement --key "$STEWARD_PEM" --payload "$P/open.json" \
      --content-type application/json --sub "urn:thinker:open:$DATA_LOG_ID" \
      --out "$P/open.cose"
    "$FORESTRIE_CLI" register --base-url "$FORESTRIE_BASE_URL" \
      --log-id "$ROOT_LOG_ID" --statement "$P/open.cose" \
      --grant-b64 "$(cat "$P/data-grant.b64")" --timeout 180 \
      --out "$P/open-receipt.cbor"
    touch "$P/data-opened"
  fi

  cmd_status
}

# --- grant <xyhex> -----------------------------------------------------------
# Authorize an agent signer by CREATING a fresh data log whose creation grant
# names the agent key in grantData (canopy grants.md §6 path C-intermediate:
# owner = our AUTH log, parent evidence = its completed creation grant). The
# create+extend creation grant IS the write credential; the authority signs the
# envelope, so the agent's private key never leaves the DO (ARC-0019 §6.3).
# NB extend-only follow-up grants on an initialized log are not implemented
# server-side — creation grants for uninitialized targets are the only way a
# new writer key is endorsed today.
#
# Takes the 64-byte ES256 x||y public key (hex, as reported by the Scribe's
# GET /identity). Sealing delegation for the new log must be signed by its
# K(L) — the agent key — so it is the WORKER's job, not this script's.
cmd_grant() {
  local xyhex="${1:-}"
  [ ${#xyhex} -eq 128 ] || die "grant needs the agent public key as 128 hex chars (64-byte x||y)"
  load_ids
  [ -n "${AUTH_LOG_ID:-}" ] || die "run 'up' first"

  local pub="$P/agent-signer.pub.pem"
  # SPKI for an uncompressed P-256 point: fixed 26-byte header ++ 0x04 ++ x ++ y.
  { printf '3059301306072a8648ce3d020106082a8648ce3d03010703420004%s' "$xyhex" \
      | xxd -r -p | openssl base64 -A | fold -w 64; } > "$pub".b64
  { echo '-----BEGIN PUBLIC KEY-----'; cat "$pub".b64; echo; echo '-----END PUBLIC KEY-----'; } \
    | sed '/^$/d' > "$pub"
  rm -f "$pub".b64
  openssl pkey -pubin -in "$pub" -noout 2>/dev/null || die "constructed SPKI PEM is invalid"

  AGENT_LOG_ID=$(uuidgen | tr 'A-Z' 'a-z')
  step "create agent data log $AGENT_LOG_ID (grantData = agent kid $(printf '%s' "$xyhex" | cut -c1-64))"
  local common=(--base-url "$FORESTRIE_BASE_URL" \
    --owner-log "$AUTH_LOG_ID" --new-log "$AGENT_LOG_ID" \
    --bootstrap-log "$ROOT_LOG_ID" --data-log \
    --signer-pem "$pub" --sign-with "$AUTHORITY_PEM" \
    --parent-grant-b64 "$(cat "$P/auth-grant.b64")" \
    --out-b64 "$P/agent-grant.b64")
  "$FORESTRIE_CLI" create-log --prepare "${common[@]}"
  "$FORESTRIE_CLI" create-log "${common[@]}"
  save_ids UNIVOCITY_ADDRESS ROOT_LOG_ID AUTH_LOG_ID DATA_LOG_ID AGENT_LOG_ID
  echo "completed creation grant (agent writer credential) → $P/agent-grant.b64"
}

# --- config ------------------------------------------------------------------
cmd_config() {
  load_ids
  [ -n "${UNIVOCITY_ADDRESS:-}" ] || die "run 'up' first"
  cp "$GENESIS" config/genesis.cbor
  local agent_grant=""
  have "$P/agent-grant.b64" && agent_grant=$(cat "$P/agent-grant.b64")
  cat > config/instance.jsonc <<EOF
// Generated by scripts/provision.sh — do not edit; regenerate instead.
// Pre-provisioned Forestrie wiring for the Scribe (plan §6, §7).
{
  "chainId": "$CHAIN_ID",
  "contract": "$UNIVOCITY_ADDRESS",
  "R": "$ROOT_LOG_ID",
  "authLogId": "$AUTH_LOG_ID",
  "dataLogId": "$DATA_LOG_ID",
  "agentLogId": "${AGENT_LOG_ID:-}",
  "genesis": "./genesis.cbor",
  "forestrieBaseUrl": "$FORESTRIE_BASE_URL",
  "logStoreUrl": "$LOG_STORE_URL",
  "grants": {
    "agent": "$agent_grant"
  }
}
EOF
  echo "wrote config/instance.jsonc and config/genesis.cbor"
}

# --- status ------------------------------------------------------------------
cmd_status() {
  load_ids
  step "provisioned"
  printf '  %-12s %s\n' contract "${UNIVOCITY_ADDRESS:-—}" \
    "root(R)" "${ROOT_LOG_ID:-—}" auth "${AUTH_LOG_ID:-—}" data "${DATA_LOG_ID:-—}" \
    "agent grant" "$(have "$P/agent-grant.b64" && echo yes || echo not-yet)"
}

case "${1:-}" in
  up) cmd_up ;;
  grant) shift; cmd_grant "$@" ;;
  config) cmd_config ;;
  status) cmd_status ;;
  *) die "usage: provision.sh up | grant <xyhex> | config | status" ;;
esac
