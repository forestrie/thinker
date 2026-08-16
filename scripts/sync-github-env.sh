#!/usr/bin/env bash
# sync-github-env.sh — populate a GitHub Environment's secrets and variables
# for `.github/workflows/deploy.yml`.
#
#   bash scripts/sync-github-env.sh dev
#   bash scripts/sync-github-env.sh dev --dry-run
#   bash scripts/sync-github-env.sh dev --rotate DEMO_PASSWORD
#
# GitHub is the source of truth for what deploy.yml reads; this script is the
# one-way sync INTO it. It is idempotent: re-running never changes a generated
# secret, so it is safe to run after a re-provision to pick up new log ids.
#
# ## Where each value comes from
#
# | source                | holds                                              |
# |-----------------------|----------------------------------------------------|
# | doppler `canopy/dev`  | the account-level secrets (Anthropic, Cloudflare,  |
# |                       | the coordinator operator token)                    |
# | `config/instance.jsonc` | the provisioned forest's public identifiers      |
# | `.provision/`         | the authority key, and the two parent auth grants  |
# | generated here        | per-environment randoms that exist nowhere else    |
#
# ## Generated randoms are written ONCE
#
# `gh secret list` reports names but never values, which is enough: if the name
# is present we leave it alone. Rotating is deliberate and per-name, because two
# of them are destructive:
#
#   SCRIBE_KEK      wraps every Scribe DO's stored signing key. Rotating it
#                   makes all of them undecryptable — every agent identity in
#                   that environment is lost.
#   KMS_SEED_SECRET derives the agent kid. Rotating it changes the kid, which
#                   invalidates every pre-issued grant against the old one.
#
# DEMO_PASSWORD, SESSION_HMAC_SECRET and GRANT_AUTHORITY_TOKEN are safe to
# rotate — the cost is logged-out sessions and a redeploy.
set -euo pipefail
cd "$(dirname "$0")/.."

REPO="${REPO:-forestrie/thinker}"
DOPPLER_PROJECT="${DOPPLER_PROJECT:-canopy}"
DOPPLER_CONFIG="${DOPPLER_CONFIG:-dev}"

ENVIRONMENT=""
DRY_RUN=0
ROTATE=()

while [ $# -gt 0 ]; do
	case "$1" in
	--dry-run) DRY_RUN=1 ;;
	--rotate)
		ROTATE+=("$2")
		shift
		;;
	--repo)
		REPO="$2"
		shift
		;;
	-h | --help)
		sed -n '2,40p' "$0"
		exit 0
		;;
	dev | stage) ENVIRONMENT="$1" ;;
	*)
		echo "sync-github-env.sh: unknown argument '$1'" >&2
		exit 2
		;;
	esac
	shift
done

[ -n "$ENVIRONMENT" ] || {
	echo "usage: sync-github-env.sh <dev|stage> [--dry-run] [--rotate NAME] [--repo owner/name]" >&2
	exit 2
}

say() { printf '%s\n' "$*" >&2; }
run() { if [ "$DRY_RUN" = 1 ]; then say "  would: $*"; else "$@"; fi; }

# ---------------------------------------------------------------- preflight --
# Report every missing prerequisite at once. Discovering them one failed command
# at a time, each after a slow network call, is the thing that makes this kind
# of script hateful to use.
missing=()
command -v gh >/dev/null || missing+=("gh (GitHub CLI)")
command -v doppler >/dev/null || missing+=("doppler")
command -v jq >/dev/null || missing+=("jq")
command -v openssl >/dev/null || missing+=("openssl")
[ -f config/instance.jsonc ] || missing+=("config/instance.jsonc (run provision.sh)")
[ -f .provision/authority.es256.pem ] || missing+=(".provision/authority.es256.pem")
[ -f .provision/agent-auth-grant.b64 ] || missing+=(".provision/agent-auth-grant.b64")
[ -f .provision/user-auth-grant.b64 ] || missing+=(".provision/user-auth-grant.b64")
if [ ${#missing[@]} -gt 0 ]; then
	say "sync-github-env.sh: missing prerequisites:"
	printf '  - %s\n' "${missing[@]}" >&2
	exit 1
fi
gh auth status >/dev/null 2>&1 || {
	say "sync-github-env.sh: gh is not authenticated — run 'gh auth login'"
	exit 1
}

# ------------------------------------------------------------------ sources --
# instance.jsonc is JSONC; strip comments before jq sees it. The pattern is
# anchored to line-start deliberately — an unanchored `//` also matches the
# scheme separator in every https:// value in the file.
INSTANCE=$(sed 's,^[[:space:]]*//.*$,,' config/instance.jsonc)
inst() { printf '%s' "$INSTANCE" | jq -r "$1"; }

R=$(inst '.R')
AGENT_AUTH_LOG_ID=$(inst '.agentAuthLogId')
USER_AUTH_LOG_ID=$(inst '.userAuthLogId')
ROOT_PUBLIC_KEY_XY=$(inst '.rootPublicKeyXY')
FORESTRIE_BASE_URL=$(inst '.forestrieBaseUrl')
GRANT_USER_AUTHORITY=$(inst '.grants.userAuthority')

for pair in "R:$R" "agentAuthLogId:$AGENT_AUTH_LOG_ID" "userAuthLogId:$USER_AUTH_LOG_ID" \
	"rootPublicKeyXY:$ROOT_PUBLIC_KEY_XY" "forestrieBaseUrl:$FORESTRIE_BASE_URL" \
	"grants.userAuthority:$GRANT_USER_AUTHORITY"; do
	case "$pair" in
	*:) # empty value
		say "sync-github-env.sh: config/instance.jsonc has no ${pair%%:*} — re-run provision.sh"
		exit 1
		;;
	esac
done

# Both parent grants come from .provision/ rather than instance.jsonc, because
# instance.jsonc's `grants.agent` is empty in the W4b.1 two-parent shape while
# .provision/ always carries both. One source, no divergence.
AGENT_AUTH_GRANT_B64=$(tr -d '\n' <.provision/agent-auth-grant.b64)
USER_AUTH_GRANT_B64=$(tr -d '\n' <.provision/user-auth-grant.b64)

# The authority holds K(L) as a JWK, not the PEM: a JWK carries both key halves
# in one string, and the sealing delegation needs an extractable public half that
# a PKCS#8 private key cannot give back. Same conversion scripts/authority.sh
# does for local dev, so local and deployed hold the identical key material.
AUTHORITY_ES256_JWK=$(node -e '
	const { createPrivateKey } = require("node:crypto");
	const pem = require("node:fs").readFileSync(process.argv[1], "utf8");
	process.stdout.write(JSON.stringify(createPrivateKey(pem).export({ format: "jwk" })));
' .provision/authority.es256.pem)

dopp() {
	doppler secrets get "$1" --project "$DOPPLER_PROJECT" --config "$DOPPLER_CONFIG" --plain 2>/dev/null || true
}

say "reading doppler $DOPPLER_PROJECT/${DOPPLER_CONFIG}…"
ANTHROPIC_API_KEY=$(dopp ANTHROPIC_API_KEY)
CLOUDFLARE_API_TOKEN=$(dopp CLOUDFLARE_API_TOKEN)
CLOUDFLARE_ACCOUNT_ID=$(dopp CLOUDFLARE_ACCOUNT_ID)
COORDINATOR_APP_TOKEN=$(dopp COORDINATOR_APP_TOKEN)

doppler_missing=()
[ -n "$ANTHROPIC_API_KEY" ] || doppler_missing+=(ANTHROPIC_API_KEY)
[ -n "$CLOUDFLARE_API_TOKEN" ] || doppler_missing+=(CLOUDFLARE_API_TOKEN)
[ -n "$CLOUDFLARE_ACCOUNT_ID" ] || doppler_missing+=(CLOUDFLARE_ACCOUNT_ID)
[ -n "$COORDINATOR_APP_TOKEN" ] || doppler_missing+=(COORDINATOR_APP_TOKEN)
if [ ${#doppler_missing[@]} -gt 0 ]; then
	say "sync-github-env.sh: doppler $DOPPLER_PROJECT/$DOPPLER_CONFIG is missing:"
	printf '  - %s\n' "${doppler_missing[@]}" >&2
	say "(authenticate with 'doppler login', or set the names above in that config)"
	exit 1
fi

# --------------------------------------------------------------- environment --
say ""
suffix=""
[ "$DRY_RUN" = 1 ] && suffix=" (dry run)"
say "syncing $REPO environment '$ENVIRONMENT'$suffix"

# Idempotent: PUT on an existing environment is a no-op rather than an error.
run gh api -X PUT "repos/$REPO/environments/$ENVIRONMENT" --silent

existing_secrets=$(gh secret list --env "$ENVIRONMENT" --repo "$REPO" --json name -q '.[].name' 2>/dev/null || true)

has_secret() { printf '%s\n' "$existing_secrets" | grep -qx "$1"; }
wants_rotate() {
	local n
	for n in ${ROTATE+"${ROTATE[@]}"}; do [ "$n" = "$1" ] && return 0; done
	return 1
}

set_var() {
	say "  var    $1"
	run gh variable set "$1" --env "$ENVIRONMENT" --repo "$REPO" --body "$2"
}

set_secret() {
	say "  secret $1"
	if [ "$DRY_RUN" = 1 ]; then
		say "  would: gh secret set $1 --env $ENVIRONMENT --repo $REPO"
	else
		printf '%s' "$2" | gh secret set "$1" --env "$ENVIRONMENT" --repo "$REPO"
	fi
}

# A generated secret is written once and then left alone forever, unless named
# in --rotate. `$3` is the destructive-rotation warning, empty when there is
# none; a non-empty warning forces an interactive confirm.
set_generated() {
	local name="$1" value="$2" danger="${3:-}"
	if has_secret "$name" && ! wants_rotate "$name"; then
		say "  secret $name (already set — left alone)"
		return
	fi
	if has_secret "$name" && [ -n "$danger" ]; then
		say ""
		say "  !! rotating $name in '$ENVIRONMENT' is DESTRUCTIVE:"
		say "     $danger"
		read -r -p "     type the environment name to confirm: " confirm </dev/tty
		[ "$confirm" = "$ENVIRONMENT" ] || {
			say "     skipped."
			return
		}
	fi
	set_secret "$name" "$value"
	# Printed only when freshly generated — this is the only chance to see it.
	[ "$name" = DEMO_PASSWORD ] && say "  ->  DEMO_PASSWORD for '$ENVIRONMENT' is: $value"
	return 0
}

say ""
say "variables (non-secret: public identifiers and behaviour switches)"

# --- scribe-worker ---------------------------------------------------------
set_var FORESTRIE_BASE_URL "$FORESTRIE_BASE_URL"
set_var FORESTRIE_ROOT_LOG_ID "$R"
set_var FORESTRIE_ROOT_PUBLIC_KEY_XY "$ROOT_PUBLIC_KEY_XY"
set_var DELEGATION_COORDINATOR_URL "${DELEGATION_COORDINATOR_URL:-https://coordinator-a.forest-2.forestrie.dev}"
set_var KNOWN_SEALER_KEY "${KNOWN_SEALER_KEY:-z1YarLKXrsRe5egrwrFfbeYadd9lOqplKxbRuMGymHUOSY7YAfdOhhPWb3H72TrPMiMLw0CBMpDPXUGMEvbkOQ==}"
set_var GRANT_USER_AUTHORITY "$GRANT_USER_AUTHORITY"
# kms-seed (C3) rather than do-resident: the kid is derivable offline, which is
# what lets the authority pre-issue the agent grant (O5).
set_var KEY_PROVIDER kms-seed
set_var AGENT_KEY_EPOCH 1
# separate (M5/O4): the user's envelope is registered as its OWN leaf rather
# than only riding inside the agent's, so "the user said this" is independently
# receipted. The demo's whole point — do not flip this to embed.
set_var ATTESTATION_MODE separate
# Haiku 4.5 at $1/$5 against Sonnet 5's $3/$15. 200K context is ample here.
set_var MODEL_ID claude-haiku-4-5

# deploy.yml's kill switch. Off for stage by default — see the warning above.
if [ "$ENVIRONMENT" = stage ]; then
	set_var ENABLE_DEPLOY "${ENABLE_DEPLOY:-false}"
else
	set_var ENABLE_DEPLOY "${ENABLE_DEPLOY:-true}"
fi

# GRANT_AUTHORITY_URL is deliberately ABSENT. The worker reaches the authority
# over the AUTHORITY service binding and passes binding.fetch as the client's
# fetchImpl, so there is no URL to configure — or to leak.
#
# DEV_AUTH is deliberately ABSENT and must never be added: it enables
# `dev:0x…` bearer tokens, which would make the whole demo impersonatable.

# --- grant-authority -------------------------------------------------------
set_var ROOT_LOG_ID "$R"
set_var AGENT_AUTH_LOG_ID "$AGENT_AUTH_LOG_ID"
set_var USER_AUTH_LOG_ID "$USER_AUTH_LOG_ID"
set_var AGENT_AUTH_GRANT_B64 "$AGENT_AUTH_GRANT_B64"
set_var USER_AUTH_GRANT_B64 "$USER_AUTH_GRANT_B64"
set_var USER_GRANT_BATCH_TURNS 16

# --- scribe-ui -------------------------------------------------------------
set_var PUBLIC_DELEGATION_COORDINATOR_URL "${DELEGATION_COORDINATOR_URL:-https://coordinator-a.forest-2.forestrie.dev}"
set_var PUBLIC_KNOWN_SEALER_KEY "${KNOWN_SEALER_KEY:-z1YarLKXrsRe5egrwrFfbeYadd9lOqplKxbRuMGymHUOSY7YAfdOhhPWb3H72TrPMiMLw0CBMpDPXUGMEvbkOQ==}"
# PUBLIC_SCRIBE_BASE is deliberately ABSENT: unset is what selects same-origin,
# and same-origin is what makes the scribe worker the single public front door.

say ""
say "secrets from doppler and .provision (overwritten on every run — they have"
say "an upstream source of truth, so drift means the upstream moved)"
set_secret ANTHROPIC_API_KEY "$ANTHROPIC_API_KEY"
set_secret CLOUDFLARE_API_TOKEN "$CLOUDFLARE_API_TOKEN"
set_secret CLOUDFLARE_ACCOUNT_ID "$CLOUDFLARE_ACCOUNT_ID"
set_secret COORDINATOR_APP_TOKEN "$COORDINATOR_APP_TOKEN"
set_secret AUTHORITY_ES256_JWK "$AUTHORITY_ES256_JWK"

say ""
say "generated secrets (written once; --rotate NAME to replace)"
set_generated SESSION_HMAC_SECRET "$(openssl rand -base64 32)" ""
set_generated GRANT_AUTHORITY_TOKEN "$(openssl rand -hex 32)" ""
set_generated DEMO_PASSWORD "$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-12)" ""
set_generated SCRIBE_KEK "$(openssl rand -base64 32)" \
	"SCRIBE_KEK wraps every Scribe DO's stored signing key. Every agent identity in '$ENVIRONMENT' becomes undecryptable."
set_generated KMS_SEED_SECRET "$(openssl rand -base64 32)" \
	"KMS_SEED_SECRET derives the agent kid. Every grant pre-issued against the current kid stops matching."

say ""
if [ "$DRY_RUN" = 1 ]; then
	say "dry run — nothing was written."
else
	say "done. Inspect with:"
	say "  gh variable list --env $ENVIRONMENT --repo $REPO"
	say "  gh secret list   --env $ENVIRONMENT --repo $REPO"
fi
