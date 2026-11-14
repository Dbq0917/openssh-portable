#!/usr/bin/env bash
# Initialise the two offline user CAs:
#   user-ca       - day-to-day employee/operator certificates
#   breakglass-ca - emergency-access certificates only (separate trust domain)
#
# Idempotent: existing CA keys are never overwritten.
# Run this on an air-gapped or tightly controlled CA host.

set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

KEY_TYPE="${CA_KEY_TYPE:-ed25519}"

init_one() {
	local name="$1" comment="$2" key
	key="$(ca_private "$name")"
	if [[ -f "$key" ]]; then
		log "keeping existing $name CA: $key"
	else
		ssh-keygen -t "$KEY_TYPE" -f "$key" -N '' -C "$comment"
		chmod 600 "$key"
		chmod 644 "$key.pub"
		log "created $name CA: $key"
	fi
	check_ca_perms "$key"

	# Seed an empty KRL. sshd treats a missing RevokedKeys file as "nothing
	# revoked", but shipping an explicit empty KRL makes the intent auditable
	# and lets operators append without a first-run special case.
	local krl; krl="$(ca_krl "$name")"
	if [[ ! -f "$krl" ]]; then
		# Generate an empty KRL from /dev/null (no keys -> empty revocation set).
		: > "$STATE_DIR/.empty-krl-input"
		ssh-keygen -k -f "$krl" "$STATE_DIR/.empty-krl-input" >/dev/null
		log "initialised empty KRL: $krl"
	fi

	ssh-keygen -lf "$key.pub" | tee -a "$CA_DIR/fingerprints.txt"
}

ensure_dirs
: > "$CA_DIR/fingerprints.txt"
init_one user       "ssh-user-ca (routine access)"
init_one breakglass "ssh-breakglass-ca (emergency access)"

cat <<EOF

Next steps:
  1. Distribute the PUBLIC keys only:
       $USER_CA.pub        -> every host as /etc/ssh/trusted-user-ca.pub
       $BREAKGLASS_CA.pub  -> every host as /etc/ssh/breakglass-ca.pub
  2. Keep BOTH private keys offline; back them up encrypted, split custody.
  3. Rotate plan documented in docs/runbook.md (section "CA rotation").
EOF
