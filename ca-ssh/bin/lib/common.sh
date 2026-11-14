#!/usr/bin/env bash
# Shared helpers for the SSH user-CA toolchain.
# Sourced by every script in bin/. Not meant to be executed directly.

set -euo pipefail

# Resolve the toolkit root (parent of bin/).
_SELF="${BASH_SOURCE[0]}"
TOOLKIT_ROOT="$(cd "$(dirname "$_SELF")/.." && pwd)"

# User-overridable locations. Defaults assume the CA operator runs from a
# dedicated, offline-hardened host with the tree under /etc/ssh-ca.
: "${CA_ROOT:=${CA_SSH_ROOT:-/etc/ssh-ca}}"
: "${CA_UMASK:=077}"
umask "$CA_UMASK"

# Layout under CA_ROOT.
CA_DIR="$CA_ROOT/ca"
LEDGER_DIR="$CA_ROOT/ledger"
KRL_DIR="$CA_ROOT/krl"
STATE_DIR="$CA_ROOT/state"
INVENTORY_FILE="${CA_INVENTORY:-$CA_ROOT/inventory/hosts.csv}"

USER_CA="$CA_DIR/user-ca"
BREAKGLASS_CA="$CA_DIR/breakglass-ca"
USER_KRL="$KRL_DIR/user-ca.krl"
BREAKGLASS_KRL="$KRL_DIR/breakglass-ca.krl"

# Default certificate lifetime. Short TTLs are the primary offboarding
# control; KRL is the immediate-kill switch.
: "${DEFAULT_CERT_TTL:=12h}"
: "${BREAKGLASS_CERT_TTL:=4h}"

log()  { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

for cmd in ssh-keygen ssh; do need "$cmd"; done

ensure_dirs() {
	local d
	for d in "$CA_DIR" "$LEDGER_DIR" "$KRL_DIR" "$STATE_DIR" "$(dirname "$INVENTORY_FILE")"; do
		install -d -m 700 "$d"
	done
}

# next_serial <ca-name>
# Monotonic per-CA serial numbers, persisted under state/. Serial numbers are
# what goes into the KRL when a whole user/key must be killed before expiry.
next_serial() {
	local ca_name file n line
	ca_name="$1"
	file="$STATE_DIR/$ca_name.serial"
	n=1000
	touch "$file"
	line="$(cat "$file")"
	[[ -n "$line" ]] && n="$line"
	n=$((n + 1))
	printf '%s\n' "$n" > "$file"
	printf '%s\n' "$n"
}

# ca_private <user|breakglass>
ca_private() {
	case "$1" in
		user)       printf '%s\n' "$USER_CA" ;;
		breakglass) printf '%s\n' "$BREAKGLASS_CA" ;;
		*) die "unknown CA: $1 (expected user|breakglass)" ;;
	esac
}

# ca_krl <user|breakglass>
ca_krl() {
	case "$1" in
		user)       printf '%s\n' "$USER_KRL" ;;
		breakglass) printf '%s\n' "$BREAKGLASS_KRL" ;;
		*) die "unknown KRL: $1" ;;
esac
}

# ledger_file <ca-name> -> per-CA append-only CSV of every certificate issued.
ledger_file() {
	printf '%s\n' "$LEDGER_DIR/$1-certificates.csv"
}

append_ledger() {
	local ca_name="$1" serial="$2" key_id="$3" principals="$4" ttl="$5" pubkey_file="$6"
	local f; f="$(ledger_file "$ca_name")"
	[[ -f "$f" ]] || printf 'serial,key_id,principals,ttl,issued_utc,pubkey_sha256,cert_file\n' > "$f"
	local fp
	fp="$(ssh-keygen -lf "$pubkey_file" | awk '{print $2}')"
	# Quote fields that may contain commas (principals) so the ledger stays
	# valid CSV for awk/csv tooling downstream.
	printf '%s,%s,%s,%s,%s,%s,%s\n' \
		"$serial" "$key_id" "\"$principals\"" "$ttl" \
		"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$fp" "${pubkey_file%.pub}-cert.pub" >> "$f"
}

# require_root_owner: CA private material must never be group/world readable.
check_ca_perms() {
	local key="$1"
	[[ -f "$key" ]] || die "CA key missing: $key (run 00-init-ca.sh first)"
	local mode
	mode="$(stat -c '%a' "$key")"
	[[ "$mode" == "600" || "$mode" == "400" ]] \
		|| die "CA key $key has unsafe mode $mode (want 600/400)"
}

# validate a principals list: non-empty, comma separated, conservative charset.
validate_principals() {
	local p="$1"
	[[ -n "$p" ]] || die "principals must not be empty"
	printf '%s' "$p" | grep -Eq '^[A-Za-z0-9._@:-]+(,[A-Za-z0-9._@:-]+)*$' \
		|| die "invalid principals (allowed: alnum . _ @ : - comma-separated): $p"
}
