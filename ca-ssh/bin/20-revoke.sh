#!/usr/bin/env bash
# Revoke access immediately by updating the CA KRL.
#
# Three modes:
#   --cert <file-cert.pub>  revoke one specific certificate
#   --serial <n>            revoke a serial (looked up in the ledger)
#   --user <name>           revoke every certificate ever issued to a user
#
# The KRL is rebuilt from the ledger + a persistent revocation list, so the
# operation is repeatable and survives KRL regeneration. Output KRL is then
# published to hosts (see 40-deploy.sh).

set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

CA_KIND="user"
MODE=""
VALUE=""

while [[ $# -gt 0 ]]; do
	case "$1" in
		--ca)     CA_KIND="$2"; shift 2 ;;
		--cert)   MODE="cert"; VALUE="$2"; shift 2 ;;
		--serial) MODE="serial"; VALUE="$2"; shift 2 ;;
		--user)   MODE="user"; VALUE="$2"; shift 2 ;;
		-h|--help) sed -n '2,14p' "$0"; exit 0 ;;
		*) die "unknown argument: $1" ;;
	esac
done

[[ -n "$MODE" ]] || die "one of --cert/--serial/--user is required"

KRL="$(ca_krl "$CA_KIND")"
CA_PUB="$(ca_private "$CA_KIND").pub"
REVLIST="$STATE_DIR/$CA_KIND.revocations"
# Persistent home for certificates revoked directly (not by serial). The KRL
# is rebuilt from this directory plus the serial: lines in REVLIST, so no
# revocation is lost when a later rebuild happens after /tmp is cleared.
REVCERT_DIR="$STATE_DIR/$CA_KIND.revoked-certs"
LEDGER="$(ledger_file "$CA_KIND")"
ensure_dirs
install -d -m 700 "$REVCERT_DIR"
touch "$REVLIST"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

case "$MODE" in
	cert)
		[[ -f "$VALUE" ]] || die "certificate not found: $VALUE"
		cp -f "$VALUE" "$REVCERT_DIR/$(basename "$VALUE")"
		echo "cert:$VALUE" >> "$REVLIST"
		;;
	serial)
		[[ "$VALUE" =~ ^[0-9]+$ ]] || die "serial must be numeric"
		# KRL accepts a serial specification file.
		printf 'serial: %s\n' "$VALUE" > "$TMP/serials"
		echo "serial:$VALUE" >> "$REVLIST"
		;;
	user)
		# Find every serial issued to this user via the ledger key_id prefix.
		[[ -f "$LEDGER" ]] || die "ledger not found: $LEDGER"
		mapfile -t serials < <(awk -F, -v u="$VALUE" 'NR>1 {split($2,a,"|"); if (a[1]==u) print $1}' "$LEDGER")
		[[ ${#serials[@]} -gt 0 ]] || die "no issued certificates found for user: $VALUE"
		: > "$TMP/serials"
		for s in "${serials[@]}"; do printf 'serial: %s\n' "$s" >> "$TMP/serials"; done
		# Record the user tag for audit AND each serial, since KRL rebuild is
		# driven entirely by the serial: lines in this file.
		echo "user:$VALUE" >> "$REVLIST"
		for s in "${serials[@]}"; do echo "serial:$s" >> "$REVLIST"; done
		;;
esac

# Rebuild the KRL from all recorded revocation inputs. Serials come from the
# persistent REVLIST, direct cert revocations from the persistent cert dir.
mapfile -t all_serials < <(awk -F: '/^serial:/{print $2}' "$REVLIST" | tr -d ' ')
: > "$TMP/krl-spec"
for s in "${all_serials[@]}"; do printf 'serial: %s\n' "$s" >> "$TMP/krl-spec"; done

cert_count="$(find "$REVCERT_DIR" -type f | wc -l | tr -d ' ')"

if [[ -s "$TMP/krl-spec" ]]; then
	# Serial-based revocation needs the CA public key so ssh-keygen can scope
	# the serial numbers. If direct cert revocations also exist, include them
	# in the same generation so nothing is dropped on rebuild.
	args=(-s "$CA_PUB" -k -f "$KRL" "$TMP/krl-spec")
	if [[ "$cert_count" -gt 0 ]]; then
		while IFS= read -r -d '' c; do args+=("$c"); done < <(find "$REVCERT_DIR" -type f -print0)
	fi
	ssh-keygen "${args[@]}"
elif [[ "$cert_count" -gt 0 ]]; then
	# Only direct cert revocations exist (no serial spec needs a CA binding).
	find "$REVCERT_DIR" -type f -print0 | xargs -0 ssh-keygen -k -f "$KRL"
else
	die "no revocation entries produced (check ledger for user/serial): $MODE $VALUE"
fi

log "KRL updated: $KRL (ca=$CA_KIND mode=$MODE value=$VALUE)"
ssh-keygen -Q -l -f "$KRL" "$CA_PUB" >/dev/null 2>&1 || true
log "publish with: 40-deploy.sh --only-krl"
