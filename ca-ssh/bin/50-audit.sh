#!/usr/bin/env bash
# Audit the deployed CA posture against the local inventory and ledger.
#
# Checks per host:
#   - trusted CA public key fingerprints match the CA host
#   - KRL present and matches the CA-side KRL checksum
#   - principals files match the rendered staging output
#   - "AuthorizedKeysFile none" is in effect (no legacy key path)
#   - breakglass block exists exactly on hosts flagged breakglass=yes
#
# Exit code is non-zero if ANY host fails, suitable for CI/cron alerting.

set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=8)
STAGING="$CA_ROOT/staging"
FAIL=0

expected_fp() { ssh-keygen -lf "$1" | awk '{print $2}'; }

LOCAL_USER_CA_FP="$(expected_fp "$USER_CA.pub")"
LOCAL_BG_CA_FP="$(expected_fp "$BREAKGLASS_CA.pub")"
LOCAL_KRL_SUM="$(sha256sum "$USER_KRL" | awk '{print $1}')"
LOCAL_BG_KRL_SUM="$(sha256sum "$BREAKGLASS_KRL" | awk '{print $1}')"

audit_one() {
	local host="$1" ip="$2" port="$3" breakglass="$4"
	local ok=1
	log "audit $host ($ip:$port)"

	local remote
	if ! remote="$(ssh "${SSH_OPTS[@]}" -p "$port" "root@$ip" 'bash -s' <<'REMOTE'
set -e
ca=/etc/ssh/ca
ssh-keygen -lf "$ca/trusted-user-ca.pub" 2>/dev/null | awk '{print "USER_CA_FP="$2}'
[[ -f "$ca/breakglass-ca.pub" ]] && ssh-keygen -lf "$ca/breakglass-ca.pub" | awk '{print "BG_CA_FP="$2}'
sha256sum "$ca/user-ca.krl" 2>/dev/null | awk '{print "USER_KRL_SUM="$1}'
[[ -f "$ca/breakglass-ca.krl" ]] && sha256sum "$ca/breakglass-ca.krl" | awk '{print "BG_KRL_SUM="$1}'
sshd -T 2>/dev/null | awk '/^authorizedkeysfile /{print "AKF="$2}'
grep -c "Match User breakglass" /etc/ssh/sshd_config.d/10-ssh-ca.conf 2>/dev/null | awk '{print "BG_BLOCK="$1}'
find "$ca/principals" -type f 2>/dev/null | sort | while read -r f; do
	echo "PRINCIPAL:${f##*/}:$(sha256sum "$f" | awk '{print $1}')"
done
REMOTE
	)"; then
		log "  FAIL: cannot connect/audit $host"
		return 1
	fi

	echo "$remote" | grep -q "USER_CA_FP=$LOCAL_USER_CA_FP" || { log "  FAIL: user CA fingerprint mismatch"; ok=0; }
	echo "$remote" | grep -q "USER_KRL_SUM=$LOCAL_KRL_SUM" || { log "  FAIL: user KRL out of date"; ok=0; }
	echo "$remote" | grep -q "AKF=none" || { log "  FAIL: AuthorizedKeysFile is not 'none' (legacy keys still trusted)"; ok=0; }

	if [[ "$breakglass" == "yes" ]]; then
		echo "$remote" | grep -q "BG_CA_FP=$LOCAL_BG_CA_FP" || { log "  FAIL: breakglass CA fingerprint mismatch/missing"; ok=0; }
		echo "$remote" | grep -q "BG_KRL_SUM=$LOCAL_BG_KRL_SUM" || { log "  FAIL: breakglass KRL out of date"; ok=0; }
		echo "$remote" | grep -q "BG_BLOCK=1" || { log "  FAIL: breakglass Match block missing"; ok=0; }
	fi

	# Compare every rendered principal file checksum with the host.
	if [[ -d "$STAGING/$host/principals" ]]; then
		while IFS= read -r -d '' f; do
			local name="${f##*/}" sum
			sum="$(sha256sum "$f" | awk '{print $1}')"
			echo "$remote" | grep -q "PRINCIPAL:$name:$sum" \
				|| { log "  FAIL: principal file drift: $name"; ok=0; }
		done < <(find "$STAGING/$host/principals" -type f -print0)
	fi

	if [[ "$ok" -eq 1 ]]; then log "  OK"; else FAIL=1; fi
}

while IFS=, read -r host ip port groups users breakglass env; do
	[[ -z "${host:-}" || "$host" == \#* || "$host" == "host" ]] && continue
	audit_one "$host" "$ip" "$port" "$breakglass" || FAIL=1
done < "$INVENTORY_FILE"

# Ledger sanity: any cert issued but past its TTL window is harmless, but a
# revoked serial still absent from the KRL is a real finding.
log "checking revocation list covers ledger revocations"
for ca_name in user breakglass; do
	rev="$STATE_DIR/$ca_name.revocations"
	[[ -f "$rev" ]] || continue
	while IFS= read -r line; do
		case "$line" in
			serial:*)
				s="${line#serial:}"
				if ! ssh-keygen -Q -l -f "$(ca_krl "$ca_name")" "$(ca_private "$ca_name").pub" 2>/dev/null | grep -q "^serial: $s\$"; then
					log "  FAIL: serial $s revoked in state but missing from $ca_name KRL"
					FAIL=1
				fi
				;;
		esac
	done < "$rev"
done

[[ "$FAIL" -eq 0 ]] && log "AUDIT CLEAN" || log "AUDIT FOUND PROBLEMS"
exit "$FAIL"
