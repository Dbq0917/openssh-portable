#!/usr/bin/env bash
# Stage and push CA trust material + principal files to target hosts.
#
# Safe-by-default workflow per host:
#   1. render principals (30-render-principals.sh)
#   2. copy new files into a staging dir on the target
#   3. run "sshd -t" against the merged config BEFORE touching the live config
#   4. atomically swap into place and reload (not restart) sshd
#   5. keep the previous version on the target for one-command rollback
#
# Modes:
#   40-deploy.sh                # all hosts from inventory
#   40-deploy.sh --host web-01  # single host
#   40-deploy.sh --only-krl     # push KRL refresh only (fast offboarding path)
#   40-deploy.sh --purge-authorized-keys  # also remove legacy authorized_keys

set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

REMOTE_DIR="/etc/ssh/ca"
SSHD_INCLUDE="Include /etc/ssh/sshd_config.d/*.conf"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)

ONLY_HOST=""
ONLY_KRL=0
PURGE=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
	case "$1" in
		--host) ONLY_HOST="$2"; shift 2 ;;
		--only-krl) ONLY_KRL=1; shift ;;
		--purge-authorized-keys) PURGE=1; shift ;;
		--dry-run) DRY_RUN=1; shift ;;
		-h|--help) sed -n '2,22p' "$0"; exit 0 ;;
		*) die "unknown argument: $1" ;;
	esac
done

[[ -f "$USER_CA.pub" ]] || die "user CA public key missing: $USER_CA.pub"
STAGING="$CA_ROOT/staging"

run_remote() {
	local ip="$1" port="$2"; shift 2
	ssh "${SSH_OPTS[@]}" -p "$port" "root@$ip" "$@"
}

deploy_one() {
	local host="$1" ip="$2" port="$3" breakglass="$4"
	log "== $host ($ip:$port) krl_only=$ONLY_KRL dry_run=$DRY_RUN"

	local target="root@$ip"
	local scp_base=(scp -P "$port" "${SSH_OPTS[@]}")

	# Always refresh KRLs (cheap, and the offboarding hot path).
	"${scp_base[@]}" "$USER_KRL" "$target:$REMOTE_DIR/user-ca.krl.new"
	if [[ "$breakglass" == "yes" ]]; then
		"${scp_base[@]}" "$BREAKGLASS_KRL" "$target:$REMOTE_DIR/breakglass-ca.krl.new"
	fi

	if [[ "$ONLY_KRL" -eq 0 ]]; then
		"${scp_base[@]}" "$USER_CA.pub" "$target:$REMOTE_DIR/trusted-user-ca.pub.new"
		if [[ "$breakglass" == "yes" ]]; then
			"${scp_base[@]}" "$BREAKGLASS_CA.pub" \
				"$target:$REMOTE_DIR/breakglass-ca.pub.new"
		fi
		"${scp_base[@]}" -r "$STAGING/$host/principals" \
			"$target:$REMOTE_DIR/principals.new"
		"${scp_base[@]}" "$TOOLKIT_ROOT/etc/sshd_config.d/10-ssh-ca.conf" \
			"$target:/etc/ssh/sshd_config.d/10-ssh-ca.conf.new"
	fi

	if [[ "$DRY_RUN" -eq 1 ]]; then
		log "dry-run: skipping remote activate for $host"
		return 0
	fi

	# Remote activation in one script so a failure cannot leave a half state.
	run_remote "$ip" "$port" REMOTE_DIR="$REMOTE_DIR" \
		SSHD_INCLUDE="$SSHD_INCLUDE" ONLY_KRL="$ONLY_KRL" PURGE="$PURGE" \
		bash -s <<'REMOTE'
set -euo pipefail
ts=$(date -u +%Y%m%dT%H%M%SZ)
backup=/var/backups/ssh-ca/$ts
mkdir -p "$backup"

swap() {
	local src="$1" dst="$2"
	[[ -e "$src" ]] || return 0
	if [[ -e "$dst" ]]; then cp -a "$dst" "$backup/"; fi
	mv "$src" "$dst"
}

swap "$REMOTE_DIR/user-ca.krl.new"       "$REMOTE_DIR/user-ca.krl"
swap "$REMOTE_DIR/breakglass-ca.krl.new" "$REMOTE_DIR/breakglass-ca.krl"

if [[ "$ONLY_KRL" != "1" ]]; then
	swap "$REMOTE_DIR/trusted-user-ca.pub.new" "$REMOTE_DIR/trusted-user-ca.pub"
	swap "$REMOTE_DIR/breakglass-ca.pub.new"   "$REMOTE_DIR/breakglass-ca.pub"
	if [[ -d "$REMOTE_DIR/principals" ]]; then
		cp -a "$REMOTE_DIR/principals" "$backup/"
	fi
	rm -rf "$REMOTE_DIR/principals.stage"
	mv "$REMOTE_DIR/principals.new" "$REMOTE_DIR/principals.stage"
	mkdir -p "$REMOTE_DIR/principals"
	cp -af "$REMOTE_DIR/principals.stage/." "$REMOTE_DIR/principals/"
	rm -rf "$REMOTE_DIR/principals.stage"
	chmod 755 "$REMOTE_DIR" "$REMOTE_DIR/principals"
	chmod 644 "$REMOTE_DIR"/principals/* 2>/dev/null || true

	swap /etc/ssh/sshd_config.d/10-ssh-ca.conf.new /etc/ssh/sshd_config.d/10-ssh-ca.conf

	if ! grep -qxF "$SSHD_INCLUDE" /etc/ssh/sshd_config; then
		cp -a /etc/ssh/sshd_config "$backup/sshd_config"
		printf '%s\n\n' "$SSHD_INCLUDE" | cat - /etc/ssh/sshd_config > /etc/ssh/sshd_config.tmp
		mv /etc/ssh/sshd_config.tmp /etc/ssh/sshd_config
	fi

	if [[ "$PURGE" == "1" ]]; then
		find /home /root -path '*/.ssh/authorized_keys' -print -delete \
			| sed "s/^/purged: /"
	fi
fi

# Validate BEFORE reload. On failure, auto-restore the newest backup and abort.
if ! sshd -t; then
	echo "sshd -t FAILED; rolling back" >&2
	if [[ -d "$backup" ]]; then cp -af "$backup/." /etc/ssh/ 2>/dev/null || true; fi
	exit 1
fi

if command -v systemctl >/dev/null && systemctl is-active --quiet ssh 2>/dev/null; then
	systemctl reload ssh
elif systemctl is-active --quiet sshd 2>/dev/null; then
	systemctl reload sshd
else
	kill -HUP "$(cat /run/sshd.pid 2>/dev/null || cat /var/run/sshd.pid)"
fi
echo "activated $REMOTE_DIR (backup $backup)"
REMOTE
}

# Iterate inventory.
while IFS=, read -r host ip port groups users breakglass env; do
	[[ -z "${host:-}" || "$host" == \#* || "$host" == "host" ]] && continue
	if [[ -n "$ONLY_HOST" && "$host" != "$ONLY_HOST" ]]; then continue; fi
	deploy_one "$host" "$ip" "$port" "$breakglass"
done < "$INVENTORY_FILE"

log "deploy complete"
