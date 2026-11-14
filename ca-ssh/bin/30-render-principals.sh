#!/usr/bin/env bash
# Render per-account AuthorizedPrincipals files from inventory/hosts.csv.
#
# Output layout (staging dir, ready to ship by 40-deploy.sh):
#   <out>/<host>/principals/<os-user>
#
# Each file lists one principal per line. A certificate authenticates only if
# one of its principals appears in the file for the target account.
#
# Group principals are rendered as "group:<name>"; personal principals as the
# bare OS login name. This mirrors what 10-sign-cert.sh embeds in certificates.

set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

OUT_DIR="${1:-$CA_ROOT/staging}"
# On production hosts the shared login account is typically "ops"; the test
# suite overrides this to the invoking user. Default to ops for real deploys.
LOGIN_USER="${SSH_LOGIN_USER:-ops}"

[[ -f "$INVENTORY_FILE" ]] || die "inventory not found: $INVENTORY_FILE"
install -d -m 700 "$OUT_DIR"

host_count=0
while IFS=, read -r host ip port groups users breakglass env; do
	[[ -z "${host:-}" || "$host" == \#* || "$host" == "host" ]] && continue

	d="$OUT_DIR/$host/principals"
	install -d -m 700 "$d"
	f="$d/$LOGIN_USER"
	: > "$f"

	# groups column uses '|' as separator (comma is the CSV delimiter).
	old_ifs="$IFS"
	IFS='|' read -ra garr <<< "$groups"
	for g in "${garr[@]}"; do
		g="$(printf '%s' "$g" | xargs)"
		[[ -n "$g" ]] && printf 'group:%s\n' "$g" >> "$f"
	done

	IFS='|' read -ra uarr <<< "$users"
	for u in "${uarr[@]}"; do
		u="$(printf '%s' "$u" | xargs)"
		[[ -n "$u" ]] && printf '%s\n' "$u" >> "$f"
	done
	IFS="$old_ifs"

	# Break-glass account gets its own principals file with a single principal.
	if [[ "$breakglass" == "yes" ]]; then
		printf 'breakglass\n' > "$d/breakglass"
	fi

	# Also emit a small host metadata file for the deployer.
	printf 'ip=%s\nport=%s\nbreakglass=%s\nenv=%s\n' \
		"$ip" "$port" "$breakglass" "$env" > "$OUT_DIR/$host/meta.env"

	host_count=$((host_count + 1))
done < "$INVENTORY_FILE"

log "rendered principals for $host_count host(s) under $OUT_DIR"
find "$OUT_DIR" -type f -name "$LOGIN_USER" -o -type f -name breakglass | sort | while read -r f; do
	printf '== %s\n' "${f#$OUT_DIR/}"
	cat "$f"
done
