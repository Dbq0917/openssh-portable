#!/usr/bin/env bash
# Issue a short-lived SSH user certificate.
#
# Examples:
#   routine: member of web + sre groups, also carries personal principal
#     10-sign-cert.sh --ca user --user alice --key /path/alice.pub \
#         --groups web,sre --ttl 12h
#
#   emergency: breakglass CA, very short TTL, locked to bastion source IPs
#     10-sign-cert.sh --ca breakglass --user oncall-pager --key bg.pub \
#         --groups breakglass --ttl 2h --source 10.0.0.5/32
#
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

CA_KIND="user"
USER_NAME=""
PUBKEY=""
GROUP_LIST=""
EXTRA_PRINCIPALS=""
TTL=""
SOURCE_ADDR=""
FORCE_COMMAND=""
NO_AGENT_FORWARD=""
NO_PORT_FORWARD=""
NO_PTY=""

usage() { sed -n '2,20p' "$0"; exit "${1:-1}"; }

while [[ $# -gt 0 ]]; do
	case "$1" in
		--ca)        CA_KIND="$2"; shift 2 ;;
		--user)      USER_NAME="$2"; shift 2 ;;
		--key)       PUBKEY="$2"; shift 2 ;;
		--groups)    GROUP_LIST="$2"; shift 2 ;;
		--principal) EXTRA_PRINCIPALS="${EXTRA_PRINCIPALS:+$EXTRA_PRINCIPALS,}$2"; shift 2 ;;
		--ttl)       TTL="$2"; shift 2 ;;
		--source)    SOURCE_ADDR="$2"; shift 2 ;;
		--force-command) FORCE_COMMAND="$2"; shift 2 ;;
		--no-agent)  NO_AGENT_FORWARD=1; shift ;;
		--no-port)   NO_PORT_FORWARD=1; shift ;;
		--no-pty)    NO_PTY=1; shift ;;
		-h|--help)   usage 0 ;;
		*) die "unknown argument: $1" ;;
	esac
done

[[ -n "$USER_NAME" ]] || die "--user is required"
[[ -f "$PUBKEY" ]]     || die "public key not found: $PUBKEY"
[[ -n "$GROUP_LIST" ]] || die "--groups is required (e.g. web,sre or breakglass)"

: "${TTL:=$([[ "$CA_KIND" == breakglass ]] && echo "$BREAKGLASS_CERT_TTL" || echo "$DEFAULT_CERT_TTL")}"

CA_KEY="$(ca_private "$CA_KIND")"
check_ca_perms "$CA_KEY"

# Build the principal list. Group principals are namespaced "group:<name>"
# so they can never collide with a personal login name.
PRINCIPALS=""

# The breakglass CA is a separate trust domain whose only principal is the
# bare token "breakglass", matched by the dedicated emergency account. It
# deliberately does NOT use the group: namespace or carry personal principals.
if [[ "$CA_KIND" == "breakglass" ]]; then
	PRINCIPALS="breakglass"
else
	_grp=(); g=""
	OLD_IFS="$IFS"
	IFS=',' read -ra _grp <<< "$GROUP_LIST"
	for g in "${_grp[@]}"; do
		[[ "$g" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid group name: $g"
		PRINCIPALS="${PRINCIPALS:+$PRINCIPALS,}group:$g"
	done
	IFS="$OLD_IFS"
	# Personal principal = the OS login name, used for per-user allow exceptions.
	PRINCIPALS="$PRINCIPALS,$USER_NAME"
	[[ -n "$EXTRA_PRINCIPALS" ]] && PRINCIPALS="$PRINCIPALS,$EXTRA_PRINCIPALS"
fi
validate_principals "$PRINCIPALS"

SERIAL="$(next_serial "$CA_KIND")"
KEY_ID="${USER_NAME}|${CA_KIND}|$(date -u +%Y%m%d)"

opts=(-s "$CA_KEY" -I "$KEY_ID" -n "$PRINCIPALS" -z "$SERIAL" -V "+$TTL")
[[ -n "$SOURCE_ADDR" ]]   && opts+=(-O "source-address=$SOURCE_ADDR")
[[ -n "$FORCE_COMMAND" ]] && opts+=(-O "force-command=$FORCE_COMMAND")
[[ -n "$NO_AGENT_FORWARD" ]] && opts+=(-O no-agent-forwarding)
[[ -n "$NO_PORT_FORWARD" ]]  && opts+=(-O no-port-forwarding)
[[ -n "$NO_PTY" ]]           && opts+=(-O no-pty)
# Clear anything not explicitly granted. X11 forwarding is off by default.
opts+=(-O no-x11-forwarding -O no-user-rc)

ensure_dirs
ssh-keygen "${opts[@]}" "$PUBKEY"

CERT="${PUBKEY%.pub}-cert.pub"
append_ledger "$CA_KIND" "$SERIAL" "$KEY_ID" "$PRINCIPALS" "$TTL" "$PUBKEY"

log "issued serial=$SERIAL ca=$CA_KIND id=$KEY_ID principals=[$PRINCIPALS] ttl=$TTL"
ssh-keygen -L -f "$CERT"
