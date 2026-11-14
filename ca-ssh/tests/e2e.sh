#!/usr/bin/env bash
# End-to-end test for the ca-ssh toolkit.
#
# Spins up two unprivileged sshd instances on loopback:
#   web host (port $WEB_PORT)  trusts user-ca, allows group:web
#   breakglass host (port $BG_PORT) trusts breakglass-ca, allows principal "breakglass"
#
# It exercises the real toolkit scripts (init/sign/render/revoke) and asserts
# the full authentication matrix. Requires a local sshd binary; by default it
# uses the one built from this repo (./sshd) or the system sshd on PATH.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SSHD_BIN="${SSHD_BIN:-$REPO_ROOT/sshd}"
SSH_BIN="${SSH_BIN:-$REPO_ROOT/ssh}"

PASS=0; FAILED=0
WEB_PORT="${WEB_PORT:-22901}"
BG_PORT="${BG_PORT:-22902}"
ME="$(whoami)"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ca-ssh-e2e.XXXXXX")"
PIDS=()

# Free the test ports from any listener left by an aborted previous run.
for _port in "$WEB_PORT" "$BG_PORT"; do
	ss -ltnp 2>/dev/null | awk -v p=":$_port" '$4 ~ p {print $NF}' \
		| sed -n 's/.*pid=\([0-9]*\).*/\1/p' \
		| while read -r _pid; do kill "$_pid" 2>/dev/null || true; done
done
sleep 0.5

cleanup() {
	for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
	# Keep WORK on failure for debugging; remove only on success.
	if [[ "$FAILED" -eq 0 ]]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT

say()  { printf '\n\033[1;34m[*] %s\033[0m\n' "$*"; }
ok()   { printf '  \033[1;32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; FAILED=$((FAILED+1)); }

# expect_login <port> <key> <known_hosts> <desc>
expect_login() {
	local port="$1" key="$2" kh="$3" desc="$4"
	if "$SSH_BIN" -p "$port" -i "$key" -o UserKnownHostsFile="$kh" \
		-o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
		"$ME@127.0.0.1" true 2>/dev/null; then
		ok "$desc"
	else
		bad "$desc (expected successful login)"
	fi
}

# expect_deny <port> <key> <known_hosts> <desc>
expect_deny() {
	local port="$1" key="$2" kh="$3" desc="$4"
	if "$SSH_BIN" -p "$port" -i "$key" -o UserKnownHostsFile="$kh" \
		-o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
		"$ME@127.0.0.1" true 2>/dev/null; then
		bad "$desc (login should have been rejected)"
	else
		ok "$desc"
	fi
}

[[ -x "$SSHD_BIN" ]] || { echo "sshd not found at $SSHD_BIN (build it: make sshd sshd-auth sshd-session)"; exit 2; }
[[ -x "$SSH_BIN"  ]] || SSH_BIN=ssh

export CA_ROOT="$WORK/ca"
export CA_INVENTORY="$WORK/inventory.csv"
# Principals are rendered for the real local account used in this unprivileged test.
export SSH_LOGIN_USER="$ME"

say "1. init CAs via 00-init-ca.sh"
"$HERE/../bin/00-init-ca.sh" >/dev/null
[[ -f "$CA_ROOT/ca/user-ca" && -f "$CA_ROOT/ca/breakglass-ca" ]] \
	&& ok "both CAs created" || bad "CA init"

say "2. build inventory + render principals via 30-render-principals.sh"
cat > "$CA_INVENTORY" <<CSV
host,ip,ssh_port,groups,users,breakglass,env
web-host,127.0.0.1,$WEB_PORT,web|sre,,yes,prod
bg-host,127.0.0.1,$BG_PORT,breakglass,,yes,prod
CSV
"$HERE/../bin/30-render-principals.sh" >/dev/null
grep -qx 'group:web' "$CA_ROOT/staging/web-host/principals/$ME" \
	&& ok "web principal rendered" || bad "principal render"
grep -qx 'breakglass' "$CA_ROOT/staging/bg-host/principals/breakglass" \
	&& ok "breakglass principal rendered" || bad "breakglass render"

say "3. generate user keys and sign via 10-sign-cert.sh"
mkdir -p "$WORK/keys"
gen() { ssh-keygen -t ed25519 -f "$WORK/keys/$1" -N '' -q; }
gen alice; gen bob; gen bg; gen exp

"$HERE/../bin/10-sign-cert.sh" --user alice --key "$WORK/keys/alice.pub" \
	--groups web,sre --ttl 8h >/dev/null
ok "alice cert (group:web,sre)"
"$HERE/../bin/10-sign-cert.sh" --user bob --key "$WORK/keys/bob.pub" \
	--groups db --ttl 8h >/dev/null
ok "bob cert (group:db only)"
"$HERE/../bin/10-sign-cert.sh" --ca breakglass --user oncall --key "$WORK/keys/bg.pub" \
	--groups breakglass --ttl 2h >/dev/null
ok "breakglass cert"
# Expired certificate: hand-craft a past validity window.
ssh-keygen -s "$CA_ROOT/ca/user-ca" -I exp-user -n group:web,exp \
	-V -2h:-1h -z 9999 "$WORK/keys/exp.pub" >/dev/null
ok "expired cert minted"

say "4. configure + launch two sshd instances"
launch_host() {
	local name="$1" port="$2" ca_pub="$3" principal_dir="$4"
	local hdir="$WORK/$name"; mkdir -p "$hdir"
	ssh-keygen -t ed25519 -f "$hdir/hostkey" -N '' -q
	mkdir -p "$hdir/principals"
	cp -a "$principal_dir/." "$hdir/principals/"
	# principal files must be named for the connecting account; breakglass
	# block uses its own account name, mapped onto $ME for this unprivileged test.
	cp "$hdir/principals/breakglass" "$hdir/principals/$ME.bg" 2>/dev/null || true

	cat > "$hdir/sshd_config" <<CONF
Port $port
ListenAddress 127.0.0.1
HostKey $hdir/hostkey
PidFile $hdir/pid
	# The test fires many auths from one loopback address; disable the
	# per-source connection penalty so it cannot mask real results.
	PerSourcePenalties no
TrustedUserCAKeys $ca_pub
AuthorizedKeysFile none
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
StrictModes no
PrintMotd no
Subsystem sftp $REPO_ROOT/sftp-server
Match User $ME
    AuthorizedPrincipalsFile $hdir/principals/$ME
CONF
	"$SSHD_BIN" -t -f "$hdir/sshd_config"
	"$SSHD_BIN" -f "$hdir/sshd_config" -E "$hdir/log"
	for _ in $(seq 1 50); do [[ -s "$hdir/pid" ]] && break; sleep 0.1; done
	[[ -s "$hdir/pid" ]] || { cat "$hdir/log"; bad "sshd did not start for $name"; return 1; }
	PIDS+=("$(cat "$hdir/pid")")
	ssh-keygen -y -f "$hdir/hostkey" | sed "s/^/[127.0.0.1]:$port /" > "$hdir/known_hosts"
}

# web host: user-ca + the rendered web principals (file for $ME holds group:web)
launch_host web "$WEB_PORT" "$CA_ROOT/ca/user-ca.pub" "$CA_ROOT/staging/web-host/principals"
# bg host: breakglass-ca; map its single principal onto the test account
mkdir -p "$WORK/bg-stage/principals"
printf 'breakglass\n' > "$WORK/bg-stage/principals/$ME"
launch_host bg "$BG_PORT" "$CA_ROOT/ca/breakglass-ca.pub" "$WORK/bg-stage/principals"
sleep 1
ok "both sshd instances listening"

WEB_KH="$WORK/web/known_hosts"; BG_KH="$WORK/bg/known_hosts"

say "5. authentication matrix"
expect_login "$WEB_PORT" "$WORK/keys/alice" "$WEB_KH" "valid web-group cert -> web host"
expect_deny  "$WEB_PORT" "$WORK/keys/bob"   "$WEB_KH" "db-only cert rejected by web host"
expect_deny  "$WEB_PORT" "$WORK/keys/exp"   "$WEB_KH" "expired cert rejected"

# Explicit raw-key attempt: point CertificateFile at a nonexistent path so the
# client offers only the bare public key.
if "$SSH_BIN" -p "$WEB_PORT" -i "$WORK/keys/alice" -o CertificateFile=/nonexistent \
	-o UserKnownHostsFile="$WEB_KH" -o IdentitiesOnly=yes -o BatchMode=yes \
	"$ME@127.0.0.1" true 2>/dev/null; then
	bad "bare public key accepted (AuthorizedKeysFile none not enforced)"
else
	ok "bare public key rejected; only certificates accepted"
fi

say "6. emergency channel isolation"
expect_login "$BG_PORT" "$WORK/keys/bg"    "$BG_KH" "breakglass-ca cert -> breakglass host"
expect_deny  "$BG_PORT" "$WORK/keys/alice" "$BG_KH" "user-ca cert rejected on breakglass host"
expect_deny  "$WEB_PORT" "$WORK/keys/bg"   "$WEB_KH" "breakglass cert rejected on routine host"

say "7. KRL revocation via 20-revoke.sh"
expect_login "$WEB_PORT" "$WORK/keys/alice" "$WEB_KH" "alice works before revocation"
"$HERE/../bin/20-revoke.sh" --user alice >/dev/null
# Attach KRL to the web sshd and reload.
echo "RevokedKeys $CA_ROOT/krl/user-ca.krl" >> "$WORK/web/sshd_config"
"$SSHD_BIN" -t -f "$WORK/web/sshd_config"
kill -HUP "$(cat "$WORK/web/pid")"; sleep 1
expect_deny "$WEB_PORT" "$WORK/keys/alice" "$WEB_KH" "alice rejected after KRL revocation"
# bob is group-denied anyway, so assert the denial reason path independently:
expect_deny "$WEB_PORT" "$WORK/keys/bob" "$WEB_KH" "bob remains correctly group-restricted"

say "8. source-address constrained certificate"
ssh-keygen -t ed25519 -f "$WORK/keys/geo" -N '' -q
ssh-keygen -s "$CA_ROOT/ca/user-ca" -I geo -n group:web,geo -V +4h \
	-O source-address=10.0.0.1/32 -z 9998 "$WORK/keys/geo.pub" >/dev/null
expect_deny "$WEB_PORT" "$WORK/keys/geo" "$WEB_KH" "source-address mismatch rejected"

printf '\n================ RESULT ================\n'
printf 'passed: %d   failed: %d\n' "$PASS" "$FAILED"
[[ "$FAILED" -eq 0 ]] && echo "E2E OK" || { echo "E2E FAILED (workdir kept: $WORK)"; exit 1; }
