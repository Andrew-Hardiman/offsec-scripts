#!/bin/bash
# ssh_enum_tests.sh — Regression tests for ssh_enum.sh
#
# Each test creates an isolated $TESTDIR (under /tmp/<random>) mimicking the
# target filesystem layout (/etc/passwd + /root/.ssh + /etc/ssh + user homes +
# /tmp + pruned-dir placeholders), sed-rewrites a copy of ssh_enum.sh to point
# at it, runs that copy, asserts against expected output, tears down.
#
# Categories:
#   A. Targeted pass — marker emission (positive)
#   B. Targeted pass — denial paths (require non-root execution)
#   C. User enumeration filter (interactive shell + UID gating)
#   D. Content classification edge cases (comments, blanks, hashed entries)
#   E. Wide-pass prune behaviour (kernel pseudo-fs + snap exclusions)
#   F. Wide-pass dedupe (targeted vs SSH_PEM_OUTLIER)
#   G. PEM regex specificity (certs, pubkeys, mid-line not matched)
#   H. Wide-pass size cap (1 MiB boundary)
#   I. Agent sockets (HIJACKABLE / PRESENT / ENV)
#   J. /etc/passwd edge cases (missing, nonexistent home, empty shell field)
#   K. Privilege contexts (standard, root, SUID drop-and-launch)
#   L. detect_enc behaviour
#   M. fingerprint behaviour
#   N. Symlinks (smoke — script must not crash)
#   O. Marker ordering / structural shape
#
# Prerequisites:
#   - bash 4+ (mapfile)
#   - ssh-keygen on PATH (real on Kali; sandbox uses a head-c1-based mock).
#     Used both by the script under test AND by fixture helpers to generate
#     real keys so fingerprint extraction tests work against real ssh-keygen.
#   - python3 (for AF_UNIX socket fixtures)
#   - root + 'nobody' user — required for categories B, K, U. The suite
#     auto-detects this at startup and SKIPS those tests with a clear reason
#     if running unprivileged (run with: sudo bash ssh_enum.tests.sh)
#   - gcc — required for T60 and T80b (SUID drop-and-launch). Skipped if absent.
#
# Run: sudo bash ssh_enum_tests.sh
# Exit code: 0 if all pass; non-zero = failure count.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_SCRIPT="$SCRIPT_DIR/ssh_enum.sh"

if [ ! -f "$TARGET_SCRIPT" ]; then
    echo "ERROR: cannot find ssh_enum.sh at $TARGET_SCRIPT"
    exit 1
fi

PASS=0
FAIL=0
SKIP=0

# ----------------------------------------------------------------------------
# Crash / interrupt cleanup. teardown_fixture handles normal flow; this trap
# catches Ctrl-C and unexpected exits so no /tmp/tmp.* fixture is ever left
# behind (including the SUID-root binary built by T60/T80b). Path-pattern
# guard ensures we only ever rm something matching the mktemp -d shape.
# ----------------------------------------------------------------------------
_cleanup_on_exit() {
    [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null
    if [ -n "$TESTDIR" ] && [ -d "$TESTDIR" ]; then
        case "$TESTDIR" in
            /tmp/tmp.*) rm -rf "$TESTDIR" 2>/dev/null ;;
        esac
    fi
}
trap _cleanup_on_exit EXIT INT TERM

# ----------------------------------------------------------------------------
# Capability detection — privileged tests SKIP with a clear message rather
# than fail or hang when prerequisites are absent. This mirrors the SKIP
# pattern in config_enum_tests.sh.
# ----------------------------------------------------------------------------
IS_ROOT=0
HAS_NOBODY=0
HAS_GCC=0
[ "$(id -u)" = "0" ] && IS_ROOT=1
id nobody >/dev/null 2>&1 && HAS_NOBODY=1
command -v gcc >/dev/null 2>&1 && HAS_GCC=1

echo "Prerequisite detection:"
if [ "$IS_ROOT" = "1" ]; then
    echo "  root:   yes"
else
    echo "  root:   NO  — 11 privileged tests will skip (denial paths, SUID drop-and-launch, agent socket"
    echo "                  ownership). Rerun with: sudo $0"
fi
if [ "$HAS_NOBODY" = "1" ]; then
    echo "  nobody: yes"
else
    echo "  nobody: NO  — privilege-context tests will skip"
fi
if [ "$HAS_GCC" = "1" ]; then
    echo "  gcc:    yes"
else
    echo "  gcc:    NO  — T60 and T80b (SUID drop-and-launch) will skip"
fi
echo

# ============================================================================
# Harness
# ============================================================================

setup_fixture() {
    TESTDIR=$(mktemp -d)
    mkdir -p "$TESTDIR/etc/ssh" "$TESTDIR/root/.ssh" "$TESTDIR/tmp" \
             "$TESTDIR/var/www" "$TESTDIR/opt" \
             "$TESTDIR/proc" "$TESTDIR/sys" "$TESTDIR/dev" "$TESTDIR/run" "$TESTDIR/snap"
    : > "$TESTDIR/etc/passwd"  # default empty; tests add users via mk_user
    # Sed-rewrite all hardcoded paths in ssh_enum.sh to point at $TESTDIR
    sed -e "s|/etc/passwd|$TESTDIR/etc/passwd|g" \
        -e "s|/root/.ssh|$TESTDIR/root/.ssh|g" \
        -e "s|/etc/ssh|$TESTDIR/etc/ssh|g" \
        -e "s|find /tmp|find $TESTDIR/tmp|g" \
        -e "s|find / -type d|find $TESTDIR -type d|g" \
        "$TARGET_SCRIPT" > "$TESTDIR/ssh_enum.sh"
    chmod 755 "$TESTDIR/ssh_enum.sh"
}

teardown_fixture() {
    [ -n "$TESTDIR" ] && [ -d "$TESTDIR" ] && rm -rf "$TESTDIR"
}

# Add an interactive user (UID, home, shell) to fixture /etc/passwd; create home
mk_user() {
    local user="$1" uid="${2:-1000}" home="$3" shell="${4:-/bin/bash}"
    mkdir -p "$home"
    cat >> "$TESTDIR/etc/passwd" <<EOF
$user:x:$uid:$uid::$home:$shell
EOF
}

# Add user to /etc/passwd WITHOUT creating the home dir. Used for tests
# (e.g. T56) that specifically need the home path to NOT exist on disk so
# the script's [ -d "$home/.ssh" ] guard can be exercised.
mk_user_no_home() {
    local user="$1" uid="${2:-1000}" home="$3" shell="${4:-/bin/bash}"
    cat >> "$TESTDIR/etc/passwd" <<EOF
$user:x:$uid:$uid::$home:$shell
EOF
}

# Drop a plain (unencrypted) legacy PEM RSA key at path. Uses real ssh-keygen
# so fingerprint extraction works against real ssh-keygen on Kali. Removes the
# auto-generated .pub sibling to keep test output focused on the privkey marker.
mk_priv_key_plain() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    ssh-keygen -t rsa -b 1024 -m PEM -N "" -f "$path" -q -C "test" </dev/null 2>/dev/null
    rm -f "${path}.pub"
}

# Drop an encrypted legacy PEM RSA key at path (Proc-Type: 4,ENCRYPTED header)
mk_priv_key_encrypted_legacy() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    ssh-keygen -t rsa -b 1024 -m PEM -N "testpass" -f "$path" -q -C "test" </dev/null 2>/dev/null
    rm -f "${path}.pub"
}

# Drop an OpenSSH-format key at path. encrypted=1 -> bcrypt-encrypted with passphrase
mk_priv_key_openssh() {
    local path="$1" encrypted="${2:-0}"
    mkdir -p "$(dirname "$path")"
    if [ "$encrypted" = "1" ]; then
        ssh-keygen -t ed25519 -N "testpass" -f "$path" -q -C "test" </dev/null 2>/dev/null
    else
        ssh-keygen -t ed25519 -N "" -f "$path" -q -C "test" </dev/null 2>/dev/null
    fi
    rm -f "${path}.pub"
}

# Drop a public key
mk_pub_key() {
    local path="$1" ktype="${2:-ssh-rsa}"
    mkdir -p "$(dirname "$path")"
    echo "$ktype AAAApubkeybodybase64 user@host" > "$path"
}

# Drop authorized_keys with content
mk_authkeys() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    shift
    : > "$path"
    for line in "$@"; do
        echo "$line" >> "$path"
    done
}

# Drop ssh config
mk_config() {
    local path="$1"; shift
    mkdir -p "$(dirname "$path")"
    : > "$path"
    for line in "$@"; do
        echo "$line" >> "$path"
    done
}

# Drop known_hosts
mk_known_hosts() {
    local path="$1"; shift
    mkdir -p "$(dirname "$path")"
    : > "$path"
    for line in "$@"; do
        echo "$line" >> "$path"
    done
}

# Background a real AF_UNIX socket at path; populate AGENT_PID for teardown
mk_agent_socket() {
    local path="$1" mode="${2:-600}"
    mkdir -p "$(dirname "$path")"
    python3 -c "
import socket, os, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind('$path')
os.chmod('$path', 0o$mode)
sys.stderr.write('READY\n'); sys.stderr.flush()
time.sleep(60)
" 2>"$TESTDIR/sock.ready" &
    AGENT_PID=$!
    # Wait for socket to be created
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        [ -S "$path" ] && return 0
        sleep 0.05
    done
    return 1
}

kill_agent_socket() {
    [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null
    wait "$AGENT_PID" 2>/dev/null
    AGENT_PID=""
}

# Run the fixture's ssh_enum.sh as the current user — with --wide so wide-pass
# mechanism tests exercise the full code path. SSH_AUTH_SOCK scrubbed to
# prevent contamination from the test runner's real ssh-agent.
run_script() {
    env -u SSH_AUTH_SOCK "$TESTDIR/ssh_enum.sh" --wide 2>/dev/null
}

# Run WITHOUT --wide. Used specifically by gate tests (T81) that verify the
# wide pass is suppressed when the flag is absent.
run_script_fast() {
    env -u SSH_AUTH_SOCK "$TESTDIR/ssh_enum.sh" 2>/dev/null
}

# Run the fixture's ssh_enum.sh as a non-root user (default: nobody).
# Returns sentinel strings on missing prerequisites so callers can skip cleanly:
#   __NEEDS_ROOT__    — script not invoked under sudo/root
#   __NEEDS_NOBODY__  — no nobody user on the system
# </dev/null on the su call is critical: without it, su prompts for nobody's
# password on stdin (PAM), and with stderr hidden the test would freeze
# silently waiting for input.
# SSH_AUTH_SOCK explicitly unset inside the su shell — su's default env
# handling varies by distro/PAM; belt-and-braces.
run_as_nobody() {
    if [ "$IS_ROOT" != "1" ]; then
        echo "__NEEDS_ROOT__"
        return
    fi
    if [ "$HAS_NOBODY" != "1" ]; then
        echo "__NEEDS_NOBODY__"
        return
    fi
    chmod o+x "$TESTDIR" 2>/dev/null
    su nobody -s /bin/bash -c "unset SSH_AUTH_SOCK; $TESTDIR/ssh_enum.sh" </dev/null 2>/dev/null
}

# As run_as_nobody but passes --wide. Used by T80a/T80b to exercise the
# wide-pass READABLE filtering and SUID bypass — the gate must be open for
# those tests to mean anything.
run_as_nobody_wide() {
    if [ "$IS_ROOT" != "1" ]; then
        echo "__NEEDS_ROOT__"
        return
    fi
    if [ "$HAS_NOBODY" != "1" ]; then
        echo "__NEEDS_NOBODY__"
        return
    fi
    chmod o+x "$TESTDIR" 2>/dev/null
    su nobody -s /bin/bash -c "unset SSH_AUTH_SOCK; $TESTDIR/ssh_enum.sh --wide" </dev/null 2>/dev/null
}

# Mark a file as readable by 'other' (so nobody can read it when traversing)
make_readable_to_other() {
    chmod o+r "$1" 2>/dev/null
}

# Assert helpers
assert_contains() {
    local output="$1" expected="$2" name="$3"
    if echo "$output" | grep -qF "$expected"; then
        echo "PASS: $name"
        PASS=$((PASS+1))
    else
        echo "FAIL: $name"
        echo "  Expected output to contain: $expected"
        echo "  Got:"
        echo "$output" | sed 's/^/    /'
        FAIL=$((FAIL+1))
    fi
}

assert_not_contains() {
    local output="$1" pattern="$2" name="$3"
    if echo "$output" | grep -qF "$pattern"; then
        echo "FAIL: $name"
        echo "  Did NOT expect: $pattern"
        echo "  Got:"
        echo "$output" | sed 's/^/    /'
        FAIL=$((FAIL+1))
    else
        echo "PASS: $name"
        PASS=$((PASS+1))
    fi
}

assert_matches_re() {
    local output="$1" regex="$2" name="$3"
    if echo "$output" | grep -qE "$regex"; then
        echo "PASS: $name"
        PASS=$((PASS+1))
    else
        echo "FAIL: $name"
        echo "  Expected regex match: $regex"
        echo "  Got:"
        echo "$output" | sed 's/^/    /'
        FAIL=$((FAIL+1))
    fi
}

assert_skipped() {
    local reason="$1" name="$2"
    echo "SKIP: $name ($reason)"
    SKIP=$((SKIP+1))
}

# Dispatch helpers for run_as_nobody sentinel codes — auto-skip with a clear
# reason when prerequisites are missing, otherwise delegate to assert_nobody_contains.
assert_nobody_contains() {
    local out="$1" expected="$2" name="$3"
    case "$out" in
        __NEEDS_ROOT__)   assert_skipped "requires sudo (running as $(id -un))" "$name" ;;
        __NEEDS_NOBODY__) assert_skipped "no nobody user" "$name" ;;
        *) assert_contains "$out" "$expected" "$name" ;;
    esac
}
assert_nobody_not_contains() {
    local out="$1" pattern="$2" name="$3"
    case "$out" in
        __NEEDS_ROOT__)   assert_skipped "requires sudo (running as $(id -un))" "$name" ;;
        __NEEDS_NOBODY__) assert_skipped "no nobody user" "$name" ;;
        *) assert_not_contains "$out" "$pattern" "$name" ;;
    esac
}

# ============================================================================
# A. Targeted pass — marker emission (positive)
# ============================================================================

# T1: plain RSA key in /root/.ssh/ -> SSH_PRIVKEY [plain]
setup_fixture
mk_priv_key_plain "$TESTDIR/root/.ssh/id_rsa"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/root/.ssh/id_rsa" "T1a: /root/.ssh plain RSA emits SSH_PRIVKEY"
assert_contains "$OUT" "[plain]" "T1b: plain marker present"
assert_contains "$OUT" "SHA256:" "T1c: fingerprint string present"
teardown_fixture

# T2: plain key in /etc/ssh/ -> SSH_PRIVKEY
setup_fixture
mk_priv_key_plain "$TESTDIR/etc/ssh/ssh_host_rsa_key"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/etc/ssh/ssh_host_rsa_key" "T2: /etc/ssh host key emits SSH_PRIVKEY"
teardown_fixture

# T3: plain key in interactive-user ~/.ssh/ -> SSH_PRIVKEY
setup_fixture
mk_user alice 1000 "$TESTDIR/home/alice"
mk_priv_key_plain "$TESTDIR/home/alice/.ssh/id_rsa"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/home/alice/.ssh/id_rsa" "T3: alice's ~/.ssh/id_rsa emits SSH_PRIVKEY"
teardown_fixture

# T4: OpenSSH-format key fixture -> SSH_PRIVKEY (encrypted/plain label tested in L)
setup_fixture
mk_priv_key_openssh "$TESTDIR/root/.ssh/id_ed25519" 0
OUT=$(run_script)
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/root/.ssh/id_ed25519" "T4: OpenSSH-format header detected as SSH_PRIVKEY"
teardown_fixture

# T5: Encrypted legacy PEM (Proc-Type) -> [encrypted]
setup_fixture
mk_priv_key_encrypted_legacy "$TESTDIR/root/.ssh/id_rsa"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/root/.ssh/id_rsa" "T5a: encrypted legacy PEM emits SSH_PRIVKEY"
assert_contains "$OUT" "[encrypted]" "T5b: encrypted marker present"
teardown_fixture

# T6: Arbitrary filename containing PEM block -> SSH_PRIVKEY (classified by content)
setup_fixture
mk_priv_key_plain "$TESTDIR/root/.ssh/some_arbitrary_name"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/root/.ssh/some_arbitrary_name" "T6: arbitrary filename in .ssh/ with PEM body -> SSH_PRIVKEY"
teardown_fixture

# T7: id_rsa.pub -> SSH_PUBKEY
setup_fixture
mk_pub_key "$TESTDIR/root/.ssh/id_rsa.pub" "ssh-rsa"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PUBKEY: $TESTDIR/root/.ssh/id_rsa.pub" "T7: ssh-rsa pubkey -> SSH_PUBKEY"
teardown_fixture

# T8: ed25519 pubkey -> SSH_PUBKEY
setup_fixture
mk_pub_key "$TESTDIR/root/.ssh/id_ed25519.pub" "ssh-ed25519"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PUBKEY: $TESTDIR/root/.ssh/id_ed25519.pub" "T8: ssh-ed25519 pubkey -> SSH_PUBKEY"
teardown_fixture

# T9: ecdsa-sha2 pubkey -> SSH_PUBKEY
setup_fixture
mk_pub_key "$TESTDIR/root/.ssh/id_ecdsa.pub" "ecdsa-sha2-nistp256"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PUBKEY: $TESTDIR/root/.ssh/id_ecdsa.pub" "T9: ecdsa-sha2 pubkey -> SSH_PUBKEY"
teardown_fixture

# T10: authorized_keys -> SSH_AUTHKEYS + indented content lines
setup_fixture
mk_authkeys "$TESTDIR/root/.ssh/authorized_keys" \
    "ssh-rsa AAAA1 alice@laptop" \
    "ssh-ed25519 AAAA2 admin@bastion"
OUT=$(run_script)
assert_contains "$OUT" "SSH_AUTHKEYS: $TESTDIR/root/.ssh/authorized_keys" "T10a: authorized_keys emits SSH_AUTHKEYS"
assert_contains "$OUT" "  ssh-rsa AAAA1 alice@laptop" "T10b: pubkey line emitted indented"
assert_contains "$OUT" "  ssh-ed25519 AAAA2 admin@bastion" "T10c: second pubkey line emitted"
teardown_fixture

# T11: authorized_keys2 variant
setup_fixture
mk_authkeys "$TESTDIR/root/.ssh/authorized_keys2" "ssh-rsa AAAAv2 user2@host"
OUT=$(run_script)
assert_contains "$OUT" "SSH_AUTHKEYS: $TESTDIR/root/.ssh/authorized_keys2" "T11: authorized_keys2 also matches SSH_AUTHKEYS"
teardown_fixture

# T12: ssh config -> SSH_CONFIG + content
setup_fixture
mk_config "$TESTDIR/root/.ssh/config" \
    "Host bastion" \
    "    HostName 10.0.0.5" \
    "    User root" \
    "    IdentityFile ~/.ssh/id_ed25519"
OUT=$(run_script)
assert_contains "$OUT" "SSH_CONFIG: $TESTDIR/root/.ssh/config" "T12a: config emits SSH_CONFIG"
assert_contains "$OUT" "  Host bastion" "T12b: Host line emitted"
assert_contains "$OUT" "  HostName 10.0.0.5" "T12c: HostName line emitted (indent preserved)"
teardown_fixture

# T13: known_hosts -> SSH_KNOWNHOSTS + col-1 hostnames only
setup_fixture
mk_known_hosts "$TESTDIR/root/.ssh/known_hosts" \
    "10.0.0.5 ssh-rsa AAAAhost1" \
    "10.0.0.10,internal.lab ssh-ed25519 AAAAhost2" \
    "github.com,140.82.112.3 ssh-rsa AAAAghkey"
OUT=$(run_script)
assert_contains "$OUT" "SSH_KNOWNHOSTS: $TESTDIR/root/.ssh/known_hosts" "T13a: known_hosts emits SSH_KNOWNHOSTS"
assert_contains "$OUT" "  10.0.0.5" "T13b: bare host in col 1 emitted"
assert_contains "$OUT" "  10.0.0.10" "T13c: comma-list first entry emitted"
assert_contains "$OUT" "  github.com" "T13d: hostname (not IP) preserved"
assert_not_contains "$OUT" "AAAAhost1" "T13e: pubkey body NOT emitted"
assert_not_contains "$OUT" "AAAAghkey" "T13f: pubkey body NOT emitted (2)"
teardown_fixture

# T14: empty .ssh/ for an interactive user -> no markers for that user
setup_fixture
mk_user bob 1001 "$TESTDIR/home/bob"
mkdir -p "$TESTDIR/home/bob/.ssh"
OUT=$(run_script)
assert_not_contains "$OUT" "$TESTDIR/home/bob/.ssh" "T14: empty .ssh dir produces no markers"
teardown_fixture

# T15: SSH_WIDE_PASS_STARTING and SSH_WIDE_PASS_DONE both emitted
setup_fixture
OUT=$(run_script)
assert_contains "$OUT" "SSH_WIDE_PASS_STARTING" "T15a: wide-pass starting marker emitted"
assert_contains "$OUT" "SSH_WIDE_PASS_DONE" "T15b: wide-pass done marker emitted"
teardown_fixture

# ============================================================================
# B. Targeted pass — denial paths (require non-root)
# ============================================================================

# T16: chmod 000 private key -> SSH_PRIVKEY_DENIED (as nobody)
setup_fixture
mk_priv_key_plain "$TESTDIR/root/.ssh/id_rsa"
chmod 000 "$TESTDIR/root/.ssh/id_rsa"
chmod 755 "$TESTDIR/root/.ssh"  # listable, individual file at 000
chmod 755 "$TESTDIR/root"
OUT=$(run_as_nobody)
assert_nobody_contains "$OUT" "SSH_PRIVKEY_DENIED: $TESTDIR/root/.ssh/id_rsa" "T16: chmod 000 id_rsa -> SSH_PRIVKEY_DENIED"
teardown_fixture

# T17: chmod 000 authorized_keys -> SSH_AUTHKEYS_DENIED
setup_fixture
mk_authkeys "$TESTDIR/root/.ssh/authorized_keys" "ssh-rsa AAAA x"
chmod 000 "$TESTDIR/root/.ssh/authorized_keys"
chmod 755 "$TESTDIR/root/.ssh"; chmod 755 "$TESTDIR/root"
OUT=$(run_as_nobody)
assert_nobody_contains "$OUT" "SSH_AUTHKEYS_DENIED: $TESTDIR/root/.ssh/authorized_keys" "T17: chmod 000 authorized_keys -> SSH_AUTHKEYS_DENIED"
teardown_fixture

# T18: chmod 000 config -> SSH_CONFIG_DENIED
setup_fixture
mk_config "$TESTDIR/root/.ssh/config" "Host x"
chmod 000 "$TESTDIR/root/.ssh/config"
chmod 755 "$TESTDIR/root/.ssh"; chmod 755 "$TESTDIR/root"
OUT=$(run_as_nobody)
assert_nobody_contains "$OUT" "SSH_CONFIG_DENIED: $TESTDIR/root/.ssh/config" "T18: chmod 000 config -> SSH_CONFIG_DENIED"
teardown_fixture

# T19: chmod 000 known_hosts -> SSH_KNOWNHOSTS_DENIED
setup_fixture
mk_known_hosts "$TESTDIR/root/.ssh/known_hosts" "host1 ssh-rsa AAAA"
chmod 000 "$TESTDIR/root/.ssh/known_hosts"
chmod 755 "$TESTDIR/root/.ssh"; chmod 755 "$TESTDIR/root"
OUT=$(run_as_nobody)
assert_nobody_contains "$OUT" "SSH_KNOWNHOSTS_DENIED: $TESTDIR/root/.ssh/known_hosts" "T19: chmod 000 known_hosts -> SSH_KNOWNHOSTS_DENIED"
teardown_fixture

# T20: chmod 000 arbitrary file -> SSH_FILE_DENIED (unrecognized name)
setup_fixture
echo "data" > "$TESTDIR/root/.ssh/random.txt"
chmod 000 "$TESTDIR/root/.ssh/random.txt"
chmod 755 "$TESTDIR/root/.ssh"; chmod 755 "$TESTDIR/root"
OUT=$(run_as_nobody)
assert_nobody_contains "$OUT" "SSH_FILE_DENIED: $TESTDIR/root/.ssh/random.txt" "T20: chmod 000 unknown-name file -> SSH_FILE_DENIED"
teardown_fixture

# T21: chmod 700 .ssh dir (cannot list) -> SSH_DIR_DENIED
setup_fixture
mk_priv_key_plain "$TESTDIR/root/.ssh/id_rsa"
chmod 700 "$TESTDIR/root/.ssh"; chmod 755 "$TESTDIR/root"
OUT=$(run_as_nobody)
assert_nobody_contains "$OUT" "SSH_DIR_DENIED: $TESTDIR/root/.ssh" "T21: chmod 700 .ssh as non-owner -> SSH_DIR_DENIED"
teardown_fixture

# ============================================================================
# C. User enumeration filter
# ============================================================================

# T22: UID=1000 + bash -> enumerated
setup_fixture
mk_user alice 1000 "$TESTDIR/home/alice" /bin/bash
mk_priv_key_plain "$TESTDIR/home/alice/.ssh/id_rsa"
OUT=$(run_script)
assert_contains "$OUT" "$TESTDIR/home/alice/.ssh/id_rsa" "T22: UID=1000+bash enumerated"
teardown_fixture

# T23: UID=1500 + zsh -> enumerated
setup_fixture
mk_user dev 1500 "$TESTDIR/home/dev" /usr/bin/zsh
mk_priv_key_plain "$TESTDIR/home/dev/.ssh/id_rsa"
OUT=$(run_script)
assert_contains "$OUT" "$TESTDIR/home/dev/.ssh/id_rsa" "T23: UID=1500+zsh enumerated"
teardown_fixture

# T24: UID=500 (< 1000) -> NOT enumerated even with bash
setup_fixture
mk_user systemd 500 "$TESTDIR/home/systemd" /bin/bash
mk_priv_key_plain "$TESTDIR/home/systemd/.ssh/id_rsa"
OUT=$(run_script)
assert_not_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/home/systemd/.ssh/id_rsa" "T24: UID=500 NOT targeted by targeted pass (below 1000 threshold)"
teardown_fixture

# T25: /usr/sbin/nologin -> NOT enumerated
setup_fixture
mk_user svc 1100 "$TESTDIR/home/svc" /usr/sbin/nologin
mk_priv_key_plain "$TESTDIR/home/svc/.ssh/id_rsa"
OUT=$(run_script)
assert_not_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/home/svc/.ssh/id_rsa" "T25: nologin shell -> NOT targeted by targeted pass"
teardown_fixture

# T26: /bin/false -> NOT enumerated
setup_fixture
mk_user denyme 1200 "$TESTDIR/home/denyme" /bin/false
mk_priv_key_plain "$TESTDIR/home/denyme/.ssh/id_rsa"
OUT=$(run_script)
assert_not_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/home/denyme/.ssh/id_rsa" "T26: /bin/false shell -> NOT targeted"
teardown_fixture

# T27: UID=0 root -> /root/.ssh always in defaults (independent of passwd)
setup_fixture
# Deliberately NO mk_user for root; rely on default SSH_DIRS
mk_priv_key_plain "$TESTDIR/root/.ssh/id_rsa"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/root/.ssh/id_rsa" "T27: /root/.ssh enumerated regardless of /etc/passwd content"
teardown_fixture

# ============================================================================
# D. Content classification edge cases
# ============================================================================

# T28: known_hosts hashed entries (|1|...) filtered
setup_fixture
mk_known_hosts "$TESTDIR/root/.ssh/known_hosts" \
    "10.0.0.5 ssh-rsa AAAAplain" \
    "|1|salt=|hashedhost ssh-rsa AAAAhashed"
OUT=$(run_script)
assert_contains "$OUT" "  10.0.0.5" "T28a: plain hostname emitted"
assert_not_contains "$OUT" "|1|" "T28b: hashed entry filtered out"
teardown_fixture

# T29: known_hosts comment lines filtered
setup_fixture
mk_known_hosts "$TESTDIR/root/.ssh/known_hosts" \
    "# this is a comment" \
    "host1 ssh-rsa AAAA"
OUT=$(run_script)
assert_contains "$OUT" "  host1" "T29a: real host emitted"
assert_not_contains "$OUT" "this is a comment" "T29b: comment line filtered"
teardown_fixture

# T30: authorized_keys blank + comment lines filtered
setup_fixture
mk_authkeys "$TESTDIR/root/.ssh/authorized_keys" \
    "# generated by ansible" \
    "" \
    "ssh-rsa AAAA real@key" \
    ""
OUT=$(run_script)
assert_contains "$OUT" "  ssh-rsa AAAA real@key" "T30a: real key line emitted"
assert_not_contains "$OUT" "generated by ansible" "T30b: comment filtered"
teardown_fixture

# T31: config comment + blank lines filtered
setup_fixture
mk_config "$TESTDIR/root/.ssh/config" \
    "# personal config" \
    "" \
    "Host bastion" \
    "    HostName 10.0.0.5"
OUT=$(run_script)
assert_contains "$OUT" "  Host bastion" "T31a: Host line emitted"
assert_not_contains "$OUT" "personal config" "T31b: comment filtered"
teardown_fixture

# T32: unrecognized file in .ssh/ (no PEM, no pubkey) -> silently ignored (no marker)
setup_fixture
echo "this is random content not a key" > "$TESTDIR/root/.ssh/notes.txt"
OUT=$(run_script)
assert_not_contains "$OUT" "notes.txt" "T32: unrecognized .ssh/ file produces no marker"
teardown_fixture

# ============================================================================
# E. Wide-pass prune behaviour
# ============================================================================

# T33: planted PEM in $TESTDIR/proc/ -> NOT in output
setup_fixture
mk_priv_key_plain "$TESTDIR/proc/planted.key"
OUT=$(run_script)
assert_not_contains "$OUT" "$TESTDIR/proc/planted.key" "T33: /proc pruned in wide pass"
teardown_fixture

# T34: planted in /sys/ -> NOT in output
setup_fixture
mk_priv_key_plain "$TESTDIR/sys/planted.key"
OUT=$(run_script)
assert_not_contains "$OUT" "$TESTDIR/sys/planted.key" "T34: /sys pruned"
teardown_fixture

# T35: planted in /dev/ -> NOT in output
setup_fixture
mk_priv_key_plain "$TESTDIR/dev/planted.key"
OUT=$(run_script)
assert_not_contains "$OUT" "$TESTDIR/dev/planted.key" "T35: /dev pruned"
teardown_fixture

# T36: planted in /run/ -> NOT in output
setup_fixture
mk_priv_key_plain "$TESTDIR/run/planted.key"
OUT=$(run_script)
assert_not_contains "$OUT" "$TESTDIR/run/planted.key" "T36: /run pruned"
teardown_fixture

# T37: planted in /snap/ -> NOT in output
setup_fixture
mkdir -p "$TESTDIR/snap/pkgX"
mk_priv_key_plain "$TESTDIR/snap/pkgX/planted.key"
OUT=$(run_script)
assert_not_contains "$OUT" "$TESTDIR/snap/pkgX/planted.key" "T37: /snap pruned"
teardown_fixture

# T38: planted in /opt/ (NOT pruned, positive control) -> SSH_PEM_OUTLIER
setup_fixture
mk_priv_key_plain "$TESTDIR/opt/keys/legit.key"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PEM_OUTLIER: $TESTDIR/opt/keys/legit.key" "T38: /opt key surfaces as SSH_PEM_OUTLIER"
teardown_fixture

# T39: planted in /var/backups/ (NOT pruned) -> SSH_PEM_OUTLIER
setup_fixture
mkdir -p "$TESTDIR/var/backups"
mk_priv_key_plain "$TESTDIR/var/backups/old.pem"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PEM_OUTLIER: $TESTDIR/var/backups/old.pem" "T39: /var/backups key surfaces"
teardown_fixture

# T40: planted in /var/www/.git/ (dev artifact kept) -> SSH_PEM_OUTLIER
setup_fixture
mkdir -p "$TESTDIR/var/www/.git"
mk_priv_key_plain "$TESTDIR/var/www/.git/leaked.pem"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PEM_OUTLIER: $TESTDIR/var/www/.git/leaked.pem" "T40: .git directory NOT pruned"
teardown_fixture

# ============================================================================
# F. Wide-pass dedupe (targeted overrides outlier)
# ============================================================================

# T41: key in /root/.ssh/ -> SSH_PRIVKEY only, NOT also SSH_PEM_OUTLIER
setup_fixture
mk_priv_key_plain "$TESTDIR/root/.ssh/id_rsa"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/root/.ssh/id_rsa" "T41a: /root/.ssh emits SSH_PRIVKEY"
assert_not_contains "$OUT" "SSH_PEM_OUTLIER: $TESTDIR/root/.ssh/id_rsa" "T41b: /root/.ssh NOT duplicated as OUTLIER"
teardown_fixture

# T42: key in /etc/ssh/ -> SSH_PRIVKEY only
setup_fixture
mk_priv_key_plain "$TESTDIR/etc/ssh/ssh_host_ed25519_key"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/etc/ssh/ssh_host_ed25519_key" "T42a: /etc/ssh emits SSH_PRIVKEY"
assert_not_contains "$OUT" "SSH_PEM_OUTLIER: $TESTDIR/etc/ssh/ssh_host_ed25519_key" "T42b: /etc/ssh NOT duplicated as OUTLIER"
teardown_fixture

# T43: key in user .ssh/ -> SSH_PRIVKEY only
setup_fixture
mk_user alice 1000 "$TESTDIR/home/alice"
mk_priv_key_plain "$TESTDIR/home/alice/.ssh/id_rsa"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/home/alice/.ssh/id_rsa" "T43a: user .ssh emits SSH_PRIVKEY"
assert_not_contains "$OUT" "SSH_PEM_OUTLIER: $TESTDIR/home/alice/.ssh/id_rsa" "T43b: user .ssh NOT duplicated as OUTLIER"
teardown_fixture

# ============================================================================
# G. PEM regex specificity
# ============================================================================

# T44: BEGIN CERTIFICATE (not private key) -> NOT matched by wide pass
setup_fixture
cat > "$TESTDIR/opt/ca.pem" <<'CERT'
-----BEGIN CERTIFICATE-----
MIIBcertmockbody
-----END CERTIFICATE-----
CERT
OUT=$(run_script)
assert_not_contains "$OUT" "$TESTDIR/opt/ca.pem" "T44: BEGIN CERTIFICATE NOT matched as private key"
teardown_fixture

# T45: BEGIN PUBLIC KEY -> NOT matched
setup_fixture
cat > "$TESTDIR/opt/pub.pem" <<'PUB'
-----BEGIN PUBLIC KEY-----
MIIBmockpubbody
-----END PUBLIC KEY-----
PUB
OUT=$(run_script)
assert_not_contains "$OUT" "$TESTDIR/opt/pub.pem" "T45: BEGIN PUBLIC KEY NOT matched"
teardown_fixture

# T46: "private key" prose mid-file (no BEGIN block) -> NOT matched
setup_fixture
cat > "$TESTDIR/opt/note.txt" <<'NOTE'
This is a note about how to store a private key.
It does not contain one.
NOTE
OUT=$(run_script)
assert_not_contains "$OUT" "$TESTDIR/opt/note.txt" "T46: prose mention of 'private key' NOT matched"
teardown_fixture

# T47: PEM block embedded mid-file (not at start of file) -> still matched
setup_fixture
cat > "$TESTDIR/opt/embedded.txt" <<'EMB'
# Some config
some_key = value
some_other = thing

-----BEGIN RSA PRIVATE KEY-----
MOCK_FP=SHA256:embed
mockbody
-----END RSA PRIVATE KEY-----

other_setting = bar
EMB
OUT=$(run_script)
assert_contains "$OUT" "SSH_PEM_OUTLIER: $TESTDIR/opt/embedded.txt" "T47: PEM block mid-file still matched (line-anchored, not file-anchored)"
teardown_fixture

# ============================================================================
# H. Wide-pass size cap (1 MiB)
# ============================================================================

# T48: ~500 KiB file with embedded key -> matched (under cap)
setup_fixture
mkdir -p "$TESTDIR/opt"
{
    head -c 500000 /dev/zero | tr '\0' 'A'
    echo
    echo "-----BEGIN RSA PRIVATE KEY-----"
    echo "MOCK_FP=SHA256:size500"
    echo "mockbody"
    echo "-----END RSA PRIVATE KEY-----"
} > "$TESTDIR/opt/half_meg.txt"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PEM_OUTLIER: $TESTDIR/opt/half_meg.txt" "T48: 500 KiB file with embedded key matched (under 1 MiB cap)"
teardown_fixture

# T49: 2 MiB file with embedded key -> NOT matched (over cap)
setup_fixture
{
    head -c 2200000 /dev/zero | tr '\0' 'A'
    echo
    echo "-----BEGIN RSA PRIVATE KEY-----"
    echo "MOCK_FP=SHA256:size2m"
    echo "-----END RSA PRIVATE KEY-----"
} > "$TESTDIR/opt/two_meg.txt"
OUT=$(run_script)
assert_not_contains "$OUT" "$TESTDIR/opt/two_meg.txt" "T49: 2 MiB file NOT matched (over 1 MiB cap)"
teardown_fixture

# T50: ~900 KiB file just under cap -> matched (boundary)
setup_fixture
{
    head -c 900000 /dev/zero | tr '\0' 'A'
    echo
    echo "-----BEGIN RSA PRIVATE KEY-----"
    echo "MOCK_FP=SHA256:size900"
    echo "-----END RSA PRIVATE KEY-----"
} > "$TESTDIR/opt/under_meg.txt"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PEM_OUTLIER: $TESTDIR/opt/under_meg.txt" "T50: 900 KiB file matched (under 1 MiB)"
teardown_fixture

# ============================================================================
# I. Agent sockets
# ============================================================================

# T51: real AF_UNIX socket owned by current user, mode 600 -> SSH_AGENT_HIJACKABLE
setup_fixture
mkdir -p "$TESTDIR/tmp/ssh-XXXXXX"
if mk_agent_socket "$TESTDIR/tmp/ssh-XXXXXX/agent.9999" 600; then
    OUT=$(run_script)
    assert_contains "$OUT" "SSH_AGENT_HIJACKABLE: $TESTDIR/tmp/ssh-XXXXXX/agent.9999" "T51: own-owned 600 socket -> HIJACKABLE"
    kill_agent_socket
else
    assert_skipped "socket creation failed" "T51"
fi
teardown_fixture

# T52: socket owned by another user (root-owned, run as nobody) -> SSH_AGENT_PRESENT
setup_fixture
mkdir -p "$TESTDIR/tmp/ssh-XXXXXX"
if mk_agent_socket "$TESTDIR/tmp/ssh-XXXXXX/agent.9999" 600; then
    chmod o+rx "$TESTDIR/tmp" "$TESTDIR/tmp/ssh-XXXXXX"
    OUT=$(run_as_nobody)
    assert_nobody_contains "$OUT" "SSH_AGENT_PRESENT: $TESTDIR/tmp/ssh-XXXXXX/agent.9999" "T52: other-owned socket -> PRESENT (not HIJACKABLE)"
    kill_agent_socket
else
    assert_skipped "socket creation failed" "T52"
fi
teardown_fixture

# T53: SSH_AUTH_SOCK env var set -> SSH_AGENT_ENV emitted
setup_fixture
OUT=$(SSH_AUTH_SOCK=/tmp/fake.sock "$TESTDIR/ssh_enum.sh" 2>/dev/null)
assert_contains "$OUT" "SSH_AGENT_ENV: /tmp/fake.sock" "T53: SSH_AUTH_SOCK env var emitted"
teardown_fixture

# T54: regular file (not a socket) named agent.X -> NOT emitted
setup_fixture
mkdir -p "$TESTDIR/tmp/ssh-X"
touch "$TESTDIR/tmp/ssh-X/agent.1234"
OUT=$(run_script)
assert_not_contains "$OUT" "SSH_AGENT" "T54: regular file with agent.* name NOT emitted (find -type s required)"
teardown_fixture

# ============================================================================
# J. /etc/passwd edge cases
# ============================================================================

# T55: missing /etc/passwd -> script still runs, defaults still scanned
setup_fixture
rm -f "$TESTDIR/etc/passwd"
mk_priv_key_plain "$TESTDIR/root/.ssh/id_rsa"
OUT=$(run_script 2>&1)  # may emit shell-level "no such file" diagnostics
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/root/.ssh/id_rsa" "T55: /root/.ssh still scanned with missing /etc/passwd"
teardown_fixture

# T56: user with /nonexistent home -> skipped via [ -d $home/.ssh ] guard
setup_fixture
mk_user_no_home ghost 1300 "/nonexistent_path_xyz"
OUT=$(run_script)
assert_not_contains "$OUT" "/nonexistent_path_xyz" "T56: non-existent home path NOT enumerated"
teardown_fixture

# T57: user with empty shell field -> currently falls into default ENUM branch
setup_fixture
echo "weirduser:x:1400:1400::$TESTDIR/home/weirduser:" >> "$TESTDIR/etc/passwd"
mkdir -p "$TESTDIR/home/weirduser/.ssh"
mk_priv_key_plain "$TESTDIR/home/weirduser/.ssh/id_rsa"
OUT=$(run_script)
assert_contains "$OUT" "$TESTDIR/home/weirduser/.ssh/id_rsa" "T57: empty shell field -> user enumerated (not in skip list)"
teardown_fixture

# ============================================================================
# K. Privilege contexts
# ============================================================================

# T58: standard context (run as nobody) -> [-readable] active, denied root key skipped
setup_fixture
mk_priv_key_plain "$TESTDIR/root/.ssh/id_rsa"
chmod 600 "$TESTDIR/root/.ssh/id_rsa"
chmod 700 "$TESTDIR/root/.ssh"; chmod 755 "$TESTDIR/root"
OUT=$(run_as_nobody)
assert_nobody_contains "$OUT" "SSH_DIR_DENIED: $TESTDIR/root/.ssh" "T58: standard context — locked /root/.ssh emits DIR_DENIED"
teardown_fixture

# T59: root context (default sandbox run) -> sees everything
setup_fixture
mk_priv_key_plain "$TESTDIR/root/.ssh/id_rsa"
chmod 600 "$TESTDIR/root/.ssh/id_rsa"
chmod 700 "$TESTDIR/root/.ssh"
OUT=$(run_script)  # as root
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/root/.ssh/id_rsa" "T59: root context reads 700/600 key"
teardown_fixture

# T60: SUID drop-and-launch (RUID!=EUID, EUID=0) -> sees root-owned key
setup_fixture
if [ "$IS_ROOT" != "1" ]; then
    assert_skipped "requires sudo (running as $(id -un))" "T60"
elif [ "$HAS_GCC" != "1" ]; then
    assert_skipped "gcc not available" "T60"
elif [ "$HAS_NOBODY" != "1" ]; then
    assert_skipped "no nobody user" "T60"
else
    mk_priv_key_plain "$TESTDIR/root/.ssh/id_rsa"
    chmod 600 "$TESTDIR/root/.ssh/id_rsa"
    chmod 700 "$TESTDIR/root/.ssh"
    chmod 755 "$TESTDIR/root"
    chmod o+x "$TESTDIR"
    cat > "$TESTDIR/suid_wrap.c" <<CC
#include <unistd.h>
int main(int argc, char **argv) {
    char *args[] = {"bash", "-p", "$TESTDIR/ssh_enum.sh", NULL};
    execv("/bin/bash", args);
    return 1;
}
CC
    gcc "$TESTDIR/suid_wrap.c" -o "$TESTDIR/suid_wrap" 2>/dev/null
    chown root:root "$TESTDIR/suid_wrap"
    # 4711 (rws--x--x): setuid + exec-only for group/other. Cannot be read or
    # copied by nobody, only executed. Tighter than 4755 with no functional cost.
    chmod 4711 "$TESTDIR/suid_wrap"
    OUT=$(su nobody -s /bin/bash -c "$TESTDIR/suid_wrap" </dev/null 2>/dev/null)
    # Drop the setuid bit immediately. From here on, even if the trap fails to
    # fire (kill -9, crash), the file is a plain binary, not a privilege artifact.
    chmod u-s "$TESTDIR/suid_wrap" 2>/dev/null
    assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/root/.ssh/id_rsa" "T60: SUID mode (RUID!=EUID=0) reads root-owned 600 key"
fi
teardown_fixture

# ============================================================================
# L. detect_enc behaviour
# ============================================================================

# T61: legacy PEM no Proc-Type -> [plain]
setup_fixture
mk_priv_key_plain "$TESTDIR/root/.ssh/id_rsa"
OUT=$(run_script)
assert_matches_re "$OUT" "SSH_PRIVKEY: $TESTDIR/root/.ssh/id_rsa \[plain\]" "T61: legacy PEM without Proc-Type -> [plain]"
teardown_fixture

# T62: legacy PEM with Proc-Type: 4,ENCRYPTED -> [encrypted]
setup_fixture
mk_priv_key_encrypted_legacy "$TESTDIR/root/.ssh/id_rsa"
OUT=$(run_script)
assert_matches_re "$OUT" "SSH_PRIVKEY: $TESTDIR/root/.ssh/id_rsa \[encrypted\]" "T62: legacy PEM Proc-Type: 4,ENCRYPTED -> [encrypted]"
teardown_fixture

# T63: OpenSSH format - hardcoded fixture with MOCK_ENCRYPTED marker -> [encrypted]
setup_fixture
mk_priv_key_openssh "$TESTDIR/root/.ssh/id_ed25519" 1
OUT=$(run_script)
assert_matches_re "$OUT" "SSH_PRIVKEY: $TESTDIR/root/.ssh/id_ed25519 \[encrypted\]" "T63: OpenSSH format encrypted -> [encrypted]"
teardown_fixture

# ============================================================================
# M. fingerprint behaviour
# ============================================================================

# T64: plain key with MOCK_FP marker -> fingerprint string present in output
setup_fixture
mk_priv_key_plain "$TESTDIR/root/.ssh/id_rsa"
OUT=$(run_script)
assert_matches_re "$OUT" "SSH_PRIVKEY: .* \[plain\] \[SHA256:" "T64: fingerprint format SHA256:<...> emitted"
teardown_fixture

# T65: corrupt PEM (no extractable key) -> [no-fp] OR a fingerprint, but marker still emits
setup_fixture
# Content with BEGIN header but garbage body — ssh-keygen would fail to read
cat > "$TESTDIR/root/.ssh/corrupt_key" <<'KEY'
-----BEGIN RSA PRIVATE KEY-----
notreallybase64atall
-----END RSA PRIVATE KEY-----
KEY
OUT=$(run_script)
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/root/.ssh/corrupt_key" "T65a: corrupt key still emits SSH_PRIVKEY marker"
assert_matches_re "$OUT" "SSH_PRIVKEY: .*corrupt_key \[(plain|encrypted)\] \[(SHA256:|no-fp)" "T65b: marker shape preserved even on corrupt content"
teardown_fixture

# ============================================================================
# N. Symlinks (smoke — must not crash)
# ============================================================================

# T66: symlinked file inside .ssh/ -> script does not crash; result either follows or skips
setup_fixture
mk_priv_key_plain "$TESTDIR/opt/real_key"
ln -s "$TESTDIR/opt/real_key" "$TESTDIR/root/.ssh/id_rsa"
OUT=$(run_script)
# Don't assert about content — symlink behaviour is "either followed or not"
# but the script MUST NOT crash or produce error output
assert_contains "$OUT" "SSH_WIDE_PASS_DONE" "T66: symlinked key file does not crash script (reaches wide-pass done)"
teardown_fixture

# T67: symlinked directory (entire .ssh/) -> no crash
setup_fixture
mkdir -p "$TESTDIR/somewhere"
mk_priv_key_plain "$TESTDIR/somewhere/id_rsa"
rmdir "$TESTDIR/root/.ssh"
ln -s "$TESTDIR/somewhere" "$TESTDIR/root/.ssh"
OUT=$(run_script)
assert_contains "$OUT" "SSH_WIDE_PASS_DONE" "T67: symlinked .ssh directory does not crash script"
teardown_fixture

# ============================================================================
# O. Marker ordering / structural shape
# ============================================================================

# T68: SSH_WIDE_PASS_STARTING precedes SSH_WIDE_PASS_DONE in output
setup_fixture
mk_priv_key_plain "$TESTDIR/opt/somekey.pem"
OUT=$(run_script)
# Line numbers
START_LINE=$(echo "$OUT" | grep -n "SSH_WIDE_PASS_STARTING" | head -1 | cut -d: -f1)
DONE_LINE=$(echo "$OUT" | grep -n "SSH_WIDE_PASS_DONE" | head -1 | cut -d: -f1)
OUTLIER_LINE=$(echo "$OUT" | grep -n "SSH_PEM_OUTLIER: $TESTDIR/opt/somekey.pem" | head -1 | cut -d: -f1)
if [ -n "$START_LINE" ] && [ -n "$DONE_LINE" ] && [ -n "$OUTLIER_LINE" ] \
   && [ "$START_LINE" -lt "$OUTLIER_LINE" ] && [ "$OUTLIER_LINE" -lt "$DONE_LINE" ]; then
    echo "PASS: T68: wide-pass markers bracket SSH_PEM_OUTLIER (STARTING < outlier < DONE)"
    PASS=$((PASS+1))
else
    echo "FAIL: T68: ordering violated (start=$START_LINE, outlier=$OUTLIER_LINE, done=$DONE_LINE)"
    FAIL=$((FAIL+1))
fi
teardown_fixture

# T69: targeted-pass markers appear BEFORE wide-pass markers
setup_fixture
mk_priv_key_plain "$TESTDIR/root/.ssh/id_rsa"
mk_priv_key_plain "$TESTDIR/opt/outlier.pem"
OUT=$(run_script)
TARGETED_LINE=$(echo "$OUT" | grep -n "SSH_PRIVKEY: $TESTDIR/root/.ssh/id_rsa" | head -1 | cut -d: -f1)
START_LINE=$(echo "$OUT" | grep -n "SSH_WIDE_PASS_STARTING" | head -1 | cut -d: -f1)
if [ -n "$TARGETED_LINE" ] && [ -n "$START_LINE" ] && [ "$TARGETED_LINE" -lt "$START_LINE" ]; then
    echo "PASS: T69: targeted SSH_PRIVKEY emitted before SSH_WIDE_PASS_STARTING"
    PASS=$((PASS+1))
else
    echo "FAIL: T69: ordering violated (targeted=$TARGETED_LINE, start=$START_LINE)"
    FAIL=$((FAIL+1))
fi
teardown_fixture

# ============================================================================
# P. Additional key formats (PKCS#8 plain/encrypted, DSA, EC)
# ============================================================================

# T70: PKCS#8 plain (BEGIN PRIVATE KEY — no algorithm token) -> SSH_PRIVKEY [plain]
setup_fixture
cat > "$TESTDIR/root/.ssh/key_pkcs8_plain" <<'KEY'
-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg
-----END PRIVATE KEY-----
KEY
OUT=$(run_script)
assert_matches_re "$OUT" "SSH_PRIVKEY: $TESTDIR/root/\.ssh/key_pkcs8_plain \[plain\]" "T70: PKCS#8 plain (BEGIN PRIVATE KEY) detected as SSH_PRIVKEY [plain]"
teardown_fixture

# T71: PKCS#8 ENCRYPTED (BEGIN ENCRYPTED PRIVATE KEY) -> SSH_PRIVKEY [encrypted]
setup_fixture
cat > "$TESTDIR/root/.ssh/key_pkcs8_enc" <<'KEY'
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI
-----END ENCRYPTED PRIVATE KEY-----
KEY
OUT=$(run_script)
assert_matches_re "$OUT" "SSH_PRIVKEY: $TESTDIR/root/\.ssh/key_pkcs8_enc \[encrypted\]" "T71: PKCS#8 ENCRYPTED header -> SSH_PRIVKEY [encrypted]"
teardown_fixture

# T72: DSA legacy PEM (BEGIN DSA PRIVATE KEY) -> SSH_PRIVKEY [plain]
setup_fixture
cat > "$TESTDIR/root/.ssh/key_dsa" <<'KEY'
-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQDhVNmockdsa
-----END DSA PRIVATE KEY-----
KEY
OUT=$(run_script)
assert_matches_re "$OUT" "SSH_PRIVKEY: $TESTDIR/root/\.ssh/key_dsa \[plain\]" "T72: DSA legacy PEM -> SSH_PRIVKEY [plain]"
teardown_fixture

# T73: EC legacy PEM (BEGIN EC PRIVATE KEY) -> SSH_PRIVKEY [plain]
setup_fixture
cat > "$TESTDIR/root/.ssh/key_ec" <<'KEY'
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDz1iWMmmockec
-----END EC PRIVATE KEY-----
KEY
OUT=$(run_script)
assert_matches_re "$OUT" "SSH_PRIVKEY: $TESTDIR/root/\.ssh/key_ec \[plain\]" "T73: EC legacy PEM -> SSH_PRIVKEY [plain]"
teardown_fixture

# T74: legacy PEM with Proc-Type + DSA header -> [encrypted] (encryption detection
# independent of algorithm-token in header)
setup_fixture
cat > "$TESTDIR/root/.ssh/key_dsa_enc" <<'KEY'
-----BEGIN DSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,0123456789ABCDEF

MIIBuwIBAAKBgQDhVNmockencrypteddsa
-----END DSA PRIVATE KEY-----
KEY
OUT=$(run_script)
assert_matches_re "$OUT" "SSH_PRIVKEY: $TESTDIR/root/\.ssh/key_dsa_enc \[encrypted\]" "T74: encrypted DSA legacy PEM detected as [encrypted]"
teardown_fixture

# ============================================================================
# Q. known_hosts @-markers (CA / revoked entries)
# ============================================================================

# T75: @cert-authority and @revoked lines preserve the hostname (col 2) alongside
# the marker. Comma-separated host lists in col 2 are split, first entry taken.
setup_fixture
mk_known_hosts "$TESTDIR/root/.ssh/known_hosts" \
    "10.0.0.5 ssh-rsa AAAAplain" \
    "@cert-authority *.lab.example.com ssh-rsa AAAAcakey" \
    "@revoked old-host ssh-rsa AAAArevkey"
OUT=$(run_script)
assert_contains "$OUT" "  10.0.0.5" "T75a: normal entry emits hostname"
assert_contains "$OUT" "  @cert-authority *.lab.example.com" "T75b: @cert-authority emits marker + hostname"
assert_contains "$OUT" "  @revoked old-host" "T75c: @revoked emits marker + hostname"
assert_not_contains "$OUT" "AAAAcakey" "T75d: key body not emitted"
teardown_fixture

# ============================================================================
# R. Multi-user fixture (concurrent .ssh dirs)
# ============================================================================

# T76: three interactive users, each with a key -> all enumerated
setup_fixture
mk_user alice 1000 "$TESTDIR/home/alice"
mk_user bob   1001 "$TESTDIR/home/bob"
mk_user carol 1002 "$TESTDIR/home/carol"
mk_priv_key_plain "$TESTDIR/home/alice/.ssh/id_rsa"
mk_priv_key_plain "$TESTDIR/home/bob/.ssh/id_ed25519"
mk_priv_key_plain "$TESTDIR/home/carol/.ssh/id_ecdsa"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/home/alice/.ssh/id_rsa" "T76a: alice's key emitted"
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/home/bob/.ssh/id_ed25519" "T76b: bob's key emitted"
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/home/carol/.ssh/id_ecdsa" "T76c: carol's key emitted"
teardown_fixture

# T77: mixed interactive + non-interactive users — only interactive enumerated
setup_fixture
mk_user alice  1000 "$TESTDIR/home/alice"     /bin/bash
mk_user daemon 200  "$TESTDIR/home/daemon"    /bin/bash       # UID below 1000
mk_user svc    1500 "$TESTDIR/home/svc"       /usr/sbin/nologin
mk_priv_key_plain "$TESTDIR/home/alice/.ssh/id_rsa"
mk_priv_key_plain "$TESTDIR/home/daemon/.ssh/id_rsa"
mk_priv_key_plain "$TESTDIR/home/svc/.ssh/id_rsa"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/home/alice/.ssh/id_rsa" "T77a: alice (1000,bash) enumerated"
assert_not_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/home/daemon/.ssh" "T77b: daemon (UID<1000) NOT targeted by targeted pass"
assert_not_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/home/svc/.ssh" "T77c: svc (nologin) NOT targeted"
teardown_fixture

# ============================================================================
# S. Truncated / malformed PEM (BEGIN without END)
# ============================================================================

# T78: file with BEGIN header but no END marker -> still detected (grep matches
# BEGIN line alone; the script doesn't attempt to parse the whole block)
setup_fixture
cat > "$TESTDIR/root/.ssh/truncated_key" <<'KEY'
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBA...
KEY
OUT=$(run_script)
assert_contains "$OUT" "SSH_PRIVKEY: $TESTDIR/root/.ssh/truncated_key" "T78: truncated PEM (BEGIN, no END) still detected as SSH_PRIVKEY"
teardown_fixture

# ============================================================================
# T. authorized_keys with many entries
# ============================================================================

# T79: 8-entry authorized_keys -> all real entries emitted (not just first)
setup_fixture
mk_authkeys "$TESTDIR/root/.ssh/authorized_keys" \
    "ssh-rsa AAAA1 alice@laptop" \
    "ssh-ed25519 AAAA2 bob@desktop" \
    "ecdsa-sha2-nistp256 AAAA3 carol@phone" \
    "ssh-rsa AAAA4 dave@ci" \
    "ssh-ed25519 AAAA5 eve@bastion" \
    "ssh-rsa AAAA6 frank@backup" \
    "ssh-ed25519 AAAA7 grace@workstation" \
    "ssh-rsa AAAA8 henry@admin"
OUT=$(run_script)
assert_contains "$OUT" "alice@laptop"      "T79a: entry 1 emitted"
assert_contains "$OUT" "bob@desktop"       "T79b: entry 2 emitted"
assert_contains "$OUT" "carol@phone"       "T79c: entry 3 emitted"
assert_contains "$OUT" "dave@ci"           "T79d: entry 4 emitted"
assert_contains "$OUT" "eve@bastion"       "T79e: entry 5 emitted"
assert_contains "$OUT" "frank@backup"      "T79f: entry 6 emitted"
assert_contains "$OUT" "grace@workstation" "T79g: entry 7 emitted"
assert_contains "$OUT" "henry@admin"       "T79h: entry 8 emitted"
teardown_fixture

# ============================================================================
# U. SUID wide-pass contrast (READABLE=() exercised in find)
# ============================================================================
# These two tests sit on the same fixture (root-owned mode-600 key in /opt/)
# and contrast standard-nobody+--wide mode vs SUID-nobody+--wide mode. Both
# tests must pass --wide so the wide-pass READABLE logic is actually exercised;
# the gate being open is a precondition, not what's being tested here.

# T80a: nobody+--wide -> find -readable filters out root-owned key
setup_fixture
mkdir -p "$TESTDIR/opt"
mk_priv_key_plain "$TESTDIR/opt/secret.pem"
chmod 600 "$TESTDIR/opt/secret.pem"  # root-owned; nobody cannot read via find -readable
OUT=$(run_as_nobody_wide)
assert_nobody_not_contains "$OUT" "$TESTDIR/opt/secret.pem" "T80a: nobody+--wide — root-owned 600 key filtered by find -readable"
teardown_fixture

# T80b: SUID-nobody+--wide -> same fixture surfaces as SSH_PEM_OUTLIER
setup_fixture
if [ "$IS_ROOT" != "1" ]; then
    assert_skipped "requires sudo (running as $(id -un))" "T80b"
elif [ "$HAS_GCC" != "1" ]; then
    assert_skipped "gcc not available" "T80b"
elif [ "$HAS_NOBODY" != "1" ]; then
    assert_skipped "no nobody user" "T80b"
else
    mkdir -p "$TESTDIR/opt"
    mk_priv_key_plain "$TESTDIR/opt/secret.pem"
    chmod 600 "$TESTDIR/opt/secret.pem"
    chmod o+x "$TESTDIR"
    cat > "$TESTDIR/suid_wrap.c" <<CC
#include <unistd.h>
int main(int argc, char **argv) {
    char *args[] = {"bash", "-p", "$TESTDIR/ssh_enum.sh", "--wide", NULL};
    execv("/bin/bash", args);
    return 1;
}
CC
    gcc "$TESTDIR/suid_wrap.c" -o "$TESTDIR/suid_wrap" 2>/dev/null
    chown root:root "$TESTDIR/suid_wrap"
    chmod 4711 "$TESTDIR/suid_wrap"
    OUT=$(su nobody -s /bin/bash -c "$TESTDIR/suid_wrap" </dev/null 2>/dev/null)
    chmod u-s "$TESTDIR/suid_wrap" 2>/dev/null
    assert_contains "$OUT" "SSH_PEM_OUTLIER: $TESTDIR/opt/secret.pem" "T80b: SUID-nobody+--wide (READABLE=()) — root-owned key surfaces as SSH_PEM_OUTLIER"
fi
teardown_fixture

# ============================================================================
# V. Gate, dedupe-fix, fingerprint-fix, and /usr/share/doc prune tests
# ============================================================================

# T81: no --wide flag -> SSH_WIDE_PASS_STARTING not emitted (gate suppresses wide pass)
setup_fixture
OUT=$(run_script_fast)
assert_not_contains "$OUT" "SSH_WIDE_PASS_STARTING" "T81: no --wide — wide-pass gate suppresses scan"
teardown_fixture

# T82: --wide flag -> SSH_WIDE_PASS_STARTING and DONE both emitted
setup_fixture
OUT=$(run_script)
assert_contains "$OUT" "SSH_WIDE_PASS_STARTING" "T82a: --wide — wide-pass gate opens"
assert_contains "$OUT" "SSH_WIDE_PASS_DONE"     "T82b: --wide — wide-pass done marker present"
teardown_fixture

# T83: key at $TESTDIR/.ssh/ (a /.ssh/ equivalent — non-standard .ssh at fixture root,
# not in any user's home, not in SSH_DIRS defaults) with --wide -> SSH_PEM_OUTLIER
# This is the dedupe-fix regression: the old */.ssh/* case pattern silently skipped
# this path; is_in_targeted_dirs() correctly surfaces it.
setup_fixture
mkdir -p "$TESTDIR/.ssh"
mk_priv_key_plain "$TESTDIR/.ssh/root_key"
OUT=$(run_script)
assert_contains "$OUT" "SSH_PEM_OUTLIER: $TESTDIR/.ssh/root_key" "T83: /.ssh/ not in SSH_DIRS — wide pass surfaces key (dedupe fix)"
teardown_fixture

# T84: combined cert+privkey in outlier location — wide pass finds it (grep
# matches the PRIVATE KEY line wherever it appears in the file); fingerprint
# must be SHA256:... or no-fp, never garbage error text ("is", "not", etc.)
# Before fingerprint fix: ssh-keygen -lf on a cert-prefixed file could emit
# "file is not a public key file" → old awk captured "is" as $2.
setup_fixture
mkdir -p "$TESTDIR/opt"
cat > "$TESTDIR/opt/combined.pem" <<'KEY'
-----BEGIN CERTIFICATE-----
MIIBmockCertBody==
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAMmockPrivKeyBody==
-----END RSA PRIVATE KEY-----
KEY
OUT=$(run_script)
assert_matches_re "$OUT" "SSH_PEM_OUTLIER: $TESTDIR/opt/combined\.pem \[(plain|encrypted)\] \[(SHA256:|no-fp)" "T84: combined cert+privkey outlier — fingerprint is SHA256: or no-fp, not garbage error text"
teardown_fixture

# T85: key in /usr/share/doc equivalent -> NOT in output even with --wide
# Package documentation demo keys have no operational authority; pure noise.
setup_fixture
mkdir -p "$TESTDIR/usr/share/doc/libssl-dev/demos"
mk_priv_key_plain "$TESTDIR/usr/share/doc/libssl-dev/demos/privkey.pem"
OUT=$(run_script)
assert_not_contains "$OUT" "$TESTDIR/usr/share/doc" "T85: /usr/share/doc pruned — package doc keys not reported"
teardown_fixture

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "============================="
echo "PASSED:  $PASS"
echo "FAILED:  $FAIL"
echo "SKIPPED: $SKIP"
echo "============================="
exit "$FAIL"
