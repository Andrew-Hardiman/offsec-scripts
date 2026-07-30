#!/bin/bash
# af_unix_sock_enum.tests.sh — Regression tests for af_unix_sock_enum.sh
#
# Each test creates an isolated /tmp/<random> directory, populates it with
# real AF_UNIX sockets (bind()-created via Python) at fixture-relative paths,
# sed-rewrites a copy of af_unix_sock_enum.sh to point at the fixture root
# and (for most tests) neutralise the -not -user "$(id -u)" ownership filter
# — because fixture sockets are owned by the test user, and the production
# filter would exclude them all. A dedicated test (T5) exercises the
# ownership filter separately.
#
# Run: ./af_unix_sock_enum.tests.sh
# Exit code: 0 if all pass, non-zero count = failures.
# T6 (non-writable exclusion) requires non-root execution; auto-skipped under uid=0.
#
# Python3 required for socket bind() (no shell primitive for AF_UNIX bind).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_SCRIPT="$SCRIPT_DIR/af_unix_sock_enum.sh"

if [ ! -f "$TARGET_SCRIPT" ]; then
  echo "ERROR: cannot find af_unix_sock_enum.sh at $TARGET_SCRIPT"
  exit 1
fi

command -v python3 >/dev/null || { echo "ERROR: python3 required"; exit 1; }

PASS=0
FAIL=0
SKIP=0

# Standard fixture: rewrites hardcoded scope paths to fixture root AND
# neutralises the -not -user filter (fixture sockets are test-user-owned).
setup_fixture() {
  TESTDIR=$(mktemp -d)
  sed -e "s|/var/run /run /tmp /var/lib /var/snap|$TESTDIR|g" \
      -e 's| -not -user "$(id -u)"||g' \
      "$TARGET_SCRIPT" > "$TESTDIR/af_unix_sock_enum.sh"
  chmod +x "$TESTDIR/af_unix_sock_enum.sh"
}

# Owner-filter-preserving fixture: for T5 (foothold-owned exclusion) —
# keeps the -not -user filter so fixture sockets owned by the test user
# get excluded, verifying production filter semantics.
setup_fixture_keep_owner_filter() {
  TESTDIR=$(mktemp -d)
  sed -e "s|/var/run /run /tmp /var/lib /var/snap|$TESTDIR|g" \
      "$TARGET_SCRIPT" > "$TESTDIR/af_unix_sock_enum.sh"
  chmod +x "$TESTDIR/af_unix_sock_enum.sh"
}

teardown_fixture() {
  rm -rf "$TESTDIR"
}

# mksock <path> [<mode>] — create real AF_UNIX socket at <path> with <mode>
# (default 666). Parent directory auto-created.
mksock() {
  local path="$1"
  local mode="${2:-666}"
  mkdir -p "$(dirname "$path")"
  python3 -c "
import socket, os
try: os.unlink('$path')
except FileNotFoundError: pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind('$path')
os.chmod('$path', 0o$mode)
"
}

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
    echo "  Did NOT expect output to contain: $pattern"
    echo "  Got:"
    echo "$output" | sed 's/^/    /'
    FAIL=$((FAIL+1))
  else
    echo "PASS: $name"
    PASS=$((PASS+1))
  fi
}

assert_equals() {
  local output="$1" expected="$2" name="$3"
  if [ "$output" = "$expected" ]; then
    echo "PASS: $name"
    PASS=$((PASS+1))
  else
    echo "FAIL: $name"
    echo "  Expected:"
    echo "$expected" | sed 's/^/    /'
    echo "  Got:"
    echo "$output" | sed 's/^/    /'
    FAIL=$((FAIL+1))
  fi
}

# ============================================================================
# T1: Empty scope — no sockets. Expect only terminator.
# ============================================================================
setup_fixture
OUT=$("$TESTDIR/af_unix_sock_enum.sh")
assert_equals "$OUT" "AF_UNIX_SOCK_SCANNED" "T1: empty scope emits only terminator"
teardown_fixture

# ============================================================================
# T2: Real-target noise — Ubuntu (17) + Kali (5) + THM (1) baseline paths.
# All must be silently dropped by the blacklist. Regression guard against
# blacklist pattern drift on real stock installs.
# ============================================================================
setup_fixture
mksock "$TESTDIR/run/uuidd/request"
mksock "$TESTDIR/run/snapd-snap.socket"
mksock "$TESTDIR/run/snapd.socket"
mksock "$TESTDIR/run/cups/cups.sock"
mksock "$TESTDIR/run/avahi-daemon/socket"
mksock "$TESTDIR/run/dbus/system_bus_socket"
mksock "$TESTDIR/run/systemd/resolve/io.systemd.Resolve"
mksock "$TESTDIR/run/systemd/oom/io.systemd.ManagedOOM"
mksock "$TESTDIR/run/systemd/journal/stdout"
mksock "$TESTDIR/run/systemd/journal/socket"
mksock "$TESTDIR/run/systemd/journal/dev-log"
mksock "$TESTDIR/run/systemd/journal/syslog"
mksock "$TESTDIR/run/systemd/io.systemd.ManagedOOM"
mksock "$TESTDIR/run/systemd/userdb/io.systemd.DynamicUser"
mksock "$TESTDIR/run/systemd/notify"
mksock "$TESTDIR/tmp/.ICE-unix/2538"
mksock "$TESTDIR/var/snap/canonical-livepatch/406/livepatchd.sock"
mksock "$TESTDIR/run/ssh-unix-local/socket"
mksock "$TESTDIR/run/polkit/agent-helper.socket"
mksock "$TESTDIR/run/pcscd/pcscd.comm"
mksock "$TESTDIR/tmp/.iprt-localipc-DRMIpcServer"
mksock "$TESTDIR/tmp/.X11-unix/X0"
mksock "$TESTDIR/var/run/acpid.socket"
OUT=$("$TESTDIR/af_unix_sock_enum.sh")
assert_equals "$OUT" "AF_UNIX_SOCK_SCANNED" "T2: 23 real-target noise paths silently dropped"
teardown_fixture

# ============================================================================
# T3: Allowlist branches — one socket per pattern, all correctly tagged.
# ============================================================================
setup_fixture
mksock "$TESTDIR/run/docker.sock"
mksock "$TESTDIR/var/lib/lxd/unix.socket"
mksock "$TESTDIR/var/snap/lxd/common/lxd/unix.socket"
mksock "$TESTDIR/var/run/redis/redis.sock"
mksock "$TESTDIR/var/run/redis-server.sock"
mksock "$TESTDIR/var/run/memcached.sock"
OUT=$("$TESTDIR/af_unix_sock_enum.sh")
assert_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[docker]: $TESTDIR/run/docker.sock" "T3a: docker.sock tagged"
assert_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[lxd]: $TESTDIR/var/lib/lxd/unix.socket" "T3b: lxd standard path tagged"
assert_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[lxd]: $TESTDIR/var/snap/lxd/common/lxd/unix.socket" "T3c: lxd snap path tagged"
assert_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[redis]: $TESTDIR/var/run/redis/redis.sock" "T3d: redis wildcard path tagged"
assert_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[redis]: $TESTDIR/var/run/redis-server.sock" "T3e: redis-server.sock tagged"
assert_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[memcached]: $TESTDIR/var/run/memcached.sock" "T3f: memcached.sock tagged"
teardown_fixture

# ============================================================================
# T4: Unknown catch-all — novel path routes to [unknown].
# ============================================================================
setup_fixture
mksock "$TESTDIR/opt/customapp/customdaemon.sock"
OUT=$("$TESTDIR/af_unix_sock_enum.sh")
assert_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[unknown]: $TESTDIR/opt/customapp/customdaemon.sock" "T4: novel path tagged unknown"
teardown_fixture

# ============================================================================
# T5: Foothold-owned exclusion — -not -user filter drops test-user-owned socket.
# ============================================================================
setup_fixture_keep_owner_filter
mksock "$TESTDIR/opt/customapp/foothold_owned.sock"
OUT=$("$TESTDIR/af_unix_sock_enum.sh")
assert_equals "$OUT" "AF_UNIX_SOCK_SCANNED" "T5: foothold-owned socket excluded by -not -user"
teardown_fixture

# ============================================================================
# T6: Non-writable exclusion — mode 0400 socket dropped by -writable filter.
# Skipped under root (root's access(2) returns W_OK regardless of mode bits).
# ============================================================================
if [ "$(id -u)" -eq 0 ]; then
  echo "SKIP: T6: non-writable socket excluded by -writable (requires non-root)"
  SKIP=$((SKIP+1))
else
  setup_fixture
  mksock "$TESTDIR/opt/readonly.sock" 400
  OUT=$("$TESTDIR/af_unix_sock_enum.sh")
  assert_equals "$OUT" "AF_UNIX_SOCK_SCANNED" "T6: non-writable socket excluded by -writable"
  teardown_fixture
fi

# ============================================================================
# T7: Regular file at allowlist path — dropped by -type s filter.
# ============================================================================
setup_fixture
mkdir -p "$TESTDIR/run"
touch "$TESTDIR/run/docker.sock"   # regular file, not a socket
chmod 666 "$TESTDIR/run/docker.sock"
OUT=$("$TESTDIR/af_unix_sock_enum.sh")
assert_equals "$OUT" "AF_UNIX_SOCK_SCANNED" "T7: regular file at allowlist path excluded by -type s"
teardown_fixture

# ============================================================================
# T8: Symlink to socket — find -type s doesn't follow, symlink itself skipped;
# real socket at target path caught by whichever branch matches its actual path.
# ============================================================================
setup_fixture
mksock "$TESTDIR/actual_socket"
mkdir -p "$TESTDIR/run"
ln -s "$TESTDIR/actual_socket" "$TESTDIR/run/docker.sock"
OUT=$("$TESTDIR/af_unix_sock_enum.sh")
assert_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[unknown]: $TESTDIR/actual_socket" "T8a: real socket caught at actual path (unknown)"
assert_not_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[docker]:" "T8b: symlink at docker.sock skipped by -type s"
teardown_fixture

# ============================================================================
# T9: Mixed comprehensive — Andrew's real Ubuntu noise + all allowlist branches
# + one unknown. Integration test.
# ============================================================================
setup_fixture
mksock "$TESTDIR/run/dbus/system_bus_socket"
mksock "$TESTDIR/run/systemd/notify"
mksock "$TESTDIR/tmp/.ICE-unix/2538"
mksock "$TESTDIR/run/docker.sock"
mksock "$TESTDIR/var/lib/lxd/unix.socket"
mksock "$TESTDIR/var/run/redis/redis-server.sock"
mksock "$TESTDIR/var/run/memcached.sock"
mksock "$TESTDIR/opt/customapp/novel.sock"
OUT=$("$TESTDIR/af_unix_sock_enum.sh")
assert_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[docker]:" "T9a: docker tagged in mixed fixture"
assert_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[lxd]:" "T9b: lxd tagged in mixed fixture"
assert_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[redis]:" "T9c: redis tagged in mixed fixture"
assert_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[memcached]:" "T9d: memcached tagged in mixed fixture"
assert_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[unknown]: $TESTDIR/opt/customapp/novel.sock" "T9g: novel tagged unknown"
assert_not_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[unknown]: $TESTDIR/run/dbus/" "T9h: dbus dropped in mixed fixture"
assert_not_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[unknown]: $TESTDIR/run/systemd/" "T9i: systemd dropped in mixed fixture"
assert_not_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[unknown]: $TESTDIR/tmp/.ICE-unix/" "T9j: ICE-unix dropped in mixed fixture"
teardown_fixture

# ============================================================================
# T10: Comment-strip deployment parity (bash) — the sed-stripped script body
# (what actually lands on target after xclip-heredoc paste) produces identical
# output to the full script.
# ============================================================================
setup_fixture
mksock "$TESTDIR/run/docker.sock"
mksock "$TESTDIR/run/systemd/notify"
mksock "$TESTDIR/opt/unknown.sock"
OUT_FULL=$("$TESTDIR/af_unix_sock_enum.sh")
STRIPPED=$(sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$TESTDIR/af_unix_sock_enum.sh")
OUT_STRIPPED=$(bash -c "$STRIPPED")
assert_equals "$OUT_STRIPPED" "$OUT_FULL" "T10: comment-stripped output matches full-script output (bash)"
teardown_fixture

# ============================================================================
# T11: Blacklist branches — one socket per pattern, all silently dropped.
# Regression guard against per-pattern drift.
# ============================================================================
setup_fixture
mksock "$TESTDIR/run/systemd/probe.sock"
mksock "$TESTDIR/run/dbus/probe.sock"
mksock "$TESTDIR/run/cups/probe.sock"
mksock "$TESTDIR/run/avahi-daemon/probe.sock"
mksock "$TESTDIR/run/uuidd/probe.sock"
mksock "$TESTDIR/run/NetworkManager/probe.sock"
mksock "$TESTDIR/run/lvm/probe.sock"
mksock "$TESTDIR/run/tuned/probe.sock"
mksock "$TESTDIR/run/dmeventd.sock"
mksock "$TESTDIR/run/sepermit/probe.sock"
mksock "$TESTDIR/run/rpcbind.sock"
mksock "$TESTDIR/run/snapd.sock"
mksock "$TESTDIR/tmp/.ICE-unix/probe"
mksock "$TESTDIR/tmp/.X11-unix/probe"
mksock "$TESTDIR/var/snap/canonical-livepatch/probe.sock"
mksock "$TESTDIR/run/polkit/probe.sock"
mksock "$TESTDIR/run/pcscd/probe.sock"
mksock "$TESTDIR/run/ssh-unix-local/probe.sock"
mksock "$TESTDIR/tmp/.iprt-localipc-probe"
mksock "$TESTDIR/var/run/acpid.socket"
mksock "$TESTDIR/var/run/mysqld.sock"
mksock "$TESTDIR/var/run/mysql.sock"
mksock "$TESTDIR/var/run/mariadb.sock"
mksock "$TESTDIR/var/run/.s.PGSQL.5432"
mksock "$TESTDIR/var/run/postgresql/probe.sock"
OUT=$("$TESTDIR/af_unix_sock_enum.sh")
assert_equals "$OUT" "AF_UNIX_SOCK_SCANNED" "T11: all 25 blacklist patterns silently drop (per-pattern regression)"
teardown_fixture

# ============================================================================
# T12: Allowlist vs blacklist precedence — path matching both branches must
# route via allowlist (case block evaluates top-to-bottom).
# ============================================================================
setup_fixture
mksock "$TESTDIR/run/dbus/docker.sock"
OUT=$("$TESTDIR/af_unix_sock_enum.sh")
assert_contains "$OUT" "WRITABLE_AF_UNIX_SOCK[docker]: $TESTDIR/run/dbus/docker.sock" "T12: allowlist wins on collision (case top-to-bottom)"
teardown_fixture

# ============================================================================
# T13: Dash execution parity — comment-stripped body under sh (dash on
# Debian/Ubuntu/Kali) produces identical output to bash. Guards against
# accidental bash-isms creeping into the script.
# ============================================================================
setup_fixture
mksock "$TESTDIR/run/docker.sock"
mksock "$TESTDIR/run/systemd/notify"
mksock "$TESTDIR/opt/unknown.sock"
OUT_BASH=$("$TESTDIR/af_unix_sock_enum.sh")
STRIPPED=$(sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$TESTDIR/af_unix_sock_enum.sh")
OUT_SH=$(sh -c "$STRIPPED")
assert_equals "$OUT_SH" "$OUT_BASH" "T13: comment-stripped output matches bash output under sh/dash"
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
