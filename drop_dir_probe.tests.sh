#!/bin/bash
# drop_dir_probe.tests.sh — Regression tests for drop_dir_probe.sh.
#
# Usage:
#   bash ~/scripts/drop_dir_probe.tests.sh
#   bash ~/scripts/drop_dir_probe.tests.sh /path/to/drop_dir_probe.sh
#
# Each test creates a hermetic mktemp fixture, sed-rewrites a copy of
# drop_dir_probe.sh to point at fixture paths (matching the cron_enum.tests.sh
# pattern), runs the copy against a synthesised /proc/mounts, asserts expected
# output, tears down.
#
# Exit code: 0 on all-pass, non-zero count = failures.

set -u
SCRIPT_UNDER_TEST=${1:-${HOME}/scripts/drop_dir_probe.sh}
[ -r "$SCRIPT_UNDER_TEST" ] || { echo "Cannot read $SCRIPT_UNDER_TEST" >&2; exit 1; }

pass=0; fail=0

setup_fixture() {
  TESTDIR=$(mktemp -d)
  mkdir -p "$TESTDIR/dev/shm" "$TESTDIR/run/lock" "$TESTDIR/run/user/$(id -u)" \
           "$TESTDIR/var/tmp" "$TESTDIR/home/.cache" "$TESTDIR/home/.config"
  sed -e "s|/proc/mounts|$TESTDIR/proc_mounts|g" \
      -e "s|\"/run/user/|\"$TESTDIR/run/user/|g" \
      -e "s|/dev/shm|$TESTDIR/dev/shm|g" \
      -e "s|/run/lock|$TESTDIR/run/lock|g" \
      -e "s|/var/tmp|$TESTDIR/var/tmp|g" \
      "$SCRIPT_UNDER_TEST" > "$TESTDIR/probe.sh"
  chmod +x "$TESTDIR/probe.sh"
}

teardown_fixture() { rm -rf "$TESTDIR"; }
write_mounts() { printf '%s\n' "$1" > "$TESTDIR/proc_mounts"; }
run_probe() { HOME="$TESTDIR/home" "$TESTDIR/probe.sh" "$@"; }

assert_contains() {
  if echo "$1" | grep -qF "$2"; then echo "PASS: $3"; pass=$((pass+1))
  else echo "FAIL: $3"; echo "  expected: $2"; echo "  actual:   $1"; fail=$((fail+1)); fi
}
assert_not_contains() {
  if echo "$1" | grep -qF "$2"; then
    echo "FAIL: $3"; echo "  unexpected: $2"; echo "  actual:     $1"; fail=$((fail+1))
  else echo "PASS: $3"; pass=$((pass+1)); fi
}
assert_exit() {
  if [ "$1" = "$2" ]; then echo "PASS: $3"; pass=$((pass+1))
  else echo "FAIL: $3"; echo "  expected exit: $2"; echo "  actual exit:   $1"; fail=$((fail+1)); fi
}

# T1: clean /run/user → DROP OK (no suid arg)
setup_fixture
write_mounts "tmpfs $TESTDIR/run/user/$(id -u) tmpfs rw,relatime 0 0"
OUT=$(run_probe 2>&1); RC=$?
assert_contains "$OUT" "DROP OK: $TESTDIR/run/user/$(id -u)" "T1: clean tmpfs /run/user accepted"
assert_exit "$RC" 0 "T1: exit code 0"
teardown_fixture

# T2: clean /run/user + suid mode → DROP OK
setup_fixture
write_mounts "tmpfs $TESTDIR/run/user/$(id -u) tmpfs rw,relatime 0 0"
OUT=$(run_probe suid 2>&1); RC=$?
assert_contains "$OUT" "DROP OK: $TESTDIR/run/user/$(id -u)" "T2: clean mount + suid mode accepted"
teardown_fixture

# T3: nosuid + suid mode → reject, fall to next
setup_fixture
write_mounts "tmpfs $TESTDIR/run/user/$(id -u) tmpfs rw,nosuid 0 0
tmpfs $TESTDIR/dev/shm tmpfs rw,relatime 0 0"
OUT=$(run_probe suid 2>&1)
assert_contains "$OUT" "DROP OK: $TESTDIR/dev/shm" "T3: nosuid /run/user with suid mode → falls to /dev/shm"
teardown_fixture

# T4: nosuid + empty mode → accept (only noexec rejects in non-suid mode)
setup_fixture
write_mounts "tmpfs $TESTDIR/run/user/$(id -u) tmpfs rw,nosuid 0 0"
OUT=$(run_probe 2>&1)
assert_contains "$OUT" "DROP OK: $TESTDIR/run/user/$(id -u)" "T4: nosuid accepted without suid mode"
teardown_fixture

# T5: noexec → always rejects (both modes)
setup_fixture
write_mounts "tmpfs $TESTDIR/run/user/$(id -u) tmpfs rw,noexec 0 0
tmpfs $TESTDIR/dev/shm tmpfs rw,relatime 0 0"
OUT=$(run_probe 2>&1)
assert_contains "$OUT" "DROP OK: $TESTDIR/dev/shm" "T5: noexec /run/user rejected even without suid mode"
teardown_fixture

# T6: inheritance — /var/tmp on nosuid /var (no own mount) + suid → reject
setup_fixture
mkdir -p "$TESTDIR/var"
write_mounts "$TESTDIR/dev/sda1 / ext4 rw,relatime 0 0
$TESTDIR/dev/sda2 $TESTDIR/var ext4 rw,nosuid 0 0"
rmdir "$TESTDIR/run/user/$(id -u)" "$TESTDIR/run/lock" 2>/dev/null
rm -rf "$TESTDIR/dev/shm" "$TESTDIR/home/.cache" "$TESTDIR/home/.config" 2>/dev/null
OUT=$(run_probe suid 2>&1)
assert_not_contains "$OUT" "DROP OK: $TESTDIR/var/tmp" "T6: /var/tmp inheriting nosuid from /var rejected"
teardown_fixture

# T7: root / handled correctly (m="/" not "//") — $HOME inherits clean / mount
setup_fixture
write_mounts "$TESTDIR/dev/sda1 / ext4 rw,relatime 0 0"
rmdir "$TESTDIR/run/user/$(id -u)" "$TESTDIR/run/lock" 2>/dev/null
rm -rf "$TESTDIR/dev/shm" "$TESTDIR/var/tmp" "$TESTDIR/home/.cache" "$TESTDIR/home/.config" 2>/dev/null
OUT=$(run_probe suid 2>&1)
assert_contains "$OUT" "DROP OK: $TESTDIR/home" "T7: \$HOME via root / mount accepted (root prefix handled)"
teardown_fixture

# T8: errors=remount-ro must NOT trigger any rejection
setup_fixture
write_mounts "$TESTDIR/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0"
rmdir "$TESTDIR/run/user/$(id -u)" "$TESTDIR/run/lock" 2>/dev/null
rm -rf "$TESTDIR/dev/shm" "$TESTDIR/var/tmp" "$TESTDIR/home/.cache" "$TESTDIR/home/.config" 2>/dev/null
OUT=$(run_probe suid 2>&1)
assert_contains "$OUT" "DROP OK: $TESTDIR/home" "T8: errors=remount-ro not false-matched as 'ro'"
teardown_fixture

# T9: $HOME/.cache prefers over $HOME
setup_fixture
write_mounts "$TESTDIR/dev/sda1 / ext4 rw,relatime 0 0"
rmdir "$TESTDIR/run/user/$(id -u)" "$TESTDIR/run/lock" 2>/dev/null
rm -rf "$TESTDIR/dev/shm" "$TESTDIR/var/tmp" 2>/dev/null
OUT=$(run_probe 2>&1)
assert_contains "$OUT" "DROP OK: $TESTDIR/home/.cache" "T9: \$HOME/.cache prefers over \$HOME"
teardown_fixture

# T10: missing .cache → falls to .config
setup_fixture
write_mounts "$TESTDIR/dev/sda1 / ext4 rw,relatime 0 0"
rmdir "$TESTDIR/run/user/$(id -u)" "$TESTDIR/run/lock" 2>/dev/null
rm -rf "$TESTDIR/dev/shm" "$TESTDIR/var/tmp" "$TESTDIR/home/.cache" 2>/dev/null
OUT=$(run_probe 2>&1)
assert_contains "$OUT" "DROP OK: $TESTDIR/home/.config" "T10: missing .cache falls to .config"
teardown_fixture

# T11: all reject → no output, exit 1
setup_fixture
write_mounts "tmpfs $TESTDIR/run/user/$(id -u) tmpfs rw,noexec,nosuid 0 0
tmpfs $TESTDIR/dev/shm tmpfs rw,noexec,nosuid 0 0
tmpfs $TESTDIR/run/lock tmpfs rw,noexec,nosuid 0 0
tmpfs $TESTDIR/var/tmp tmpfs rw,noexec,nosuid 0 0
$TESTDIR/dev/sda1 $TESTDIR/home ext4 rw,noexec,nosuid 0 0"
OUT=$(run_probe suid 2>&1); RC=$?
assert_not_contains "$OUT" "DROP OK" "T11: all noexec+nosuid → no DROP OK"
assert_exit "$RC" 1 "T11: exit code 1"
teardown_fixture

# T12: invalid mode arg → exit 2
setup_fixture
write_mounts ""
OUT=$("$TESTDIR/probe.sh" garbage 2>&1); RC=$?
assert_exit "$RC" 2 "T12: invalid mode arg exits 2"
assert_contains "$OUT" "Usage:" "T12: prints Usage on invalid arg"
teardown_fixture

# T13: missing /proc/mounts → exit 1 with error msg
setup_fixture
# Don't create proc_mounts
OUT=$(run_probe 2>&1); RC=$?
assert_exit "$RC" 1 "T13: missing /proc/mounts exits 1"
assert_contains "$OUT" "not readable" "T13: prints not-readable message"
teardown_fixture

echo "----"
echo "$pass passed, $fail failed"
exit $fail
