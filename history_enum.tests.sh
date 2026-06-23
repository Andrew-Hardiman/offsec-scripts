#!/bin/bash
# history_enum.tests.sh — Regression tests for history_enum.sh
#
# Each test creates an isolated /tmp/<random> directory mimicking a target
# layout (/etc/passwd + user home dirs), sed-rewrites a copy of history_enum.sh
# to point at it, runs that copy, asserts against expected output, tears down.
#
# Run: ./history_enum.tests.sh
# Exit code: 0 if all pass, non-zero count = failures.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_SCRIPT="$SCRIPT_DIR/history_enum.sh"

if [ ! -f "$TARGET_SCRIPT" ]; then
  echo "ERROR: cannot find history_enum.sh at $TARGET_SCRIPT"
  exit 1
fi

PASS=0
FAIL=0
SKIP=0

setup_fixture() {
  TESTDIR=$(mktemp -d)
  mkdir -p "$TESTDIR/etc"
  # Rewrite history_enum.sh's hardcoded /etc/passwd path to point at $TESTDIR
  sed "s|/etc/passwd|$TESTDIR/etc/passwd|g" "$TARGET_SCRIPT" > "$TESTDIR/history_enum.sh"
  chmod +x "$TESTDIR/history_enum.sh"
}

teardown_fixture() {
  rm -rf "$TESTDIR"
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

# ============================================================================
# Marker emission tests (EMPTY, FOUND, CRED)
# ============================================================================

# T1: No history files exist → HISTORY_EMPTY
setup_fixture
mkdir -p "$TESTDIR/home/user"
cat > "$TESTDIR/etc/passwd" <<EOF
user:x:1000:1000::$TESTDIR/home/user:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_EMPTY" "T1a: empty case emits HISTORY_EMPTY"
assert_not_contains "$OUT" "HISTORY_CRED" "T1b: empty case emits no HISTORY_CRED"
assert_not_contains "$OUT" "HISTORY_FOUND" "T1c: empty case emits no HISTORY_FOUND"
teardown_fixture

# T2: History file exists but contains no cred patterns → HISTORY_FOUND
setup_fixture
mkdir -p "$TESTDIR/home/user"
echo "ls -la
cat /etc/hostname
cd /tmp" > "$TESTDIR/home/user/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
user:x:1000:1000::$TESTDIR/home/user:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_FOUND: $TESTDIR/home/user/.bash_history" "T2a: no-cred file emits HISTORY_FOUND"
assert_not_contains "$OUT" "HISTORY_CRED" "T2b: no-cred file emits no HISTORY_CRED"
teardown_fixture

# T3: History file with cred pattern → HISTORY_CRED including the matched line
setup_fixture
mkdir -p "$TESTDIR/home/user"
echo "mysql -uroot -ppassword123" > "$TESTDIR/home/user/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
user:x:1000:1000::$TESTDIR/home/user:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_CRED[$TESTDIR/home/user/.bash_history]:" "T3a: cred match emits HISTORY_CRED marker"
assert_contains "$OUT" "mysql -uroot -ppassword123" "T3b: HISTORY_CRED includes the matched line"
teardown_fixture

# ============================================================================
# Credential pattern coverage tests (one per regex alternation)
# ============================================================================

# T4: -p<password> (mysql style, no space) caught
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "mysql -uroot -pSecret456" > "$TESTDIR/home/u/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_CRED" "T4: -p<pass> caught"
teardown_fixture

# T5: --password= caught
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "mysqldump --password=DbSecret mydb" > "$TESTDIR/home/u/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_CRED" "T5: --password= caught"
teardown_fixture

# T6: MYSQL_PWD= env var caught
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "export MYSQL_PWD=cluster_secret" > "$TESTDIR/home/u/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_CRED" "T6: MYSQL_PWD= caught"
teardown_fixture

# T7: PGPASSWORD= env var caught
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "export PGPASSWORD=pg_secret" > "$TESTDIR/home/u/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_CRED" "T7: PGPASSWORD= caught"
teardown_fixture

# T8: sshpass -p caught
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "sshpass -p 'WhySecret' ssh root@1.2.3.4" > "$TESTDIR/home/u/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_CRED" "T8: sshpass -p caught"
teardown_fixture

# T9: Bearer token caught
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "curl -H 'Authorization: Bearer eyJ.foo.bar' api.example.com" > "$TESTDIR/home/u/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_CRED" "T9: Bearer token caught"
teardown_fixture

# T10: GitHub PAT (ghp_) caught
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "git push https://ghp_AbCdEf123456@github.com/repo" > "$TESTDIR/home/u/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_CRED" "T10: ghp_ token caught"
teardown_fixture

# T11: URL embed (://user:pass@host) caught
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "psql postgres://admin:Secret@db.local:5432/x" > "$TESTDIR/home/u/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_CRED" "T11: URL embed user:pass@ caught"
teardown_fixture

# ============================================================================
# False-positive control tests
# ============================================================================

# T12: mkdir -p /tmp/foo NOT caught (space after -p — common no-cred usage)
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "mkdir -p /tmp/foo" > "$TESTDIR/home/u/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_not_contains "$OUT" "HISTORY_CRED" "T12: mkdir -p (space after) NOT flagged"
teardown_fixture

# T13: git log -p NOT caught (-p as end-of-arg, no attached value)
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "git log -p" > "$TESTDIR/home/u/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_not_contains "$OUT" "HISTORY_CRED" "T13: git log -p (end of arg) NOT flagged"
teardown_fixture

# ============================================================================
# /etc/passwd filter tests (awk UID + shell + home logic)
# ============================================================================

# T14: System account (UID < 1000) excluded from enumeration even with real shell
setup_fixture
mkdir -p "$TESTDIR/system_home"
echo "mysql -psystem_secret" > "$TESTDIR/system_home/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
sysuser:x:50:50::$TESTDIR/system_home:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_EMPTY" "T14: UID 50 system account home not scanned"
teardown_fixture

# T15: User with /usr/sbin/nologin shell excluded
setup_fixture
mkdir -p "$TESTDIR/nologin_home"
echo "mysql -pnoshell_secret" > "$TESTDIR/nologin_home/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
nl:x:1000:1000::$TESTDIR/nologin_home:/usr/sbin/nologin
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_EMPTY" "T15: nologin shell excludes from enumeration"
teardown_fixture

# T16: User with /bin/false shell excluded
setup_fixture
mkdir -p "$TESTDIR/false_home"
echo "mysql -pfalse_secret" > "$TESTDIR/false_home/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
fu:x:1000:1000::$TESTDIR/false_home:/bin/false
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_EMPTY" "T16: /bin/false shell excludes from enumeration"
teardown_fixture

# T17: Non-standard interactive admin (UID >= 1000, /bin/bash, non-/home home) INCLUDED
setup_fixture
mkdir -p "$TESTDIR/srv/admin"
echo "mysql -padmin_secret" > "$TESTDIR/srv/admin/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
admin:x:1100:1100::$TESTDIR/srv/admin:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_CRED[$TESTDIR/srv/admin/.bash_history]:" "T17: non-standard interactive home included"
teardown_fixture

# T18: root (UID 0) with /bin/bash included
setup_fixture
mkdir -p "$TESTDIR/root"
echo "mysql -proot_secret" > "$TESTDIR/root/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
root:x:0:0:root:$TESTDIR/root:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_CRED[$TESTDIR/root/.bash_history]:" "T18: root included"
teardown_fixture

# ============================================================================
# Edge case tests
# ============================================================================

# T19: /etc/passwd home pointing at non-existent dir → skipped silently
setup_fixture
mkdir -p "$TESTDIR/home/real"
echo "mysql -preal_secret" > "$TESTDIR/home/real/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
phantom:x:1000:1000::$TESTDIR/home/ghost:/bin/bash
real:x:1001:1001::$TESTDIR/home/real:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_CRED[$TESTDIR/home/real/.bash_history]:" "T19a: real home scanned"
assert_not_contains "$OUT" "ghost" "T19b: phantom home produces no reference to /home/ghost"
teardown_fixture

# T20: Home path with spaces — quoted iteration must survive
setup_fixture
mkdir -p "$TESTDIR/home/john doe"
echo "mysql -pspace_secret" > "$TESTDIR/home/john doe/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
john:x:1000:1000::$TESTDIR/home/john doe:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_CRED[$TESTDIR/home/john doe/.bash_history]:" "T20: home path with spaces handled"
teardown_fixture

# T21: Multiple history files in one home — all scanned, each emits correct marker
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "no creds here" > "$TESTDIR/home/u/.bash_history"
echo "mysql -pmysql_history_secret" > "$TESTDIR/home/u/.mysql_history"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_FOUND: $TESTDIR/home/u/.bash_history" "T21a: no-cred file emits FOUND"
assert_contains "$OUT" "HISTORY_CRED[$TESTDIR/home/u/.mysql_history]:" "T21b: cred file emits CRED"
teardown_fixture

# ============================================================================
# File-name pattern tests (verify -name predicates match expected file types)
# ============================================================================

# T22: .viminfo enumerated (explicit -name)
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "boring vim state" > "$TESTDIR/home/u/.viminfo"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" ".viminfo" "T22: .viminfo enumerated"
teardown_fixture

# T23: .lesshst enumerated (explicit -name)
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "some less browse history" > "$TESTDIR/home/u/.lesshst"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" ".lesshst" "T23: .lesshst enumerated"
teardown_fixture

# T24: .zsh_history caught via .*history glob
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "mysql -pzsh_secret" > "$TESTDIR/home/u/.zsh_history"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_CRED[$TESTDIR/home/u/.zsh_history]:" "T24: .zsh_history caught via .*history glob"
teardown_fixture

# T25: .psql_history caught via .*history glob (URL-embed cred — realistic psql connect)
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "\\c postgresql://admin:psql_secret@localhost/mydb" > "$TESTDIR/home/u/.psql_history"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_contains "$OUT" "HISTORY_CRED[$TESTDIR/home/u/.psql_history]:" "T25: .psql_history caught via .*history glob"
teardown_fixture

# ============================================================================
# FP control v2 — binary allow-list (eliminates flag-cluster collisions)
# ============================================================================
# These tests assert that common -p<x> flag clusters in non-credential-bearing
# binaries are NOT flagged as HISTORY_CRED. They guard the regex tightening
# that restricts -p[^- ] to known DB-client binary contexts (mysql, psql,
# mongo, etc.) instead of firing on any -p<x> anywhere.

# T26: gcc -pthread NOT flagged (compiler flag cluster, common in exploit dev /
# kernel module builds — surfaced as the dominant FP from THM PrivEsc Task 16)
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "gcc -pthread c0w.c -o c0w" > "$TESTDIR/home/u/.viminfo"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_not_contains "$OUT" "HISTORY_CRED" "T26: gcc -pthread NOT flagged"
teardown_fixture

# T27: ls -plh NOT flagged (long-listing flag cluster, common dir browse)
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "ls -plh /var/log" > "$TESTDIR/home/u/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_not_contains "$OUT" "HISTORY_CRED" "T27: ls -plh NOT flagged"
teardown_fixture

# T28: tar -pcvf NOT flagged (preserve-permissions create-verbose-file flag cluster)
setup_fixture
mkdir -p "$TESTDIR/home/u"
echo "tar -pcvf backup.tar /home/user" > "$TESTDIR/home/u/.bash_history"
cat > "$TESTDIR/etc/passwd" <<EOF
u:x:1000:1000::$TESTDIR/home/u:/bin/bash
EOF
OUT=$("$TESTDIR/history_enum.sh")
assert_not_contains "$OUT" "HISTORY_CRED" "T28: tar -pcvf NOT flagged"
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
