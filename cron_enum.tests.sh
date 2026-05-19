#!/bin/bash
# test_cron_enum.sh — Regression tests for cron_enum.sh
#
# Each test creates an isolated /tmp/<random> directory mimicking the real
# /etc/cron* layout, sed-rewrites a copy of cron_enum.sh to point at it,
# runs that copy, asserts against expected output, tears down.
#
# Run: ./test_cron_enum.sh
# Exit code: 0 if all pass, non-zero count = failures.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_SCRIPT="$SCRIPT_DIR/cron_enum.sh"

if [ ! -f "$TARGET_SCRIPT" ]; then
  echo "ERROR: cannot find cron_enum.sh at $TARGET_SCRIPT"
  exit 1
fi

PASS=0
FAIL=0

setup_fixture() {
  TESTDIR=$(mktemp -d)
  mkdir -p "$TESTDIR/etc/cron.d" "$TESTDIR/etc/cron.daily" \
           "$TESTDIR/etc/cron.hourly" "$TESTDIR/etc/cron.weekly" \
           "$TESTDIR/etc/cron.monthly" "$TESTDIR/scripts" "$TESTDIR/bin"
  # Rewrite cron_enum.sh's hardcoded /etc/cron* paths to point at $TESTDIR
  sed "s|/etc/cron|$TESTDIR/etc/cron|g" "$TARGET_SCRIPT" > "$TESTDIR/cron_enum.sh"
  chmod +x "$TESTDIR/cron_enum.sh"
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

assert_empty() {
  local output="$1" name="$2"
  if [ -z "$output" ]; then
    echo "PASS: $name"
    PASS=$((PASS+1))
  else
    echo "FAIL: $name"
    echo "  Expected empty output, got:"
    echo "$output" | sed 's/^/    /'
    FAIL=$((FAIL+1))
  fi
}

# ============================================================================
# WRITABLE_SCRIPT tests
# ============================================================================

# T1: Absolute-path writable script in /etc/crontab → WRITABLE_SCRIPT
setup_fixture
touch "$TESTDIR/scripts/writable.sh"
chmod +w "$TESTDIR/scripts/writable.sh"
echo "* * * * * root $TESTDIR/scripts/writable.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WRITABLE_SCRIPT: $TESTDIR/scripts/writable.sh" "T1: absolute-path writable script detected"
teardown_fixture

# T2: Relative-path command resolving via cron's PATH to writable script
setup_fixture
touch "$TESTDIR/bin/relwritable.sh"
chmod +wx "$TESTDIR/bin/relwritable.sh"
cat > "$TESTDIR/etc/crontab" <<EOF
PATH=$TESTDIR/bin:/usr/local/bin:/usr/bin
* * * * * root relwritable.sh
EOF
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WRITABLE_SCRIPT: $TESTDIR/bin/relwritable.sh" "T2: relative-path PATH-resolved writable script detected"
teardown_fixture

# T3: Writable script in /etc/cron.daily → WRITABLE_SCRIPT
setup_fixture
touch "$TESTDIR/etc/cron.daily/writable_daily"
chmod +w "$TESTDIR/etc/cron.daily/writable_daily"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WRITABLE_SCRIPT: $TESTDIR/etc/cron.daily/writable_daily" "T3: writable run-parts script detected"
teardown_fixture

# T4: Non-writable cron script → NO WRITABLE_SCRIPT
setup_fixture
touch "$TESTDIR/scripts/readonly.sh"
chmod 0444 "$TESTDIR/scripts/readonly.sh"
echo "* * * * * root $TESTDIR/scripts/readonly.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "WRITABLE_SCRIPT:" "T4: non-writable script not flagged"
teardown_fixture

# T5: /dev/null in cron entry → NO WRITABLE_SCRIPT (test -f filter)
setup_fixture
echo "* * * * * root /usr/bin/something > /dev/null 2>&1" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "WRITABLE_SCRIPT: /dev/null" "T5: /dev/null not flagged as writable script"
teardown_fixture

# T6: Directory cited in cron entry → NO WRITABLE_SCRIPT (test -f filter)
setup_fixture
echo "* * * * * root cd / && run-parts /etc/cron.hourly" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "WRITABLE_SCRIPT: /" "T6: root directory '/' not flagged"
teardown_fixture

# ============================================================================
# RELATIVE_CMD tests
# ============================================================================

# T7: Relative-path command in cron entry → RELATIVE_CMD
setup_fixture
cat > "$TESTDIR/etc/crontab" <<EOF
PATH=/usr/local/bin:/usr/bin
* * * * * root myscript.sh
EOF
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "RELATIVE_CMD: myscript.sh" "T7: relative-path command detected"
teardown_fixture

# T8: Absolute-path command → NO RELATIVE_CMD
setup_fixture
echo "* * * * * root /usr/bin/something" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "RELATIVE_CMD:" "T8: absolute-path command not flagged as RELATIVE_CMD"
teardown_fixture

# T9: Shell builtin (cd) as command → NO RELATIVE_CMD
setup_fixture
echo "* * * * * root cd / && something" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "RELATIVE_CMD: cd" "T9: shell builtin (cd) filtered out"
teardown_fixture

# T10: Env var assignment (SHELL=/bin/sh) → NO RELATIVE_CMD
setup_fixture
cat > "$TESTDIR/etc/crontab" <<EOF
SHELL=/bin/sh
MAILTO=root
EOF
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "RELATIVE_CMD: SHELL" "T10a: SHELL= not flagged as RELATIVE_CMD"
assert_not_contains "$OUT" "RELATIVE_CMD: MAILTO" "T10b: MAILTO= not flagged as RELATIVE_CMD"
teardown_fixture

# ============================================================================
# WRITABLE_PATH_DIR tests
# ============================================================================

# T11: Writable dir in cron's PATH → WRITABLE_PATH_DIR
setup_fixture
mkdir -p "$TESTDIR/writable_path"
chmod +w "$TESTDIR/writable_path"
echo "PATH=$TESTDIR/writable_path:/usr/bin" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WRITABLE_PATH_DIR: $TESTDIR/writable_path" "T11: writable PATH dir detected"
teardown_fixture

# T12: Read-only PATH dir → NO WRITABLE_PATH_DIR for that dir
setup_fixture
mkdir -p "$TESTDIR/readonly_path"
chmod 0555 "$TESTDIR/readonly_path"
echo "PATH=$TESTDIR/readonly_path:/usr/bin" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "WRITABLE_PATH_DIR: $TESTDIR/readonly_path" "T12: read-only PATH dir not flagged"
teardown_fixture

# ============================================================================
# WILDCARD tests
# ============================================================================

# T13: tar with wildcard in cron-invoked script body → WILDCARD
setup_fixture
cat > "$TESTDIR/scripts/with_tar.sh" <<'EOF'
#!/bin/sh
cd /backup
tar czf backup.tar.gz *
EOF
chmod +x "$TESTDIR/scripts/with_tar.sh"
echo "* * * * * root $TESTDIR/scripts/with_tar.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD:" "T13a: tar wildcard in script body detected"
assert_contains "$OUT" "with_tar.sh" "T13b: WILDCARD output includes script path"
teardown_fixture

# T14: rsync with wildcard → WILDCARD
setup_fixture
cat > "$TESTDIR/scripts/with_rsync.sh" <<'EOF'
#!/bin/sh
rsync -av /src/* /dst/
EOF
chmod +x "$TESTDIR/scripts/with_rsync.sh"
echo "* * * * * root $TESTDIR/scripts/with_rsync.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD:" "T14: rsync wildcard detected"
teardown_fixture

# T15: chown with wildcard → WILDCARD
setup_fixture
cat > "$TESTDIR/scripts/with_chown.sh" <<'EOF'
#!/bin/sh
chown root:root /var/log/*
EOF
chmod +x "$TESTDIR/scripts/with_chown.sh"
echo "* * * * * root $TESTDIR/scripts/with_chown.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD:" "T15: chown wildcard detected"
teardown_fixture

# T16: 'started' substring (NOT whole-word 'tar') → NO WILDCARD false positive
setup_fixture
cat > "$TESTDIR/scripts/has_started.sh" <<'EOF'
#!/bin/sh
echo "daemon started: pid=.* something"
EOF
echo "* * * * * root $TESTDIR/scripts/has_started.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "WILDCARD:" "T16: 'started' substring not flagged as tar"
teardown_fixture

# T17: tar without wildcard → NO WILDCARD
setup_fixture
cat > "$TESTDIR/scripts/tar_no_wild.sh" <<'EOF'
#!/bin/sh
tar czf backup.tar.gz file1 file2 file3
EOF
chmod +x "$TESTDIR/scripts/tar_no_wild.sh"
echo "* * * * * root $TESTDIR/scripts/tar_no_wild.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "WILDCARD:" "T17: tar without wildcard not flagged"
teardown_fixture

# T18: Wildcard in /etc/cron.d/* file (inline command) → WILDCARD
setup_fixture
echo "* * * * * root tar czf /backup.tar.gz /home/*" > "$TESTDIR/etc/cron.d/inline_tar"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD:" "T18: inline wildcard in /etc/cron.d/* detected"
teardown_fixture

# ============================================================================
# Empty / clean system
# ============================================================================

# T19: Empty cron config → empty output
setup_fixture
echo "# Empty crontab, no entries" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_empty "$OUT" "T19: clean system produces empty output"
teardown_fixture

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "============================="
echo "PASSED: $PASS"
echo "FAILED: $FAIL"
echo "============================="
exit "$FAIL"
