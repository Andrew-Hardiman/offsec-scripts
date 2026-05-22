#!/bin/bash
# cron_enum.tests.sh — Regression tests for cron_enum.sh
#
# Each test creates an isolated /tmp/<random> directory mimicking the real
# /etc/cron* layout, sed-rewrites a copy of cron_enum.sh to point at it,
# runs that copy, asserts against expected output, tears down.
#
# Run: ./cron_enum.tests.sh
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

# T1: Absolute-path writable script in /etc/crontab → WRITABLE_SCRIPT[root]
setup_fixture
touch "$TESTDIR/scripts/writable.sh"
chmod +w "$TESTDIR/scripts/writable.sh"
echo "* * * * * root $TESTDIR/scripts/writable.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WRITABLE_SCRIPT[root]: $TESTDIR/scripts/writable.sh" "T1: absolute-path writable script detected"
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
assert_contains "$OUT" "WRITABLE_SCRIPT[root]: $TESTDIR/bin/relwritable.sh" "T2: relative-path PATH-resolved writable script detected"
teardown_fixture

# T3: Writable script in /etc/cron.daily → WRITABLE_SCRIPT[root]
setup_fixture
touch "$TESTDIR/etc/cron.daily/writable_daily"
chmod +w "$TESTDIR/etc/cron.daily/writable_daily"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WRITABLE_SCRIPT[root]: $TESTDIR/etc/cron.daily/writable_daily" "T3: writable run-parts script detected"
teardown_fixture

# T4: Non-writable cron script → NO WRITABLE_SCRIPT[root]
setup_fixture
touch "$TESTDIR/scripts/readonly.sh"
chmod 0444 "$TESTDIR/scripts/readonly.sh"
echo "* * * * * root $TESTDIR/scripts/readonly.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "WRITABLE_SCRIPT[root]:" "T4: non-writable script not flagged"
teardown_fixture

# T5: /dev/null in cron entry → NO WRITABLE_SCRIPT[root] (test -f filter)
setup_fixture
echo "* * * * * root /usr/bin/something > /dev/null 2>&1" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "WRITABLE_SCRIPT[root]: /dev/null" "T5: /dev/null not flagged as writable script"
teardown_fixture

# T6: Directory cited in cron entry → NO WRITABLE_SCRIPT[root] (test -f filter)
setup_fixture
echo "* * * * * root cd / && run-parts /etc/cron.hourly" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "WRITABLE_SCRIPT[root]: /" "T6: root directory '/' not flagged"
teardown_fixture

# ============================================================================
# RELATIVE_CMD tests
# ============================================================================

# T7: Relative-path command in root cron entry → RELATIVE_CMD[root]
setup_fixture
cat > "$TESTDIR/etc/crontab" <<EOF
PATH=/usr/local/bin:/usr/bin
* * * * * root myscript.sh
EOF
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "RELATIVE_CMD[root]: myscript.sh" "T7: relative-path command detected"
teardown_fixture

# T8: Absolute-path command → NO RELATIVE_CMD[root]
setup_fixture
echo "* * * * * root /usr/bin/something" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "RELATIVE_CMD[root]:" "T8: absolute-path command not flagged as RELATIVE_CMD"
teardown_fixture

# T9: Shell builtin (cd) as command → NO RELATIVE_CMD[root]
setup_fixture
echo "* * * * * root cd / && something" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "RELATIVE_CMD[root]: cd" "T9: shell builtin (cd) filtered out"
teardown_fixture

# T10: Env var assignment (SHELL=/bin/sh) → NO RELATIVE_CMD[root]
setup_fixture
cat > "$TESTDIR/etc/crontab" <<EOF
SHELL=/bin/sh
MAILTO=root
EOF
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "RELATIVE_CMD[root]: SHELL" "T10a: SHELL= not flagged as RELATIVE_CMD"
assert_not_contains "$OUT" "RELATIVE_CMD[root]: MAILTO" "T10b: MAILTO= not flagged as RELATIVE_CMD"
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

# T13: tar with wildcard in cron-invoked script body → WILDCARD[root]
setup_fixture
cat > "$TESTDIR/scripts/with_tar.sh" <<'EOF'
#!/bin/sh
cd /backup
tar czf backup.tar.gz *
EOF
chmod +x "$TESTDIR/scripts/with_tar.sh"
echo "* * * * * root $TESTDIR/scripts/with_tar.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD[root]:" "T13a: tar wildcard in script body detected"
assert_contains "$OUT" "with_tar.sh" "T13b: WILDCARD output includes script path"
teardown_fixture

# T14: rsync with wildcard → WILDCARD[root]
setup_fixture
cat > "$TESTDIR/scripts/with_rsync.sh" <<'EOF'
#!/bin/sh
rsync -av /src/* /dst/
EOF
chmod +x "$TESTDIR/scripts/with_rsync.sh"
echo "* * * * * root $TESTDIR/scripts/with_rsync.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD[root]:" "T14: rsync wildcard detected"
teardown_fixture

# T15: chown with wildcard → WILDCARD[root]
setup_fixture
cat > "$TESTDIR/scripts/with_chown.sh" <<'EOF'
#!/bin/sh
chown root:root /var/log/*
EOF
chmod +x "$TESTDIR/scripts/with_chown.sh"
echo "* * * * * root $TESTDIR/scripts/with_chown.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD[root]:" "T15: chown wildcard detected"
teardown_fixture

# T16: 'started' substring (NOT whole-word 'tar') → NO WILDCARD[root] false positive
setup_fixture
cat > "$TESTDIR/scripts/has_started.sh" <<'EOF'
#!/bin/sh
echo "daemon started: pid=.* something"
EOF
echo "* * * * * root $TESTDIR/scripts/has_started.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "WILDCARD[root]:" "T16: 'started' substring not flagged as tar"
teardown_fixture

# T17: tar without wildcard → NO WILDCARD[root]
setup_fixture
cat > "$TESTDIR/scripts/tar_no_wild.sh" <<'EOF'
#!/bin/sh
tar czf backup.tar.gz file1 file2 file3
EOF
chmod +x "$TESTDIR/scripts/tar_no_wild.sh"
echo "* * * * * root $TESTDIR/scripts/tar_no_wild.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "WILDCARD[root]:" "T17: tar without wildcard not flagged"
teardown_fixture

# T18: Wildcard in /etc/cron.d/* file (inline root command) → WILDCARD[root]
setup_fixture
echo "* * * * * root tar czf /backup.tar.gz /home/*" > "$TESTDIR/etc/cron.d/inline_tar"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD[root]:" "T18: inline wildcard in /etc/cron.d/* detected"
teardown_fixture

# ============================================================================
# Root-user filtering tests
# ============================================================================

# T19: Non-root cron entry with writable script → NO output (not a PrivEsc to root)
setup_fixture
touch "$TESTDIR/scripts/nonroot_writable.sh"
chmod +w "$TESTDIR/scripts/nonroot_writable.sh"
echo "* * * * * www-data $TESTDIR/scripts/nonroot_writable.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "WRITABLE_SCRIPT[root]:" "T19: non-root cron entry not flagged as WRITABLE_SCRIPT"
teardown_fixture

# ============================================================================
# Empty / clean system
# ============================================================================

# T20: Empty cron config → empty output
setup_fixture
echo "# Empty crontab, no entries" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_empty "$OUT" "T20: clean system produces empty output"
teardown_fixture

# ============================================================================
# Slash-containing relative path tests (PATH search applies only to no-slash names)
# ============================================================================

# T21: Slash-containing relative command → NO RELATIVE_CMD[root]
setup_fixture
cat > "$TESTDIR/etc/crontab" <<EOF
PATH=/usr/local/bin:/usr/bin
* * * * * root ./overwrite.sh
* * * * * root sub/overwrite.sh
EOF
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "RELATIVE_CMD[root]: ./overwrite.sh" "T21a: leading-dot slash relative not flagged"
assert_not_contains "$OUT" "RELATIVE_CMD[root]: sub/overwrite.sh" "T21b: mid-slash relative not flagged"
teardown_fixture

# ============================================================================
# @-string schedule tests (@hourly/@daily/@reboot: user=field 2, command=field 3)
# ============================================================================

# T22a: @-string relative command → RELATIVE_CMD[root] (RELATIVE_CMD block @-parse)
setup_fixture
cat > "$TESTDIR/etc/crontab" <<EOF
PATH=/usr/local/bin:/usr/bin
@hourly root atstring_cmd.sh
EOF
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "RELATIVE_CMD[root]: atstring_cmd.sh" "T22a: @hourly relative command detected"
teardown_fixture

# T22b: @reboot writable absolute script → WRITABLE_SCRIPT[root] (absolute-token block @-parse; confirms @reboot surfaced)
setup_fixture
touch "$TESTDIR/scripts/reboot_writable.sh"
chmod +w "$TESTDIR/scripts/reboot_writable.sh"
echo "@reboot root $TESTDIR/scripts/reboot_writable.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WRITABLE_SCRIPT[root]: $TESTDIR/scripts/reboot_writable.sh" "T22b: @reboot writable script surfaced"
teardown_fixture

# T22c: @-string inline wildcard → WILDCARD[root] (WILDCARD block @-parse)
setup_fixture
echo "@daily root tar czf /backup.tar.gz /home/*" > "$TESTDIR/etc/cron.d/atstring_tar"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD[root]:" "T22c: @daily inline wildcard detected"
teardown_fixture

# T22d: Non-root @-string entry → NO output (root filter still applies under @-parse)
setup_fixture
touch "$TESTDIR/scripts/atstring_nonroot.sh"
chmod +w "$TESTDIR/scripts/atstring_nonroot.sh"
echo "@hourly www-data $TESTDIR/scripts/atstring_nonroot.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" "WRITABLE_SCRIPT[root]:" "T22d: non-root @-string entry not flagged"
teardown_fixture

# ============================================================================
# Missing /etc/crontab (cron.d-only) test — guards mawk abort on absent first file
# ============================================================================

# T23: cron.d entry with NO /etc/crontab present → still detected
# (Pre-fix: mawk aborts on the missing crontab arg before reading cron.d. Fails only
#  on mawk hosts; gawk skips missing files silently. Kali/Ubuntu default to mawk.)
setup_fixture
cat > "$TESTDIR/etc/cron.d/cronD_only" <<EOF
PATH=/usr/local/bin:/usr/bin
* * * * * root crondonly_cmd.sh
EOF
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "RELATIVE_CMD[root]: crondonly_cmd.sh" "T23: cron.d-only entry detected without /etc/crontab"
teardown_fixture

# ============================================================================
# Expansion-directory resolution tests (WILDCARD marker: <dir>:<file>:<line>:<body>)
# ============================================================================

# T24a: cd on a PRIOR script line (not the hit line) → dir resolved from it (THM shape)
setup_fixture
cat > "$TESTDIR/scripts/compress.sh" <<'EOF'
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *
EOF
chmod +x "$TESTDIR/scripts/compress.sh"
echo "* * * * * root $TESTDIR/scripts/compress.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD[root]: /home/user:" "T24a: dir resolved from prior-line cd in script"
teardown_fixture

# T24b: inline cd in same command (cd /x && tar *) → dir = /x
setup_fixture
echo "* * * * * root cd /var/backups && tar czf /b.tgz *" > "$TESTDIR/etc/cron.d/inline_cd"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD[root]: /var/backups:" "T24b: dir resolved from inline cd in cron line"
teardown_fixture

# T24c: no governing cd → dir = root's HOME (WILDCARD entries are root-only)
setup_fixture
echo "* * * * * root tar czf /b.tgz /home/*" > "$TESTDIR/etc/cron.d/no_cd"
RH=$(awk -F: '$1=="root"{print $6; exit}' /etc/passwd); RH=${RH:-/root}
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD[root]: $RH:" "T24c: no-cd hit falls back to root HOME"
teardown_fixture

# T24d: variable/computed cd target → UNRESOLVED (no silent wrong path)
setup_fixture
cat > "$TESTDIR/scripts/var_cd.sh" <<'EOF'
#!/bin/sh
cd $BACKUP_DIR
tar czf /tmp/b.tgz *
EOF
chmod +x "$TESTDIR/scripts/var_cd.sh"
echo "* * * * * root $TESTDIR/scripts/var_cd.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD[root]: UNRESOLVED:" "T24d: variable cd target emits UNRESOLVED"
teardown_fixture

# T24e: substring trap — 'abcd /trap' must NOT be read as a cd; falls back to root HOME
setup_fixture
cat > "$TESTDIR/scripts/trap_cd.sh" <<'EOF'
#!/bin/sh
echo abcd /trap
tar czf /tmp/b.tgz *
EOF
chmod +x "$TESTDIR/scripts/trap_cd.sh"
echo "* * * * * root $TESTDIR/scripts/trap_cd.sh" > "$TESTDIR/etc/crontab"
RH=$(awk -F: '$1=="root"{print $6; exit}' /etc/passwd); RH=${RH:-/root}
OUT=$("$TESTDIR/cron_enum.sh")
assert_not_contains "$OUT" ": /trap:" "T24e: 'abcd /trap' substring not parsed as cd target"
assert_contains "$OUT" "WILDCARD[root]: $RH:" "T24e: trap line falls back to root HOME"
teardown_fixture

# T24f: absolute then RELATIVE cd → appended (cd /a; cd b → /a/b), not last-token 'b'
setup_fixture
cat > "$TESTDIR/scripts/abs_rel.sh" <<'EOF'
#!/bin/sh
cd /a
cd b
tar czf /tmp/b.tgz *
EOF
chmod +x "$TESTDIR/scripts/abs_rel.sh"
echo "* * * * * root $TESTDIR/scripts/abs_rel.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD[root]: /a/b:" "T24f: absolute then relative cd replayed to /a/b"
teardown_fixture

# T24g: '..' lexically normalised (cd /a/b; cd .. → /a)
setup_fixture
cat > "$TESTDIR/scripts/dotdot.sh" <<'EOF'
#!/bin/sh
cd /a/b
cd ..
tar czf /tmp/b.tgz *
EOF
chmod +x "$TESTDIR/scripts/dotdot.sh"
echo "* * * * * root $TESTDIR/scripts/dotdot.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD[root]: /a:" "T24g: cd .. normalised to /a"
teardown_fixture

# T24h: relative-first cd (no absolute anchor) → resolved against initial cwd = root HOME
setup_fixture
cat > "$TESTDIR/scripts/rel_first.sh" <<'EOF'
#!/bin/sh
cd backup
tar czf /tmp/b.tgz *
EOF
chmod +x "$TESTDIR/scripts/rel_first.sh"
echo "* * * * * root $TESTDIR/scripts/rel_first.sh" > "$TESTDIR/etc/crontab"
RH=$(awk -F: '$1=="root"{print $6; exit}' /etc/passwd); RH=${RH:-/root}
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD[root]: $RH/backup:" "T24h: relative-first cd anchored at root HOME"
teardown_fixture

# T24i: run-parts script, no cd → UNRESOLVED (initial cwd is wrapper-dependent, not root HOME)
setup_fixture
cat > "$TESTDIR/etc/cron.daily/rp_nocd" <<'EOF'
#!/bin/sh
tar czf /tmp/b.tgz *
EOF
chmod +x "$TESTDIR/etc/cron.daily/rp_nocd"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD[root]: UNRESOLVED:" "T24i: run-parts no-cd is UNRESOLVED"
teardown_fixture

# T24j: run-parts script WITH an absolute cd → resolves (absolute resets unknown base)
setup_fixture
cat > "$TESTDIR/etc/cron.daily/rp_abs" <<'EOF'
#!/bin/sh
cd /srv/data
tar czf /tmp/b.tgz *
EOF
chmod +x "$TESTDIR/etc/cron.daily/rp_abs"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD[root]: /srv/data:" "T24j: run-parts absolute cd resolves"
teardown_fixture

# T24k: variable cd then absolute cd → absolute re-anchors (→ /b, not UNRESOLVED)
setup_fixture
cat > "$TESTDIR/scripts/var_abs.sh" <<'EOF'
#!/bin/sh
cd $BACKUP
cd /b
tar czf /tmp/b.tgz *
EOF
chmod +x "$TESTDIR/scripts/var_abs.sh"
echo "* * * * * root $TESTDIR/scripts/var_abs.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/cron_enum.sh")
assert_contains "$OUT" "WILDCARD[root]: /b:" "T24k: variable then absolute cd re-anchors to /b"
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
