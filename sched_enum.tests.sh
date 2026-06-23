#!/bin/bash
# sched_enum.tests.sh — Regression tests for sched_enum.sh
#
# Each test creates an isolated /tmp/<random> directory mimicking the real
# scheduler config layouts (/etc/cron*, /var/spool/cron/crontabs/,
# /var/spool/cron/atjobs/, /etc/anacrontab), sed-rewrites a copy of
# sched_enum.sh to point at it (and to rewrite the at-job `-uid 0` filter to
# the current test user so fixture files pass without sudo), runs that copy,
# asserts against expected output, tears down.
#
# Run: ./sched_enum.tests.sh
# Exit code: 0 if all pass, non-zero count = failures.
# T27g (AT_SPOOL_DENIED) requires non-root execution; auto-skipped under uid=0.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_SCRIPT="$SCRIPT_DIR/sched_enum.sh"

if [ ! -f "$TARGET_SCRIPT" ]; then
  echo "ERROR: cannot find sched_enum.sh at $TARGET_SCRIPT"
  exit 1
fi

PASS=0
FAIL=0
SKIP=0

setup_fixture() {
  TESTDIR=$(mktemp -d)
  mkdir -p "$TESTDIR/etc/cron.d" "$TESTDIR/etc/cron.daily" \
           "$TESTDIR/etc/cron.hourly" "$TESTDIR/etc/cron.weekly" \
           "$TESTDIR/etc/cron.monthly" \
           "$TESTDIR/var/spool/cron/crontabs" \
           "$TESTDIR/var/spool/cron/atjobs" \
           "$TESTDIR/scripts" "$TESTDIR/bin"
  # Rewrite sched_enum.sh's hardcoded paths to point at $TESTDIR, and the at-job
  # ownership filter (-uid 0) to match the current test user — fixture files
  # owned by the test user pass the filter without requiring sudo. Production
  # behaviour (filter to root-owned) is preserved; this rewrite only affects
  # the hermetic test copy.
  # Two-stage substitution via tokens to avoid substring conflicts.
  sed -e "s|/var/spool/cron|@VARSPOOLCRON@|g" \
      -e "s|/var/spool/at\b|@VARSPOOLAT@|g" \
      -e "s|/etc/anacrontab|@ETCANAC@|g" \
      -e "s|/etc/cron|@ETCCRON@|g" \
      -e "s|-uid 0|-uid $(id -u)|g" \
      -e "s|@VARSPOOLCRON@|$TESTDIR/var/spool/cron|g" \
      -e "s|@VARSPOOLAT@|$TESTDIR/var/spool/at|g" \
      -e "s|@ETCANAC@|$TESTDIR/etc/anacrontab|g" \
      -e "s|@ETCCRON@|$TESTDIR/etc/cron|g" \
      "$TARGET_SCRIPT" > "$TESTDIR/sched_enum.sh"
  chmod +x "$TESTDIR/sched_enum.sh"
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
# WRITABLE_SCRIPT[root,cron] tests
# ============================================================================

# T1: Absolute-path writable script in /etc/crontab → WRITABLE_SCRIPT[root,cron]
setup_fixture
touch "$TESTDIR/scripts/writable.sh"
chmod +w "$TESTDIR/scripts/writable.sh"
echo "* * * * * root $TESTDIR/scripts/writable.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WRITABLE_SCRIPT[root,cron]: $TESTDIR/scripts/writable.sh" "T1: absolute-path writable script detected"
teardown_fixture

# T2: Relative-path command resolving via cron's PATH to writable script
setup_fixture
touch "$TESTDIR/bin/relwritable.sh"
chmod +wx "$TESTDIR/bin/relwritable.sh"
cat > "$TESTDIR/etc/crontab" <<EOF
PATH=$TESTDIR/bin:/usr/local/bin:/usr/bin
* * * * * root relwritable.sh
EOF
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WRITABLE_SCRIPT[root,cron]: $TESTDIR/bin/relwritable.sh" "T2: relative-path PATH-resolved writable script detected"
teardown_fixture

# T3: Writable script in /etc/cron.daily → WRITABLE_SCRIPT[root,cron]
setup_fixture
touch "$TESTDIR/etc/cron.daily/writable_daily"
chmod +w "$TESTDIR/etc/cron.daily/writable_daily"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WRITABLE_SCRIPT[root,cron]: $TESTDIR/etc/cron.daily/writable_daily" "T3: writable run-parts script detected"
teardown_fixture

# T4: Non-writable cron script → NO WRITABLE_SCRIPT[root,cron]
setup_fixture
touch "$TESTDIR/scripts/readonly.sh"
chmod 0444 "$TESTDIR/scripts/readonly.sh"
echo "* * * * * root $TESTDIR/scripts/readonly.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" "WRITABLE_SCRIPT[root,cron]:" "T4: non-writable script not flagged"
teardown_fixture

# T5: /dev/null in cron entry → NO WRITABLE_SCRIPT[root,cron] (test -f filter)
setup_fixture
echo "* * * * * root /usr/bin/something > /dev/null 2>&1" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" "WRITABLE_SCRIPT[root,cron]: /dev/null" "T5: /dev/null not flagged as writable script"
teardown_fixture

# T6: Directory cited in cron entry → NO WRITABLE_SCRIPT[root,cron] (test -f filter)
setup_fixture
echo "* * * * * root cd / && run-parts /etc/cron.hourly" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" "WRITABLE_SCRIPT[root,cron]: /" "T6: root directory '/' not flagged"
teardown_fixture

# ============================================================================
# RELATIVE_CMD[root,cron] tests
# ============================================================================

# T7: Relative-path command in root cron entry → RELATIVE_CMD[root,cron]
setup_fixture
cat > "$TESTDIR/etc/crontab" <<EOF
PATH=/usr/local/bin:/usr/bin
* * * * * root myscript.sh
EOF
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "RELATIVE_CMD[root,cron]: myscript.sh" "T7: relative-path command detected"
teardown_fixture

# T8: Absolute-path command → NO RELATIVE_CMD[root,cron]
setup_fixture
echo "* * * * * root /usr/bin/something" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" "RELATIVE_CMD[root,cron]:" "T8: absolute-path command not flagged as RELATIVE_CMD"
teardown_fixture

# T9: Shell builtin (cd) as command → NO RELATIVE_CMD[root,cron]
setup_fixture
echo "* * * * * root cd / && something" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" "RELATIVE_CMD[root,cron]: cd" "T9: shell builtin (cd) filtered out"
teardown_fixture

# T10: Env var assignment (SHELL=/bin/sh) → NO RELATIVE_CMD[root,cron]
setup_fixture
cat > "$TESTDIR/etc/crontab" <<EOF
SHELL=/bin/sh
MAILTO=root
EOF
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" "RELATIVE_CMD[root,cron]: SHELL" "T10a: SHELL= not flagged as RELATIVE_CMD"
assert_not_contains "$OUT" "RELATIVE_CMD[root,cron]: MAILTO" "T10b: MAILTO= not flagged as RELATIVE_CMD"
teardown_fixture

# ============================================================================
# WRITABLE_PATH_DIR[cron] tests
# ============================================================================

# T11: Writable dir in cron's PATH → WRITABLE_PATH_DIR[cron]
setup_fixture
mkdir -p "$TESTDIR/writable_path"
chmod +w "$TESTDIR/writable_path"
echo "PATH=$TESTDIR/writable_path:/usr/bin" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WRITABLE_PATH_DIR[cron]: $TESTDIR/writable_path" "T11: writable PATH dir detected"
teardown_fixture

# T12: Read-only PATH dir → NO WRITABLE_PATH_DIR[cron] for that dir
setup_fixture
mkdir -p "$TESTDIR/readonly_path"
chmod 0555 "$TESTDIR/readonly_path"
echo "PATH=$TESTDIR/readonly_path:/usr/bin" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" "WRITABLE_PATH_DIR[cron]: $TESTDIR/readonly_path" "T12: read-only PATH dir not flagged"
teardown_fixture

# ============================================================================
# WILDCARD[root,cron] tests
# ============================================================================

# T13: tar with wildcard in cron-invoked script body → WILDCARD[root,cron]
setup_fixture
cat > "$TESTDIR/scripts/with_tar.sh" <<'EOF'
#!/bin/sh
cd /backup
tar czf backup.tar.gz *
EOF
chmod +x "$TESTDIR/scripts/with_tar.sh"
echo "* * * * * root $TESTDIR/scripts/with_tar.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,cron]:" "T13a: tar wildcard in script body detected"
assert_contains "$OUT" "with_tar.sh" "T13b: WILDCARD output includes script path"
teardown_fixture

# T14: rsync with wildcard → WILDCARD[root,cron]
setup_fixture
cat > "$TESTDIR/scripts/with_rsync.sh" <<'EOF'
#!/bin/sh
rsync -av /src/* /dst/
EOF
chmod +x "$TESTDIR/scripts/with_rsync.sh"
echo "* * * * * root $TESTDIR/scripts/with_rsync.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,cron]:" "T14: rsync wildcard detected"
teardown_fixture

# T15: chown with wildcard → WILDCARD[root,cron]
setup_fixture
cat > "$TESTDIR/scripts/with_chown.sh" <<'EOF'
#!/bin/sh
chown root:root /var/log/*
EOF
chmod +x "$TESTDIR/scripts/with_chown.sh"
echo "* * * * * root $TESTDIR/scripts/with_chown.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,cron]:" "T15: chown wildcard detected"
teardown_fixture

# T16: 'started' substring (NOT whole-word 'tar') → NO WILDCARD[root,cron] false positive
setup_fixture
cat > "$TESTDIR/scripts/has_started.sh" <<'EOF'
#!/bin/sh
echo "daemon started: pid=.* something"
EOF
echo "* * * * * root $TESTDIR/scripts/has_started.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" "WILDCARD[root,cron]:" "T16: 'started' substring not flagged as tar"
teardown_fixture

# T17: tar without wildcard → NO WILDCARD[root,cron]
setup_fixture
cat > "$TESTDIR/scripts/tar_no_wild.sh" <<'EOF'
#!/bin/sh
tar czf backup.tar.gz file1 file2 file3
EOF
chmod +x "$TESTDIR/scripts/tar_no_wild.sh"
echo "* * * * * root $TESTDIR/scripts/tar_no_wild.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" "WILDCARD[root,cron]:" "T17: tar without wildcard not flagged"
teardown_fixture

# T18: Wildcard in /etc/cron.d/* file (inline root command) → WILDCARD[root,cron]
setup_fixture
echo "* * * * * root tar czf /backup.tar.gz /home/*" > "$TESTDIR/etc/cron.d/inline_tar"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,cron]:" "T18: inline wildcard in /etc/cron.d/* detected"
teardown_fixture

# ============================================================================
# Root-user filtering tests
# ============================================================================

# T19: Non-root cron entry with writable script → NO WRITABLE_SCRIPT[root,cron]
setup_fixture
touch "$TESTDIR/scripts/nonroot_writable.sh"
chmod +w "$TESTDIR/scripts/nonroot_writable.sh"
echo "* * * * * www-data $TESTDIR/scripts/nonroot_writable.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" "WRITABLE_SCRIPT[root,cron]:" "T19: non-root cron entry not flagged as WRITABLE_SCRIPT"
teardown_fixture

# ============================================================================
# Empty / clean system
# ============================================================================

# T20: Empty cron config → empty output
setup_fixture
echo "# Empty crontab, no entries" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_empty "$OUT" "T20: clean system produces empty output"
teardown_fixture

# ============================================================================
# Slash-containing relative path tests (PATH search applies only to no-slash names)
# ============================================================================

# T21: Slash-containing relative command → NO RELATIVE_CMD[root,cron]
setup_fixture
cat > "$TESTDIR/etc/crontab" <<EOF
PATH=/usr/local/bin:/usr/bin
* * * * * root ./overwrite.sh
* * * * * root sub/overwrite.sh
EOF
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" "RELATIVE_CMD[root,cron]: ./overwrite.sh" "T21a: leading-dot slash relative not flagged"
assert_not_contains "$OUT" "RELATIVE_CMD[root,cron]: sub/overwrite.sh" "T21b: mid-slash relative not flagged"
teardown_fixture

# ============================================================================
# @-string schedule tests (@hourly/@daily/@reboot: user=field 2, command=field 3)
# ============================================================================

# T22a: @-string relative command → RELATIVE_CMD[root,cron]
setup_fixture
cat > "$TESTDIR/etc/crontab" <<EOF
PATH=/usr/local/bin:/usr/bin
@hourly root atstring_cmd.sh
EOF
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "RELATIVE_CMD[root,cron]: atstring_cmd.sh" "T22a: @hourly relative command detected"
teardown_fixture

# T22b: @reboot writable absolute script → WRITABLE_SCRIPT[root,cron]
setup_fixture
touch "$TESTDIR/scripts/reboot_writable.sh"
chmod +w "$TESTDIR/scripts/reboot_writable.sh"
echo "@reboot root $TESTDIR/scripts/reboot_writable.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WRITABLE_SCRIPT[root,cron]: $TESTDIR/scripts/reboot_writable.sh" "T22b: @reboot writable script surfaced"
teardown_fixture

# T22c: @-string inline wildcard → WILDCARD[root,cron]
setup_fixture
echo "@daily root tar czf /backup.tar.gz /home/*" > "$TESTDIR/etc/cron.d/atstring_tar"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,cron]:" "T22c: @daily inline wildcard detected"
teardown_fixture

# T22d: Non-root @-string entry → NO output
setup_fixture
touch "$TESTDIR/scripts/atstring_nonroot.sh"
chmod +w "$TESTDIR/scripts/atstring_nonroot.sh"
echo "@hourly www-data $TESTDIR/scripts/atstring_nonroot.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" "WRITABLE_SCRIPT[root,cron]:" "T22d: non-root @-string entry not flagged"
teardown_fixture

# ============================================================================
# Missing /etc/crontab (cron.d-only) test — guards mawk abort on absent first file
# ============================================================================

# T23: cron.d entry with NO /etc/crontab present → still detected
setup_fixture
cat > "$TESTDIR/etc/cron.d/cronD_only" <<EOF
PATH=/usr/local/bin:/usr/bin
* * * * * root crondonly_cmd.sh
EOF
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "RELATIVE_CMD[root,cron]: crondonly_cmd.sh" "T23: cron.d-only entry detected without /etc/crontab"
teardown_fixture

# ============================================================================
# Expansion-directory resolution tests (WILDCARD marker: <dir>:<file>:<line>:<body>)
# ============================================================================

# T24a: cd on a PRIOR script line → dir resolved from it
setup_fixture
cat > "$TESTDIR/scripts/compress.sh" <<'EOF'
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *
EOF
chmod +x "$TESTDIR/scripts/compress.sh"
echo "* * * * * root $TESTDIR/scripts/compress.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,cron]: /home/user:" "T24a: dir resolved from prior-line cd in script"
teardown_fixture

# T24b: inline cd in same command (cd /x && tar *) → dir = /x
setup_fixture
echo "* * * * * root cd /var/backups && tar czf /b.tgz *" > "$TESTDIR/etc/cron.d/inline_cd"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,cron]: /var/backups:" "T24b: dir resolved from inline cd in cron line"
teardown_fixture

# T24c: no governing cd → dir = root's HOME
setup_fixture
echo "* * * * * root tar czf /b.tgz /home/*" > "$TESTDIR/etc/cron.d/no_cd"
RH=$(awk -F: '$1=="root"{print $6; exit}' /etc/passwd); RH=${RH:-/root}
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,cron]: $RH:" "T24c: no-cd hit falls back to root HOME"
teardown_fixture

# T24d: variable/computed cd target → UNRESOLVED
setup_fixture
cat > "$TESTDIR/scripts/var_cd.sh" <<'EOF'
#!/bin/sh
cd $BACKUP_DIR
tar czf /tmp/b.tgz *
EOF
chmod +x "$TESTDIR/scripts/var_cd.sh"
echo "* * * * * root $TESTDIR/scripts/var_cd.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,cron]: UNRESOLVED:" "T24d: variable cd target emits UNRESOLVED"
teardown_fixture

# T24e: substring trap — 'abcd /trap' must NOT be read as a cd
setup_fixture
cat > "$TESTDIR/scripts/trap_cd.sh" <<'EOF'
#!/bin/sh
echo abcd /trap
tar czf /tmp/b.tgz *
EOF
chmod +x "$TESTDIR/scripts/trap_cd.sh"
echo "* * * * * root $TESTDIR/scripts/trap_cd.sh" > "$TESTDIR/etc/crontab"
RH=$(awk -F: '$1=="root"{print $6; exit}' /etc/passwd); RH=${RH:-/root}
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" ": /trap:" "T24e: 'abcd /trap' substring not parsed as cd target"
assert_contains "$OUT" "WILDCARD[root,cron]: $RH:" "T24e: trap line falls back to root HOME"
teardown_fixture

# T24f: absolute then RELATIVE cd → appended (cd /a; cd b → /a/b)
setup_fixture
cat > "$TESTDIR/scripts/abs_rel.sh" <<'EOF'
#!/bin/sh
cd /a
cd b
tar czf /tmp/b.tgz *
EOF
chmod +x "$TESTDIR/scripts/abs_rel.sh"
echo "* * * * * root $TESTDIR/scripts/abs_rel.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,cron]: /a/b:" "T24f: absolute then relative cd replayed to /a/b"
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
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,cron]: /a:" "T24g: cd .. normalised to /a"
teardown_fixture

# T24h: relative-first cd (no absolute anchor) → resolved against root HOME
setup_fixture
cat > "$TESTDIR/scripts/rel_first.sh" <<'EOF'
#!/bin/sh
cd backup
tar czf /tmp/b.tgz *
EOF
chmod +x "$TESTDIR/scripts/rel_first.sh"
echo "* * * * * root $TESTDIR/scripts/rel_first.sh" > "$TESTDIR/etc/crontab"
RH=$(awk -F: '$1=="root"{print $6; exit}' /etc/passwd); RH=${RH:-/root}
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,cron]: $RH/backup:" "T24h: relative-first cd anchored at root HOME"
teardown_fixture

# T24i: run-parts script, no cd → UNRESOLVED
setup_fixture
cat > "$TESTDIR/etc/cron.daily/rp_nocd" <<'EOF'
#!/bin/sh
tar czf /tmp/b.tgz *
EOF
chmod +x "$TESTDIR/etc/cron.daily/rp_nocd"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,cron]: UNRESOLVED:" "T24i: run-parts no-cd is UNRESOLVED"
teardown_fixture

# T24j: run-parts script WITH an absolute cd → resolves
setup_fixture
cat > "$TESTDIR/etc/cron.daily/rp_abs" <<'EOF'
#!/bin/sh
cd /srv/data
tar czf /tmp/b.tgz *
EOF
chmod +x "$TESTDIR/etc/cron.daily/rp_abs"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,cron]: /srv/data:" "T24j: run-parts absolute cd resolves"
teardown_fixture

# T24k: variable cd then absolute cd → absolute re-anchors
setup_fixture
cat > "$TESTDIR/scripts/var_abs.sh" <<'EOF'
#!/bin/sh
cd $BACKUP
cd /b
tar czf /tmp/b.tgz *
EOF
chmod +x "$TESTDIR/scripts/var_abs.sh"
echo "* * * * * root $TESTDIR/scripts/var_abs.sh" > "$TESTDIR/etc/crontab"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,cron]: /b:" "T24k: variable then absolute cd re-anchors to /b"
teardown_fixture

# ============================================================================
# T25 — User crontab tests (/var/spool/cron/crontabs/root, 5-field no user)
# Cron-family marker — routes to Cron walkthroughs via untagged-equivalent path
# ============================================================================

# T25a: Writable absolute script in root's user crontab → WRITABLE_SCRIPT[root,cron]
setup_fixture
touch "$TESTDIR/scripts/uc_writable.sh"
chmod +w "$TESTDIR/scripts/uc_writable.sh"
echo "* * * * * $TESTDIR/scripts/uc_writable.sh" > "$TESTDIR/var/spool/cron/crontabs/root"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WRITABLE_SCRIPT[root,cron]: $TESTDIR/scripts/uc_writable.sh" "T25a: writable script in root's user crontab detected"
teardown_fixture

# T25b: Relative cmd + writable PATH dir from user crontab
setup_fixture
mkdir -p "$TESTDIR/uc_writable_path"
chmod +w "$TESTDIR/uc_writable_path"
cat > "$TESTDIR/var/spool/cron/crontabs/root" <<EOF
PATH=$TESTDIR/uc_writable_path:/usr/bin
* * * * * uc_rel_cmd
EOF
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "RELATIVE_CMD[root,cron]: uc_rel_cmd" "T25b1: relative cmd in user crontab detected"
assert_contains "$OUT" "WRITABLE_PATH_DIR[cron]: $TESTDIR/uc_writable_path" "T25b2: writable PATH dir from user crontab detected"
teardown_fixture

# T25c: @reboot in user crontab → WRITABLE_SCRIPT[root,cron]
setup_fixture
touch "$TESTDIR/scripts/uc_reboot.sh"
chmod +w "$TESTDIR/scripts/uc_reboot.sh"
echo "@reboot $TESTDIR/scripts/uc_reboot.sh" > "$TESTDIR/var/spool/cron/crontabs/root"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WRITABLE_SCRIPT[root,cron]: $TESTDIR/scripts/uc_reboot.sh" "T25c: @reboot in user crontab surfaced"
teardown_fixture

# T25d: Non-root user crontab (e.g. www-data) → NOT scanned (PrivEsc filter at file level)
setup_fixture
touch "$TESTDIR/scripts/wwwdata_writable.sh"
chmod +w "$TESTDIR/scripts/wwwdata_writable.sh"
echo "* * * * * $TESTDIR/scripts/wwwdata_writable.sh" > "$TESTDIR/var/spool/cron/crontabs/www-data"
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" "$TESTDIR/scripts/wwwdata_writable.sh" "T25d: non-root user crontab (www-data) not scanned"
teardown_fixture

# ============================================================================
# T26 — Anacron tests (/etc/anacrontab, period delay jobid cmd, always root)
# ============================================================================

# T26a: Writable absolute command in /etc/anacrontab → WRITABLE_SCRIPT[root,anacron]
setup_fixture
touch "$TESTDIR/scripts/anac_writable.sh"
chmod +w "$TESTDIR/scripts/anac_writable.sh"
cat > "$TESTDIR/etc/anacrontab" <<EOF
1 5 daily.test $TESTDIR/scripts/anac_writable.sh
EOF
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WRITABLE_SCRIPT[root,anacron]: $TESTDIR/scripts/anac_writable.sh" "T26a: writable absolute cmd in anacrontab detected"
teardown_fixture

# T26b: Relative cmd + writable PATH dir from anacrontab
setup_fixture
mkdir -p "$TESTDIR/anac_writable_path"
chmod +w "$TESTDIR/anac_writable_path"
cat > "$TESTDIR/etc/anacrontab" <<EOF
PATH=$TESTDIR/anac_writable_path:/usr/bin
1 5 daily.test anac_rel_cmd
EOF
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "RELATIVE_CMD[root,anacron]: anac_rel_cmd" "T26b1: relative cmd in anacrontab detected"
assert_contains "$OUT" "WRITABLE_PATH_DIR[anacron]: $TESTDIR/anac_writable_path" "T26b2: writable PATH dir from anacrontab detected"
teardown_fixture

# T26c: Wildcard in anacrontab command → WILDCARD[root,anacron]
setup_fixture
cat > "$TESTDIR/etc/anacrontab" <<EOF
1 5 daily.test tar czf /b.tgz /home/*
EOF
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,anacron]:" "T26c: wildcard in anacrontab inline command detected"
teardown_fixture

# T26d: PATH= line in anacrontab → NOT flagged as relative command (variable-assignment filter)
setup_fixture
cat > "$TESTDIR/etc/anacrontab" <<EOF
PATH=/usr/local/bin:/usr/bin
SHELL=/bin/sh
EOF
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" "RELATIVE_CMD[root,anacron]: PATH" "T26d1: PATH= not flagged as RELATIVE_CMD"
assert_not_contains "$OUT" "RELATIVE_CMD[root,anacron]: SHELL" "T26d2: SHELL= not flagged as RELATIVE_CMD"
teardown_fixture

# ============================================================================
# T27 — At-job tests (/var/spool/cron/atjobs/ root-owned files, body-scan)
# ============================================================================
# Note: setup_fixture sed-rewrites `-uid 0` → `-uid $(id -u)` in the test copy
# so fixture files owned by the test user pass the at-job ownership filter
# without requiring sudo. Production behaviour preserved.

# T27a: Writable abs-path script referenced by at-job → WRITABLE_SCRIPT[root,at]
setup_fixture
touch "$TESTDIR/scripts/at_target.sh"
chmod +w "$TESTDIR/scripts/at_target.sh"
cat > "$TESTDIR/var/spool/cron/atjobs/a000010147de65b" <<EOF
#!/bin/sh
# atrun uid=0 gid=0
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin; export PATH
cd /root || exit 1
$TESTDIR/scripts/at_target.sh
EOF
chmod 600 "$TESTDIR/var/spool/cron/atjobs/a000010147de65b"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WRITABLE_SCRIPT[root,at]: $TESTDIR/scripts/at_target.sh" "T27a: writable abs-path script in at-job body detected"
teardown_fixture

# T27b: Relative cmd + writable PATH dir from at-job body → both markers
setup_fixture
mkdir -p "$TESTDIR/at_writable_path"
chmod +w "$TESTDIR/at_writable_path"
cat > "$TESTDIR/var/spool/cron/atjobs/a000020155555" <<EOF
#!/bin/sh
# atrun uid=0 gid=0
PATH=$TESTDIR/at_writable_path:/usr/bin; export PATH
at_relative_cmd
EOF
chmod 600 "$TESTDIR/var/spool/cron/atjobs/a000020155555"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "RELATIVE_CMD[root,at]: at_relative_cmd" "T27b1: relative cmd in at-job body detected"
assert_contains "$OUT" "WRITABLE_PATH_DIR[at]: $TESTDIR/at_writable_path" "T27b2: writable PATH dir from at-job body detected"
teardown_fixture

# T27c: Wildcard in at-job body → WILDCARD[root,at]
setup_fixture
cat > "$TESTDIR/var/spool/cron/atjobs/a000030166666" <<EOF
#!/bin/sh
# atrun uid=0 gid=0
PATH=/usr/bin:/bin; export PATH
cd /tmp
tar czf /b.tgz *
EOF
chmod 600 "$TESTDIR/var/spool/cron/atjobs/a000030166666"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WILDCARD[root,at]:" "T27c: wildcard in at-job body detected"
teardown_fixture

# T27d: At-job file itself writable → WRITABLE_SCRIPT[root,at] for the file path
setup_fixture
cat > "$TESTDIR/var/spool/cron/atjobs/a000040177777" <<EOF
#!/bin/sh
# atrun uid=0 gid=0
PATH=/usr/bin:/bin; export PATH
echo no-op
EOF
chmod 666 "$TESTDIR/var/spool/cron/atjobs/a000040177777"
OUT=$("$TESTDIR/sched_enum.sh")
assert_contains "$OUT" "WRITABLE_SCRIPT[root,at]: $TESTDIR/var/spool/cron/atjobs/a000040177777" "T27d: writable at-job file itself detected"
teardown_fixture

# T27e: Empty spool dir → no at-markers, no AT_SPOOL_DENIED
setup_fixture
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" ",at]" "T27e1: empty spool → no at-routing markers"
assert_not_contains "$OUT" "AT_SPOOL_DENIED" "T27e2: empty spool → no AT_SPOOL_DENIED"
teardown_fixture

# T27f: No spool dir at all → no at-markers, no AT_SPOOL_DENIED
setup_fixture
rmdir "$TESTDIR/var/spool/cron/atjobs"
OUT=$("$TESTDIR/sched_enum.sh")
assert_not_contains "$OUT" ",at]" "T27f1: no spool dir → no at-routing markers"
assert_not_contains "$OUT" "AT_SPOOL_DENIED" "T27f2: no spool dir → no AT_SPOOL_DENIED"
teardown_fixture

# T27g: Spool with unreadable files (foothold scenario) → AT_SPOOL_DENIED
# Requires non-root execution; root bypasses chmod via DAC_OVERRIDE.
if [ "$(id -u)" != "0" ]; then
  setup_fixture
  cat > "$TESTDIR/var/spool/cron/atjobs/a000050188888" <<EOF
#!/bin/sh
# atrun uid=0 gid=0
PATH=/usr/bin:/bin; export PATH
echo no-op
EOF
  chmod 000 "$TESTDIR/var/spool/cron/atjobs/a000050188888"
  OUT=$("$TESTDIR/sched_enum.sh")
  assert_contains "$OUT" "AT_SPOOL_DENIED: $TESTDIR/var/spool/cron/atjobs" "T27g: unreadable job file → AT_SPOOL_DENIED"
  teardown_fixture
else
  echo "SKIP: T27g (requires non-root execution; root bypasses chmod via DAC_OVERRIDE)"
  SKIP=$((SKIP+1))
fi

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
