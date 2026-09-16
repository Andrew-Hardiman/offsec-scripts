#!/bin/bash
# loose_creds_enum_tests.sh — Regression tests for loose_creds_enum.sh
#
# Each test creates an isolated /var/tmp/<random> directory mimicking the
# target filesystem layout (/etc/passwd + user home dirs + /etc + /var/www +
# /srv + /opt + /tmp + /var/backups + /var/mail + /var/spool + /root),
# sed-rewrites a copy of loose_creds_enum.sh to point at it, runs that copy,
# asserts against expected output, tears down.
#
# Fixture prefix is /var/tmp NOT /tmp — the script's own /tmp find target
# would cause cascading sed substitutions if we prefixed with /tmp.
#
# Run: ./loose_creds_enum_tests.sh
# Exit code: 0 if all pass, non-zero count = failures.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_SCRIPT="$SCRIPT_DIR/loose_creds_enum.sh"

if [ ! -f "$TARGET_SCRIPT" ]; then
  echo "ERROR: cannot find loose_creds_enum.sh at $TARGET_SCRIPT"
  exit 1
fi

PASS=0
FAIL=0
SKIP=0

setup_fixture() {
  TESTDIR=$(mktemp -d /var/tmp/loose.XXXXXX)
  mkdir -p "$TESTDIR/etc" "$TESTDIR/usr/local/etc" "$TESTDIR/var/www" "$TESTDIR/srv" \
           "$TESTDIR/opt" "$TESTDIR/tmp" "$TESTDIR/var/backups" "$TESTDIR/var/mail" \
           "$TESTDIR/var/spool" "$TESTDIR/root"
  # Rewrite all hardcoded paths in loose_creds_enum.sh to point at $TESTDIR.
  # Order matters: /etc/passwd first (won't cascade), then tree-class find calls.
  sed -e "s|/etc/passwd|$TESTDIR/etc/passwd|g" \
      -e "s|find /etc /usr/local/etc|find $TESTDIR/etc $TESTDIR/usr/local/etc|g" \
      -e "s|for tree in /var/www /srv|for tree in $TESTDIR/var/www $TESTDIR/srv|g" \
      -e "s|\\[ -d /opt \\]|[ -d $TESTDIR/opt ]|g" \
      -e "s|find /opt|find $TESTDIR/opt|g" \
      -e "s|for tree in /var/backups /var/mail /var/spool /root|for tree in $TESTDIR/var/backups $TESTDIR/var/mail $TESTDIR/var/spool $TESTDIR/root|g" \
      -e "s|\\[ -d /tmp \\]|[ -d $TESTDIR/tmp ]|g" \
      -e "s|find /tmp|find $TESTDIR/tmp|g" \
      "$TARGET_SCRIPT" > "$TESTDIR/loose_creds_enum.sh"
  chmod +x "$TESTDIR/loose_creds_enum.sh"
}

teardown_fixture() {
  rm -rf "$TESTDIR"
}

# Default fixture: one user with home directory; called from tests that need a user
mk_user() {
  local user="$1" uid="${2:-1000}" home="$3"
  mkdir -p "$home"
  cat >> "$TESTDIR/etc/passwd" <<EOF
$user:x:$uid:$uid::$home:/bin/bash
EOF
}

# Non-interactive user (nologin shell) — should be SKIPPED by Tree-class 2
mk_nologin_user() {
  local user="$1" uid="${2:-999}" home="$3"
  mkdir -p "$home"
  cat >> "$TESTDIR/etc/passwd" <<EOF
$user:x:$uid:$uid::$home:/usr/sbin/nologin
EOF
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
# Marker emission tests
# ============================================================================

# T1: No suspicious files anywhere → LOOSE_CRED_EMPTY
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "hello" > "$TESTDIR/etc/normal.conf"
echo "hello" > "$TESTDIR/home/u/notes.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "LOOSE_CRED_EMPTY" "T1a: empty case emits LOOSE_CRED_EMPTY"
assert_not_contains "$OUT" "LOOSE_CRED_FILE" "T1b: empty case emits no LOOSE_CRED_FILE"
teardown_fixture

# T2: Single suspicious file → LOOSE_CRED_FILE with path
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "root:HuntedValue" > "$TESTDIR/etc/password.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "LOOSE_CRED_FILE: $TESTDIR/etc/password.txt" "T2a: single hit emits LOOSE_CRED_FILE with path"
assert_not_contains "$OUT" "LOOSE_CRED_EMPTY" "T2b: non-empty case does not emit LOOSE_CRED_EMPTY"
teardown_fixture

# T3: Multiple suspicious files → one LOOSE_CRED_FILE per file
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "1" > "$TESTDIR/etc/password.txt"
echo "2" > "$TESTDIR/etc/secret.dat"
echo "3" > "$TESTDIR/etc/token.log"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "password.txt" "T3a: first of many hits emitted"
assert_contains "$OUT" "secret.dat" "T3b: second of many hits emitted"
assert_contains "$OUT" "token.log" "T3c: third of many hits emitted"
teardown_fixture

# ============================================================================
# Per-glob positive tests — one file per glob, verify it matches
# ============================================================================

# T4: *password*
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/mypassword.dat"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "mypassword.dat" "T4: *password* glob catches mypassword.dat"
teardown_fixture

# T5: *passwd*
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/passwd.dpkg-old"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "passwd.dpkg-old" "T5: *passwd* glob catches passwd.dpkg-old"
teardown_fixture

# T6: *credential*
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/aws_credential"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "aws_credential" "T6: *credential* glob catches aws_credential"
teardown_fixture

# T7: *creds*
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/backup_creds"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "backup_creds" "T7: *creds* glob catches backup_creds"
teardown_fixture

# T8: *secret*
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/api_secret.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "api_secret.txt" "T8: *secret* glob catches api_secret.txt"
teardown_fixture

# T9: *token*
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/oauth_token"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "oauth_token" "T9: *token* glob catches oauth_token"
teardown_fixture

# T10: *login*
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/login_data"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "login_data" "T10: *login* glob catches login_data"
teardown_fixture

# T11: *hash*
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/user_hashes.dump"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "user_hashes.dump" "T11: *hash* glob catches user_hashes.dump"
teardown_fixture

# T12: *.pwd
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/admin.pwd"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "admin.pwd" "T12: *.pwd glob catches admin.pwd"
teardown_fixture

# T13: *.password
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/db.password"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "db.password" "T13: *.password glob catches db.password"
teardown_fixture

# T14: *.pem
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/cert.pem"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "cert.pem" "T14: *.pem glob catches cert.pem"
teardown_fixture

# T15: *.key (NOT via /.ssh/ path, so we don't hit the exclusion)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/signing.key"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "signing.key" "T15: *.key glob catches signing.key"
teardown_fixture

# T16: *.priv
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/wallet.priv"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "wallet.priv" "T16: *.priv glob catches wallet.priv"
teardown_fixture

# T17: *_key
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/master_key"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "master_key" "T17: *_key glob catches master_key"
teardown_fixture

# ============================================================================
# Case-insensitivity tests
# ============================================================================

# T18: Uppercase basename
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/PASSWORD.TXT"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "PASSWORD.TXT" "T18: uppercase PASSWORD.TXT caught (case-insensitive)"
teardown_fixture

# T19: Mixed case
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/MySeCrEt.Log"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "MySeCrEt.Log" "T19: mixed-case MySeCrEt.Log caught"
teardown_fixture

# ============================================================================
# Backup variants — should be caught by wildcard globs
# ============================================================================

# T20: password.txt.bak — caught by *password* wildcard
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/password.txt.bak"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "password.txt.bak" "T20: password.txt.bak caught via *password* wildcard"
teardown_fixture

# T21: secrets.old — caught by *secret* wildcard
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/secrets.old"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "secrets.old" "T21: secrets.old caught via *secret* wildcard"
teardown_fixture

# T22: creds~ (editor backup) — caught by *creds* wildcard
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/creds~"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "creds~" "T22: creds~ editor backup caught via *creds* wildcard"
teardown_fixture

# ============================================================================
# Path exclusion tests
# ============================================================================

# T23: /etc/passwd (canonical, exact-path exclusion) NOT emitted
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "LOOSE_CRED_FILE: $TESTDIR/etc/passwd" "T23: /etc/passwd canonical NOT emitted"
teardown_fixture

# T24: /etc/passwd.bak (backup variant) IS emitted (backup exclusion doesn't apply)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "legacy" > "$TESTDIR/etc/passwd.bak"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "passwd.bak" "T24: /etc/passwd.bak backup variant IS emitted"
teardown_fixture

# T25: /etc/pam.d/* excluded
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/etc/pam.d"
echo "x" > "$TESTDIR/etc/pam.d/common-password"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "common-password" "T25: /etc/pam.d/common-password NOT emitted"
teardown_fixture

# T26: /etc/pam.conf excluded (and its backup variants)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/pam.conf"
# pam.conf itself contains no glob-match — needs a matching name. Force one:
mkdir -p "$TESTDIR/etc/pam.d"
echo "x" > "$TESTDIR/etc/pam.conf.password.bak"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "pam.conf.password.bak" "T26: /etc/pam.conf* backup variant NOT emitted"
teardown_fixture

# T27: /etc/ssh/* excluded (ssh_enum's territory)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/etc/ssh"
echo "x" > "$TESTDIR/etc/ssh/host_key"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "host_key" "T27: /etc/ssh/host_key NOT emitted"
teardown_fixture

# T28: /home/u/.ssh/* excluded
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/home/u/.ssh"
echo "x" > "$TESTDIR/home/u/.ssh/deploy_key"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "deploy_key" "T28: user .ssh/deploy_key NOT emitted"
teardown_fixture

# T29: /etc/apparmor.d/* excluded
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/etc/apparmor.d"
echo "x" > "$TESTDIR/etc/apparmor.d/usr.bin.passwd"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "usr.bin.passwd" "T29: /etc/apparmor.d/usr.bin.passwd NOT emitted"
teardown_fixture

# T30: /etc/selinux/* excluded
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/etc/selinux/targeted"
echo "x" > "$TESTDIR/etc/selinux/targeted/password.te"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "password.te" "T30: /etc/selinux/targeted/password.te NOT emitted"
teardown_fixture

# T31: Non-.ssh /etc paths still emit (path exclusion is specific)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/etc/myapp"
echo "x" > "$TESTDIR/etc/myapp/password.conf"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "password.conf" "T31: custom /etc/myapp/password.conf IS emitted (not excluded)"
teardown_fixture

# ============================================================================
# Tree-class coverage
# ============================================================================

# T32: Tree-class 1 — /etc
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/tc1_secret"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "tc1_secret" "T32: Tree-class 1 (/etc) caught"
teardown_fixture

# T33: Tree-class 1 — /usr/local/etc
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/usr/local/etc/tc1b_secret"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "tc1b_secret" "T33: Tree-class 1 (/usr/local/etc) caught"
teardown_fixture

# T34: Tree-class 2 — home dir (interactive user)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/home/u/my_secret.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "my_secret.txt" "T34: Tree-class 2 (user home) caught"
teardown_fixture

# T35: Tree-class 3a — /var/www
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/var/www/app"
echo "x" > "$TESTDIR/var/www/app/db_password.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "db_password.txt" "T35: Tree-class 3a (/var/www) caught"
teardown_fixture

# T36: Tree-class 3a — /srv
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/srv/site_credentials"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "site_credentials" "T36: Tree-class 3a (/srv) caught"
teardown_fixture

# T37: Tree-class 3b — /opt
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/opt/app"
echo "x" > "$TESTDIR/opt/app/api_secret.yml"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "api_secret.yml" "T37: Tree-class 3b (/opt) caught"
teardown_fixture

# T38: Tree-class 4 — /tmp
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/tmp/dropped_creds"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "dropped_creds" "T38: Tree-class 4 (/tmp) caught"
teardown_fixture

# T39: Tree-class 4 — /var/backups
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/var/backups/passwd_backup.old"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "passwd_backup.old" "T39: Tree-class 4 (/var/backups) caught"
teardown_fixture

# T40: Tree-class 4 — /var/mail
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/var/mail/secret_notice"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "secret_notice" "T40: Tree-class 4 (/var/mail) caught"
teardown_fixture

# T41: Tree-class 4 — /var/spool
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/var/spool/mail"
echo "x" > "$TESTDIR/var/spool/mail/token_dump"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "token_dump" "T41: Tree-class 4 (/var/spool) caught"
teardown_fixture

# T42: Tree-class 4 — /root
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/root/root_password"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "root_password" "T42: Tree-class 4 (/root) caught"
teardown_fixture

# ============================================================================
# Maxdepth boundary tests
# ============================================================================

# T43: /etc at maxdepth 4 — file at depth 4 IS caught
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/etc/a/b/c"
echo "x" > "$TESTDIR/etc/a/b/c/password.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "$TESTDIR/etc/a/b/c/password.txt" "T43: /etc file at depth 4 caught"
teardown_fixture

# T44: /etc at maxdepth 4 — file at depth 5 is NOT caught
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/etc/a/b/c/d"
echo "x" > "$TESTDIR/etc/a/b/c/d/password.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "$TESTDIR/etc/a/b/c/d/password.txt" "T44: /etc file at depth 5 NOT caught (maxdepth 4)"
teardown_fixture

# T45: home dir at maxdepth 3 — file at depth 3 IS caught
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/home/u/a/b"
echo "x" > "$TESTDIR/home/u/a/b/secret.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "$TESTDIR/home/u/a/b/secret.txt" "T45: home file at depth 3 caught"
teardown_fixture

# T46: home dir at maxdepth 3 — file at depth 4 is NOT caught
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/home/u/a/b/c"
echo "x" > "$TESTDIR/home/u/a/b/c/secret.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "$TESTDIR/home/u/a/b/c/secret.txt" "T46: home file at depth 4 NOT caught (maxdepth 3)"
teardown_fixture

# T47: /tmp at maxdepth 2 — file at depth 2 IS caught
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/tmp/subdir"
echo "x" > "$TESTDIR/tmp/subdir/password.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "$TESTDIR/tmp/subdir/password.txt" "T47: /tmp file at depth 2 caught"
teardown_fixture

# T48: /tmp at maxdepth 2 — file at depth 3 is NOT caught
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/tmp/a/b"
echo "x" > "$TESTDIR/tmp/a/b/password.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "$TESTDIR/tmp/a/b/password.txt" "T48: /tmp file at depth 3 NOT caught (maxdepth 2)"
teardown_fixture

# ============================================================================
# Size cap
# ============================================================================

# T49: File >= 1 MiB with matching name is NOT emitted
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
dd if=/dev/zero of="$TESTDIR/etc/big_password.dump" bs=1024 count=1100 2>/dev/null   # ~1.1 MiB
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "big_password.dump" "T49: file >= 1 MiB NOT emitted (size cap)"
teardown_fixture

# T50: File just under 1 MiB IS emitted
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
dd if=/dev/zero of="$TESTDIR/etc/medium_password.dump" bs=1024 count=1000 2>/dev/null  # ~1000 KiB
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_contains "$OUT" "medium_password.dump" "T50: file just under 1 MiB IS emitted"
teardown_fixture

# ============================================================================
# Home dir filtering
# ============================================================================

# T51: Non-interactive (nologin shell) user home NOT scanned
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"                    # interactive
mk_nologin_user svc 500 "$TESTDIR/home/svc"         # non-interactive, UID < 1000
echo "x" > "$TESTDIR/home/svc/secret.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "$TESTDIR/home/svc/secret.txt" "T51: nologin user's home NOT scanned"
teardown_fixture

# T52: Low-UID non-root non-interactive account NOT scanned
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
# UID 100 = typical service account range; nologin shell = non-interactive
mk_nologin_user svc2 100 "$TESTDIR/home/svc2"
echo "x" > "$TESTDIR/home/svc2/secret.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "$TESTDIR/home/svc2/secret.txt" "T52: UID<1000 nologin account home NOT scanned"
teardown_fixture

# T53: root home IS scanned (UID=0 special case in awk filter)
setup_fixture
# Note: mk_user with UID 0 to represent root; home is /root
mk_user root 0 "$TESTDIR/root"
echo "x" > "$TESTDIR/root/password.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
# Emitted from either Tree-class 2 (root home enumeration) OR Tree-class 4 (/root direct)
assert_contains "$OUT" "$TESTDIR/root/password.txt" "T53: root's home caught"
teardown_fixture

# ============================================================================
# Symlink handling
# ============================================================================

# T54: Symlink is not followed (find -type f skips symlink files)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/outside"
echo "target-content" > "$TESTDIR/outside/password.txt"
ln -s "$TESTDIR/outside/password.txt" "$TESTDIR/etc/pw_symlink.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
# The symlink itself (etc/pw_symlink.txt) is type l, not f — not caught.
# The target (outside/password.txt) is outside all tree-classes — not scanned.
assert_not_contains "$OUT" "$TESTDIR/etc/pw_symlink.txt" "T54: symlink itself NOT emitted"
assert_not_contains "$OUT" "$TESTDIR/outside/password.txt" "T54b: symlink target (out-of-tree) NOT emitted"
teardown_fixture

# ============================================================================
# Dedup
# ============================================================================

# T55: File emitted exactly once even if it lives in a tree-class overlap
# Loose-cred trees don't overlap by design, but symlinks could create phantom
# overlap. Not testing symlink cross-tree — the sort -u | mapfile line covers it.
# Test that duplicated find results aren't emitted twice.
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/dedup_password.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
COUNT=$(echo "$OUT" | grep -c "dedup_password.txt")
if [ "$COUNT" = "1" ]; then
    echo "PASS: T55: file emitted exactly once (count=$COUNT)"
    PASS=$((PASS+1))
else
    echo "FAIL: T55: file emitted $COUNT times (expected 1)"
    FAIL=$((FAIL+1))
fi
teardown_fixture

# ============================================================================
# Marker format
# ============================================================================

# T56: LOOSE_CRED_FILE format is exactly "LOOSE_CRED_FILE: <abs-path>"
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/fmt_password.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
# Assert the marker line matches exactly (no trailing extra content)
LINE=$(echo "$OUT" | grep "fmt_password.txt")
EXPECTED="LOOSE_CRED_FILE: $TESTDIR/etc/fmt_password.txt"
if [ "$LINE" = "$EXPECTED" ]; then
    echo "PASS: T56: marker format exact"
    PASS=$((PASS+1))
else
    echo "FAIL: T56: marker format mismatch"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $LINE"
    FAIL=$((FAIL+1))
fi
teardown_fixture

# ============================================================================
# Privilege-context detection
# T57–T59 mirror config_enum_tests.sh T57–T59. Same mechanic under test
# (conditional -readable based on EUID/RUID comparison). Provides independent
# regression coverage in case loose_creds_enum drifts from the shared idiom.
# ============================================================================

# T57: Same script run as root vs UID 1000 yields different file sets.
if [ "$(id -u)" = "0" ] && command -v setpriv >/dev/null; then
    setup_fixture
    mk_user u 1000 "$TESTDIR/home/u"
    mk_user root 0 "$TESTDIR/root"
    echo "root-only-content" > "$TESTDIR/etc/root_only_password.txt"
    chmod 600 "$TESTDIR/etc/root_only_password.txt"
    chmod 755 "$TESTDIR" "$TESTDIR/etc"
    chmod 644 "$TESTDIR/etc/passwd"

    ROOT_OUT=$("$TESTDIR/loose_creds_enum.sh")
    UID1000_OUT=$(setpriv --reuid=1000 --regid=1000 --clear-groups "$TESTDIR/loose_creds_enum.sh" 2>&1)
    assert_contains "$ROOT_OUT" "root_only_password.txt" "T57a: root sees root-only file"
    assert_not_contains "$UID1000_OUT" "root_only_password.txt" "T57b: UID 1000 does NOT see root-only file"
    teardown_fixture
else
    echo "SKIP: T57a: root sees root-only file (requires running as root with setpriv — try: sudo ./loose_creds_enum_tests.sh)"
    echo "SKIP: T57b: UID 1000 does NOT see root-only file (requires running as root with setpriv — try: sudo ./loose_creds_enum_tests.sh)"
    SKIP=$((SKIP+2))
fi

# T58: SUID drop-and-launch post-root context (RUID=1000, EUID=0)
if [ "$(id -u)" = "0" ] && command -v gcc >/dev/null && command -v setpriv >/dev/null; then
    setup_fixture
    mk_user u 1000 "$TESTDIR/home/u"
    mk_user root 0 "$TESTDIR/root"
    echo "suid-context-content" > "$TESTDIR/etc/suid_password.txt"
    chown root:root "$TESTDIR/etc/suid_password.txt"
    chmod 600 "$TESTDIR/etc/suid_password.txt"
    chmod 755 "$TESTDIR" "$TESTDIR/etc"
    chmod 644 "$TESTDIR/etc/passwd"

    cat > "$TESTDIR/suid_wrapper.c" <<'WRAPPER_EOF'
#include <unistd.h>
#include <stdio.h>
int main(int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "usage: %s <script>\n", argv[0]); return 1; }
    execl("/bin/bash", "bash", "-p", argv[1], NULL);
    perror("execl");
    return 1;
}
WRAPPER_EOF
    if gcc -o "$TESTDIR/suid_wrapper" "$TESTDIR/suid_wrapper.c" 2>/dev/null; then
        chown root:root "$TESTDIR/suid_wrapper"
        chmod 4755 "$TESTDIR/suid_wrapper"

        SUID_OUT=$(setpriv --reuid=1000 --regid=1000 --clear-groups \
            "$TESTDIR/suid_wrapper" "$TESTDIR/loose_creds_enum.sh" 2>&1)
        assert_contains "$SUID_OUT" "suid_password.txt" \
            "T58a: SUID context (RUID=1000 EUID=0) finds root-only file via skipped -readable"

        UID1000_OUT=$(setpriv --reuid=1000 --regid=1000 --clear-groups \
            "$TESTDIR/loose_creds_enum.sh" 2>&1)
        assert_not_contains "$UID1000_OUT" "suid_password.txt" \
            "T58b: same fixture, straight UID 1000 (no SUID wrapper) does NOT find root-only file"
    else
        echo "SKIP: T58a: SUID context finds root-only file via skipped -readable (gcc compilation failed)"
        echo "SKIP: T58b: straight UID 1000 does NOT find root-only file (gcc compilation failed)"
        SKIP=$((SKIP+2))
    fi
    teardown_fixture
else
    echo "SKIP: T58a: SUID context finds root-only file (requires root + gcc + setpriv — try: sudo ./loose_creds_enum_tests.sh)"
    echo "SKIP: T58b: straight UID 1000 does NOT find root-only file (requires root + gcc + setpriv — try: sudo ./loose_creds_enum_tests.sh)"
    SKIP=$((SKIP+2))
fi

# T59: Sudo-style post-root (RUID=EUID=0) — verifies the fix didn't regress
# the common case (which every other test in this file implicitly runs in).
if [ "$(id -u)" = "0" ]; then
    setup_fixture
    mk_user u 1000 "$TESTDIR/home/u"
    echo "sudo-style-content" > "$TESTDIR/etc/sudo_password.txt"
    OUT=$("$TESTDIR/loose_creds_enum.sh")
    assert_contains "$OUT" "sudo_password.txt" "T59: RUID=EUID=0 (sudo-style) finds files"
    teardown_fixture
else
    echo "SKIP: T59: RUID=EUID=0 (sudo-style) finds files (requires running as root — try: sudo ./loose_creds_enum_tests.sh)"
    SKIP=$((SKIP+1))
fi

# ============================================================================
# Negative controls — patterns deliberately EXCLUDED from the glob set
# ============================================================================

# T60: 'keyboard' does NOT match (bare *key* excluded)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/keyboard.conf"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "keyboard.conf" "T60: keyboard.conf NOT matched (bare *key* excluded)"
teardown_fixture

# T61: 'auth_type' does NOT match (bare *auth* excluded)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/auth_type.conf"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "auth_type.conf" "T61: auth_type.conf NOT matched (bare *auth* excluded)"
teardown_fixture

# T62: 'admin_email' does NOT match (bare *admin* excluded)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "x" > "$TESTDIR/etc/admin_email.txt"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "admin_email.txt" "T62: admin_email.txt NOT matched (bare *admin* excluded)"
teardown_fixture

# T63: /etc/passwd- (shadow-utils rolling backup) NOT emitted.
# Same-content-as-passwd rationale as T23 — byte-identical to /etc/passwd
# (system-generated, not admin-writeable), so if /etc/passwd clears the bar,
# so does its rolling backup.
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "root:x:0:0:root:/root:/bin/bash" > "$TESTDIR/etc/passwd-"
OUT=$("$TESTDIR/loose_creds_enum.sh")
assert_not_contains "$OUT" "$TESTDIR/etc/passwd-" "T63: /etc/passwd- (shadow-utils rolling backup) NOT emitted"
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
