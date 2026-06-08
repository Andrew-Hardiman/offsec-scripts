#!/bin/bash
# config_enum_tests.sh — Regression tests for config_enum.sh
#
# Each test creates an isolated /tmp/<random> directory mimicking the target
# filesystem layout (/etc/passwd + user home dirs + /etc + /var/www + /opt etc),
# sed-rewrites a copy of config_enum.sh to point at it, runs that copy, asserts
# against expected output, tears down.
#
# Run: ./config_enum_tests.sh
# Exit code: 0 if all pass, non-zero count = failures.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_SCRIPT="$SCRIPT_DIR/config_enum.sh"

if [ ! -f "$TARGET_SCRIPT" ]; then
  echo "ERROR: cannot find config_enum.sh at $TARGET_SCRIPT"
  exit 1
fi

PASS=0
FAIL=0

setup_fixture() {
  TESTDIR=$(mktemp -d)
  mkdir -p "$TESTDIR/etc" "$TESTDIR/usr/local/etc" "$TESTDIR/var/www" "$TESTDIR/srv" "$TESTDIR/opt"
  # Rewrite all hardcoded paths in config_enum.sh to point at $TESTDIR
  sed -e "s|/etc/passwd|$TESTDIR/etc/passwd|g" \
      -e "s|find /etc /usr/local/etc|find $TESTDIR/etc $TESTDIR/usr/local/etc|g" \
      -e "s|for tree in /var/www /srv|for tree in $TESTDIR/var/www $TESTDIR/srv|g" \
      -e "s|\\[ -d /opt \\]|[ -d $TESTDIR/opt ]|g" \
      -e "s|find /opt|find $TESTDIR/opt|g" \
      "$TARGET_SCRIPT" > "$TESTDIR/config_enum.sh"
  chmod +x "$TESTDIR/config_enum.sh"
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

# T1: No config files exist anywhere → CONFIG_EMPTY
setup_fixture
touch "$TESTDIR/etc/passwd"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_EMPTY" "T1a: empty case emits CONFIG_EMPTY"
assert_not_contains "$OUT" "CONFIG_CRED" "T1b: empty case emits no CONFIG_CRED"
assert_not_contains "$OUT" "CONFIG_FOUND" "T1c: empty case emits no CONFIG_FOUND"
teardown_fixture

# T2: Config file exists but no cred patterns → CONFIG_FOUND
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
cat > "$TESTDIR/etc/apache.conf" <<EOF
ServerName localhost
DocumentRoot /var/www/html
EOF
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_FOUND: $TESTDIR/etc/apache.conf" "T2a: no-cred file emits CONFIG_FOUND"
assert_not_contains "$OUT" "CONFIG_CRED" "T2b: no-cred file emits no CONFIG_CRED"
teardown_fixture

# T3: Config file with cred pattern → CONFIG_CRED including matched line
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
cat > "$TESTDIR/etc/my.cnf" <<EOF
[client]
password=Secret123
EOF
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED[$TESTDIR/etc/my.cnf]:" "T3a: cred match emits CONFIG_CRED marker"
assert_contains "$OUT" "password=Secret123" "T3b: CONFIG_CRED includes matched line"
teardown_fixture

# ============================================================================
# Per-syntax regex coverage (master pattern alternations)
# ============================================================================

# T4: INI/properties assignment
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "password=iniSecret" > "$TESTDIR/etc/app.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T4: INI assignment caught"
teardown_fixture

# T5: YAML colon
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "password: yamlSecret" > "$TESTDIR/etc/app.yml"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T5: YAML colon caught"
teardown_fixture

# T6: JSON quoted key
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo '{"password": "jsonSecret"}' > "$TESTDIR/etc/app.json"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T6: JSON caught"
teardown_fixture

# T7: PHP variable
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/var/www/html"
echo "<?php \$password = 'phpSecret'; ?>" > "$TESTDIR/var/www/html/wp-config.php"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T7: PHP variable caught"
teardown_fixture

# T8: PHP define
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/var/www/html"
echo "<?php define('DB_PASSWORD', 'phpDefSecret'); ?>" > "$TESTDIR/var/www/html/wp-config.php"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T8: PHP define caught"
teardown_fixture

# T9: XML element
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "<config><password>xmlSecret</password></config>" > "$TESTDIR/etc/app.xml"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T9: XML element caught"
teardown_fixture

# T10: XML attribute (via INI pattern)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo '<user password="xmlAttrSecret" />' > "$TESTDIR/etc/users.xml"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T10: XML attribute caught"
teardown_fixture

# T11: PEM private key header
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
cat > "$TESTDIR/etc/ssl.conf" <<EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
EOF
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T11: PEM header caught"
teardown_fixture

# T12: URL-embedded credentials
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "DATABASE_URL=mysql://user:hunter2@localhost/db" > "$TESTDIR/etc/app.env"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T12: URL embedded creds caught"
teardown_fixture

# T13: GitHub PAT
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "token: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" > "$TESTDIR/etc/app.yml"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T13: GitHub PAT caught"
teardown_fixture

# T14: Bearer token
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "Authorization: Bearer abc123" > "$TESTDIR/etc/api.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T14: Bearer token caught"
teardown_fixture

# T15: auth keyword (Docker config form)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/home/u/.docker"
echo '{"auths":{"reg":{"auth":"dXNlcjpwYXNz"}}}' > "$TESTDIR/home/u/.docker/config.json"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T15: auth keyword (Docker) caught"
teardown_fixture

# ============================================================================
# Compound key coverage
# ============================================================================

# T16: db_password (Spring/Rails style)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "spring.datasource.db_password=springSecret" > "$TESTDIR/etc/app.properties"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T16: db_password caught"
teardown_fixture

# T17: MYSQL_PWD env-style (compound with _pwd)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "MYSQL_PWD=mysqlEnvSecret" > "$TESTDIR/etc/mysqld.env"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T17: MYSQL_PWD caught"
teardown_fixture

# T18: pgpassword standalone (no underscore)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "PGPASSWORD=pgEnvSecret" > "$TESTDIR/etc/pg.env"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T18: pgpassword caught"
teardown_fixture

# T19: aws_secret_access_key
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/home/u/.aws"
echo "aws_secret_access_key = AKIA-test-key" > "$TESTDIR/home/u/.aws/credentials"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T19: aws_secret_access_key caught"
teardown_fixture

# T20: db_passwd variant (_passwd not _password)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "db_passwd=passwdVariantSecret" > "$TESTDIR/etc/app.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T20: db_passwd variant caught"
teardown_fixture

# ============================================================================
# False positive controls (key-name boundary, suffix, prose)
# ============================================================================

# T21: password_field (metadata, NOT a cred)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "password_field = userPassword" > "$TESTDIR/etc/app.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_FOUND" "T21a: password_field emits FOUND not CRED"
assert_not_contains "$OUT" "CONFIG_CRED" "T21b: password_field NOT matched"
teardown_fixture

# T22: password_max_age (config, NOT a cred)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "password_max_age = 90" > "$TESTDIR/etc/pam.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_CRED" "T22: password_max_age NOT matched"
teardown_fixture

# T23: xpassword substring (no left word boundary)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "xpassword = X" > "$TESTDIR/etc/app.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_CRED" "T23: xpassword substring NOT matched"
teardown_fixture

# T24: PAM-style space-delimited (no equals sign)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "password   required   pam_unix.so" > "$TESTDIR/etc/pam.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_CRED" "T24: PAM space-delim NOT matched"
teardown_fixture

# T25: URL with port (no creds, NOT matched)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "url=https://example.com:8080/path" > "$TESTDIR/etc/app.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_CRED" "T25: URL with port NOT matched as cred"
teardown_fixture

# T26: PEM public key (NOT matched — we only flag PRIVATE)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "-----BEGIN PUBLIC KEY-----" > "$TESTDIR/etc/ssl.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_CRED" "T26: PEM public key NOT matched"
teardown_fixture

# T27: auth_type metadata (NOT matched)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "auth_type=basic" > "$TESTDIR/etc/auth.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_CRED" "T27: auth_type NOT matched"
teardown_fixture

# ============================================================================
# Empty values (axis-3: match these — empty password is itself a finding)
# ============================================================================

# T28: Empty value matches
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "password = " > "$TESTDIR/etc/app.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T28: empty value matched"
teardown_fixture

# T29: Bare key with equals
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "password=" > "$TESTDIR/etc/app.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T29: bare key= matched"
teardown_fixture

# ============================================================================
# Placeholders (axis-3: don't filter — lazy sysadmin leaves real defaults)
# ============================================================================

# T30: changeme placeholder
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "password = changeme" > "$TESTDIR/etc/app.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T30: changeme placeholder matched"
teardown_fixture

# T31: Commented-out credential (still readable)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "# password = oldCommentedCred" > "$TESTDIR/etc/app.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED" "T31: commented cred matched"
teardown_fixture

# ============================================================================
# File-dispatch tests (.netrc, .htpasswd, .pgpass, .ldaprc, .sh)
# ============================================================================

# T32: .netrc — space-delimited password VALUE caught via NETRC_PATTERN
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
cat > "$TESTDIR/home/u/.netrc" <<EOF
machine github.com
login user
password netrcSecretValue
EOF
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED[$TESTDIR/home/u/.netrc]:" "T32a: .netrc CRED marker"
assert_contains "$OUT" "password netrcSecretValue" "T32b: .netrc value extracted"
teardown_fixture

# T33: .ldaprc — BINDPW caught via NETRC_PATTERN
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "BINDPW ldapBindSecret" > "$TESTDIR/home/u/.ldaprc"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "BINDPW ldapBindSecret" "T33: .ldaprc BINDPW caught"
teardown_fixture

# T34: .htpasswd — whole-file emission, every non-blank line
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
cat > "$TESTDIR/etc/.htpasswd" <<EOF
admin:\$apr1\$abc.def
user2:\$2y\$10\$xyz

EOF
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "admin:" "T34a: .htpasswd line 1 emitted"
assert_contains "$OUT" "user2:" "T34b: .htpasswd line 2 emitted"
teardown_fixture

# T35: .pgpass — whole-file emission, format hostname:port:db:user:password
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "localhost:5432:mydb:postgres:pgPassSecret" > "$TESTDIR/home/u/.pgpass"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "localhost:5432:mydb:postgres:pgPassSecret" "T35: .pgpass emitted"
teardown_fixture

# T36: .sh — CLI-flag dispatch (mysql -p<val>)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/var/www/html"
echo "mysql -uroot -pShellCliSecret < dump.sql" > "$TESTDIR/var/www/html/deploy.sh"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "mysql -uroot -pShellCliSecret" "T36: .sh CLI-flag caught"
teardown_fixture

# T37: .sh — assignment dispatch (master pattern still applies)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/var/www/html"
echo 'DB_PASS="shellAssignSecret"' > "$TESTDIR/var/www/html/setup.sh"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "shellAssignSecret" "T37: .sh assignment caught"
teardown_fixture

# T38: .sh — sshpass caught
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/srv/app"
echo "sshpass -p sshpassSecret ssh user@host" > "$TESTDIR/srv/app/connect.sh"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "sshpass -p sshpassSecret" "T38: .sh sshpass caught"
teardown_fixture

# T39: .sh NOT enumerated under /opt (per axis-2 decision)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/opt/myapp"
echo "mysql -uroot -pOptShellSecret < init.sql" > "$TESTDIR/opt/myapp/launch.sh"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "launch.sh" "T39: /opt .sh NOT scanned"
teardown_fixture

# ============================================================================
# Tree enumeration tests
# ============================================================================

# T40: /etc — extension glob (.conf)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "password=etcSecret" > "$TESTDIR/etc/svc.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED[$TESTDIR/etc/svc.conf]" "T40: /etc .conf enumerated"
teardown_fixture

# T41: /usr/local/etc — extension glob
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "api_key=usrLocalSecret" > "$TESTDIR/usr/local/etc/customapp.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "CONFIG_CRED[$TESTDIR/usr/local/etc/customapp.conf]" "T41: /usr/local/etc enumerated"
teardown_fixture

# T42: /home/<user> — named-file allow-list (.my.cnf)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "[client]
password=homeMyCnfSecret" > "$TESTDIR/home/u/.my.cnf"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "homeMyCnfSecret" "T42: home/.my.cnf enumerated"
teardown_fixture

# T43: /root — named-file allow-list
setup_fixture
mk_user root 0 "$TESTDIR/root"
echo "[client]
password=rootMyCnfSecret" > "$TESTDIR/root/.my.cnf"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "rootMyCnfSecret" "T43: /root enumerated"
teardown_fixture

# T44: /var/www — wp-config.php named file
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/var/www/html"
echo "<?php define('DB_PASSWORD', 'wwwSecret'); ?>" > "$TESTDIR/var/www/html/wp-config.php"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "wwwSecret" "T44: /var/www wp-config.php enumerated"
teardown_fixture

# T45: /srv — extension glob (.env)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/srv/app"
echo "SECRET_KEY=srvAppSecret" > "$TESTDIR/srv/app/.env"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "srvAppSecret" "T45: /srv .env enumerated"
teardown_fixture

# T46: /opt — JSON config
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/opt/myapp"
echo '{"password": "optJsonSecret"}' > "$TESTDIR/opt/myapp/config.json"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "optJsonSecret" "T46: /opt config.json enumerated"
teardown_fixture

# T47: Path-scoped home (.aws/credentials)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/home/u/.aws"
echo "aws_secret_access_key = pathScopedSecret" > "$TESTDIR/home/u/.aws/credentials"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "pathScopedSecret" "T47: .aws/credentials path-scoped enumerated"
teardown_fixture

# ============================================================================
# Filter behaviour (maxdepth, size cap)
# ============================================================================

# T48: maxdepth — /etc files over depth 4 are skipped
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/etc/a/b/c/d"
echo "password=overMaxdepth" > "$TESTDIR/etc/a/b/c/d/over.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "overMaxdepth" "T48: /etc files beyond maxdepth 4 skipped"
teardown_fixture

# T49: maxdepth — home files over depth 3 are skipped
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/home/u/a/b/c"
echo "password=homeOverMaxdepth" > "$TESTDIR/home/u/a/b/c/.env"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "homeOverMaxdepth" "T49: home files beyond maxdepth 3 skipped"
teardown_fixture

# T50: maxdepth — /var/www UNBOUNDED depth (files deep should still be found)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/var/www/html/a/b/c/d/e/f/plugin"
echo "password=deepVarWwwSecret" > "$TESTDIR/var/www/html/a/b/c/d/e/f/plugin/.env"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "deepVarWwwSecret" "T50: /var/www unbounded depth found"
teardown_fixture

# T51: Size cap — files >= 1 MiB skipped
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
# Create a 1.5 MB file with a credential at the start
{ echo "password=largeFileSecret"; dd if=/dev/zero bs=1024 count=1600 2>/dev/null; } > "$TESTDIR/etc/large.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "largeFileSecret" "T51: files >= 1 MiB skipped via -size -1048576c"
teardown_fixture

# T52: Size cap — files just under 1 MiB INCLUDED
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
# 500 KB file with credential
{ echo "password=mediumFileSecret"; dd if=/dev/zero bs=1024 count=500 2>/dev/null; } > "$TESTDIR/etc/medium.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "mediumFileSecret" "T52: files under 1 MiB included"
teardown_fixture

# ============================================================================
# Service-account home filtering (UID < 1000 with non-bash shell excluded)
# ============================================================================

# T53: nologin user home is excluded
setup_fixture
mkdir -p "$TESTDIR/var/lib/nologin"
cat > "$TESTDIR/etc/passwd" <<EOF
mail:x:100:100::$TESTDIR/var/lib/nologin:/usr/sbin/nologin
EOF
echo "password=nologinExcluded" > "$TESTDIR/var/lib/nologin/.my.cnf"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "nologinExcluded" "T53: nologin home excluded from enumeration"
teardown_fixture

# T54: UID 500 (under 1000, non-bash by convention) excluded
setup_fixture
mkdir -p "$TESTDIR/var/lib/svc"
cat > "$TESTDIR/etc/passwd" <<EOF
svc:x:500:500::$TESTDIR/var/lib/svc:/sbin/nologin
EOF
echo "password=svcExcluded" > "$TESTDIR/var/lib/svc/.my.cnf"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "svcExcluded" "T54: UID < 1000 nologin home excluded"
teardown_fixture

# ============================================================================
# Output marker format
# ============================================================================

# T55: CONFIG_CRED format is "CONFIG_CRED[<file>]: <linenum>:<line>"
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "password=formatTest" > "$TESTDIR/etc/format.conf"
OUT=$("$TESTDIR/config_enum.sh")
# grep -n prefixes with N: so the marker should contain "]: 1:password="
assert_contains "$OUT" "]: 1:password=formatTest" "T55: marker includes grep line number prefix"
teardown_fixture

# T56: Multiple matches in one file emit multiple CONFIG_CRED lines
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
cat > "$TESTDIR/etc/multi.conf" <<EOF
password=first
api_key=second
EOF
OUT=$("$TESTDIR/config_enum.sh")
LINE_COUNT=$(echo "$OUT" | grep -c "CONFIG_CRED\[$TESTDIR/etc/multi.conf\]")
if [ "$LINE_COUNT" -eq 2 ]; then
  echo "PASS: T56: multiple matches in one file emit multiple CONFIG_CRED lines"
  PASS=$((PASS+1))
else
  echo "FAIL: T56: expected 2 CONFIG_CRED lines for file with 2 matches, got $LINE_COUNT"
  FAIL=$((FAIL+1))
fi
teardown_fixture

# ============================================================================
# Privilege-agnostic (dual-context) validation
# ============================================================================

# T57: Same script run as root vs UID 1000 yields different file sets.
# Requires running as root with setpriv available (so we can drop privileges to UID 1000).
if [ "$(id -u)" = "0" ] && command -v setpriv >/dev/null; then
  setup_fixture
  mk_user u 1000 "$TESTDIR/home/u"
  mk_user root 0 "$TESTDIR/root"
  # File readable only by root
  echo "password=rootOnlyDualCtx" > "$TESTDIR/etc/root-only.conf"
  chmod 600 "$TESTDIR/etc/root-only.conf"
  # Need to allow UID 1000 to traverse $TESTDIR and read $TESTDIR/etc/passwd
  chmod 755 "$TESTDIR" "$TESTDIR/etc"
  chmod 644 "$TESTDIR/etc/passwd"

  ROOT_OUT=$("$TESTDIR/config_enum.sh")
  UID1000_OUT=$(setpriv --reuid=1000 --regid=1000 --clear-groups "$TESTDIR/config_enum.sh" 2>&1)
  assert_contains "$ROOT_OUT" "rootOnlyDualCtx" "T57a: root sees root-only file"
  assert_not_contains "$UID1000_OUT" "rootOnlyDualCtx" "T57b: UID 1000 does NOT see root-only file"
  teardown_fixture
else
  echo "SKIP: T57 (requires running as root with setpriv available — try: sudo ./config_enum_tests.sh)"
fi

# T58: SUID drop-and-launch post-root context (RUID=1000, EUID=0)
# This is the case the conditional -readable fix exists for. A setuid-root C
# wrapper preserves EUID=0 while RUID stays as the unprivileged invoker.
# Without the fix, find -readable would filter by RUID=1000 (the unprivileged
# UID) and miss root-only-readable files. With the fix, the script detects
# EUID=0 & RUID!=0, skips -readable, and grep's open() (EUID-based) succeeds.
if [ "$(id -u)" = "0" ] && command -v gcc >/dev/null && command -v setpriv >/dev/null; then
  setup_fixture
  mk_user u 1000 "$TESTDIR/home/u"
  mk_user root 0 "$TESTDIR/root"
  # File readable only by root
  echo "password=suidPostRootSecret" > "$TESTDIR/etc/root-only.conf"
  chown root:root "$TESTDIR/etc/root-only.conf"
  chmod 600 "$TESTDIR/etc/root-only.conf"
  # Allow UID 1000 to traverse and read /etc/passwd
  chmod 755 "$TESTDIR" "$TESTDIR/etc"
  chmod 644 "$TESTDIR/etc/passwd"

  # Build a setuid-root wrapper that preserves the SUID context to a child bash.
  # bash -p prevents bash from dropping EUID->RUID on startup.
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
      "$TESTDIR/suid_wrapper" "$TESTDIR/config_enum.sh" 2>&1)

    assert_contains "$SUID_OUT" "suidPostRootSecret" \
      "T58a: SUID context (RUID=1000 EUID=0) finds root-only file via skipped -readable"

    # Also verify the suid context is what we expect — the script's own behavior
    # under SUID should differ from straight UID 1000.
    UID1000_OUT=$(setpriv --reuid=1000 --regid=1000 --clear-groups \
      "$TESTDIR/config_enum.sh" 2>&1)
    assert_not_contains "$UID1000_OUT" "suidPostRootSecret" \
      "T58b: same fixture, straight UID 1000 (no SUID wrapper) does NOT find root-only file"
  else
    echo "SKIP: T58 (gcc compilation failed)"
  fi
  teardown_fixture
else
  echo "SKIP: T58 (requires running as root with gcc and setpriv — try: sudo ./config_enum_tests.sh)"
fi

# T59: Sudo-style post-root (RUID=EUID=0) keeps -readable filter and still finds
# all files. Verifies the fix didn't regress the sudo-style case (which is what
# every other test in this file implicitly runs in, since the test harness runs
# as root). Explicit check here for completeness.
# Requires running as root (uses chown root:root to set up the root-only fixture).
if [ "$(id -u)" = "0" ]; then
  setup_fixture
  mk_user u 1000 "$TESTDIR/home/u"
  echo "password=sudoStyleSecret" > "$TESTDIR/etc/root-only-sudo.conf"
  chown root:root "$TESTDIR/etc/root-only-sudo.conf"
  chmod 600 "$TESTDIR/etc/root-only-sudo.conf"
  SUDO_OUT=$("$TESTDIR/config_enum.sh")
  assert_contains "$SUDO_OUT" "sudoStyleSecret" "T59: sudo-style (RUID=EUID=0) finds root-only file"
  teardown_fixture
else
  echo "SKIP: T59 (requires running as root — try: sudo ./config_enum_tests.sh)"
fi

# ============================================================================
# Fix A: .ovpn enumeration across all four tree-classes
# ============================================================================

# T60: .ovpn at /etc enumerated (Tree-class 1)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
cat > "$TESTDIR/etc/sample.ovpn" <<EOF
client
auth-user-pass /etc/openvpn/etcOvpnEnum.txt
EOF
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "$TESTDIR/etc/sample.ovpn" "T60: /etc .ovpn enumerated"
teardown_fixture

# T61: .ovpn at user home enumerated (Tree-class 2)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
cat > "$TESTDIR/home/u/myvpn.ovpn" <<EOF
client
auth-user-pass /etc/openvpn/homeOvpnEnum.txt
EOF
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "$TESTDIR/home/u/myvpn.ovpn" "T61: home .ovpn enumerated"
teardown_fixture

# T62: .ovpn at /var/www enumerated (Tree-class 3a)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/var/www/html"
cat > "$TESTDIR/var/www/html/client.ovpn" <<EOF
client
auth-user-pass /etc/openvpn/wwwOvpnEnum.txt
EOF
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "$TESTDIR/var/www/html/client.ovpn" "T62: /var/www .ovpn enumerated"
teardown_fixture

# T63: .ovpn at /opt enumerated (Tree-class 3b)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/opt/vpnconfigs"
cat > "$TESTDIR/opt/vpnconfigs/client.ovpn" <<EOF
client
auth-user-pass /etc/openvpn/optOvpnEnum.txt
EOF
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "$TESTDIR/opt/vpnconfigs/client.ovpn" "T63: /opt .ovpn enumerated"
teardown_fixture

# ============================================================================
# Fix B: OVPN_PATTERN directive coverage
# ============================================================================

# T64: auth-user-pass directive matches (positive — primary OpenVPN credential pointer)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "auth-user-pass /etc/openvpn/T64auth.txt" > "$TESTDIR/home/u/t64.ovpn"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "auth-user-pass /etc/openvpn/T64auth.txt" "T64: auth-user-pass matched"
teardown_fixture

# T65: key directive matches (positive — private key file pointer)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "key client.key" > "$TESTDIR/home/u/t65.ovpn"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "key client.key" "T65: key directive matched"
teardown_fixture

# T66: secret, tls-auth, tls-crypt, tls-crypt-v2, pkcs12 all match
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
cat > "$TESTDIR/home/u/t66.ovpn" <<EOF
secret /etc/openvpn/static.key
tls-auth ta.key 1
tls-crypt tlscrypt.key
tls-crypt-v2 tlscryptv2.key
pkcs12 client.p12
EOF
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "secret /etc/openvpn/static.key" "T66a: secret matched"
assert_contains "$OUT" "tls-auth ta.key 1" "T66b: tls-auth matched"
assert_contains "$OUT" "tls-crypt tlscrypt.key" "T66c: tls-crypt matched"
assert_contains "$OUT" "tls-crypt-v2 tlscryptv2.key" "T66d: tls-crypt-v2 matched"
assert_contains "$OUT" "pkcs12 client.p12" "T66e: pkcs12 matched"
teardown_fixture

# T67: ca directive does NOT match (public CA cert, not credential)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "ca ca.crt" > "$TESTDIR/home/u/t67.ovpn"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_CRED" "T67: ca directive NOT matched (public cert)"
teardown_fixture

# T68: cert directive does NOT match (public client cert, not credential)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "cert client.crt" > "$TESTDIR/home/u/t68.ovpn"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_CRED" "T68: cert directive NOT matched (public cert)"
teardown_fixture

# T69: crl-verify does NOT match (revocation list, not credential)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "crl-verify crl.pem" > "$TESTDIR/home/u/t69.ovpn"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_CRED" "T69: crl-verify NOT matched"
teardown_fixture

# T70: dev/verb/keyboard do NOT match (non-credential directives)
# keyboard is the critical case — substring "key" inside keyboard must not match
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
cat > "$TESTDIR/home/u/t70.ovpn" <<EOF
dev tun
verb 3
keyboard layout
EOF
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_CRED" "T70: dev/verb/keyboard NOT matched"
teardown_fixture

# T71: indented directive matches (OpenVPN spec permits leading whitespace)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "    key indented.key" > "$TESTDIR/home/u/t71.ovpn"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "key indented.key" "T71: indented directive matched"
teardown_fixture

# T72: commented directive matches (consistent with T31 — commented creds still flagged)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "# auth-user-pass /etc/openvpn/oldauth.txt" > "$TESTDIR/home/u/t72.ovpn"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "# auth-user-pass /etc/openvpn/oldauth.txt" "T72: commented directive matched"
teardown_fixture

# ============================================================================
# Fix C: Infrastructure config path exclusion
# ============================================================================

# T73: /etc/nsswitch.conf with passwd: directive does NOT emit CONFIG_CRED
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
cat > "$TESTDIR/etc/nsswitch.conf" <<EOF
passwd:         compat
group:          compat
shadow:         compat
EOF
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_CRED[$TESTDIR/etc/nsswitch.conf]" "T73: nsswitch.conf excluded"
teardown_fixture

# T74: /etc/pam.d/* directory excluded
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/etc/pam.d"
cat > "$TESTDIR/etc/pam.d/common-auth" <<EOF
auth required pam_unix.so try_first_pass
EOF
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_CRED[$TESTDIR/etc/pam.d/common-auth]" "T74: pam.d/* excluded"
teardown_fixture

# T75: /etc/services excluded (no .conf extension but no longer enumerated regardless)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "ssh 22/tcp" > "$TESTDIR/etc/services"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_FOUND: $TESTDIR/etc/services" "T75: services excluded"
teardown_fixture

# T76: /etc/protocols excluded
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "tcp 6 TCP" > "$TESTDIR/etc/protocols"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_FOUND: $TESTDIR/etc/protocols" "T76: protocols excluded"
teardown_fixture

# T77: /etc/hosts.allow and /etc/hosts.deny excluded
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "sshd: 10.0.0.0/8" > "$TESTDIR/etc/hosts.allow"
echo "ALL: ALL" > "$TESTDIR/etc/hosts.deny"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_FOUND: $TESTDIR/etc/hosts.allow" "T77a: hosts.allow excluded"
assert_not_contains "$OUT" "CONFIG_FOUND: $TESTDIR/etc/hosts.deny" "T77b: hosts.deny excluded"
teardown_fixture

# T78: /etc/ld.so.conf and /etc/ld.so.conf.d/* excluded
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/etc/ld.so.conf.d"
echo "include /etc/ld.so.conf.d/*.conf" > "$TESTDIR/etc/ld.so.conf"
echo "/usr/local/lib/x86_64-linux-gnu" > "$TESTDIR/etc/ld.so.conf.d/x86_64.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "$TESTDIR/etc/ld.so.conf" "T78a: ld.so.conf excluded"
assert_not_contains "$OUT" "$TESTDIR/etc/ld.so.conf.d" "T78b: ld.so.conf.d excluded"
teardown_fixture

# T79: custom file outside /etc/ with same name IS scanned (exclusion is /etc/-prefixed only)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/opt/myapp"
echo '{"password": "customAppOutsideEtc"}' > "$TESTDIR/opt/myapp/nsswitch.json"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "customAppOutsideEtc" "T79: custom path with infra-name still scanned"
teardown_fixture

# ============================================================================
# Fix D: Anchored INI/YAML pattern + XML attribute alternation + SH_VAR_PATTERN
# ============================================================================

# T80: exim-style template line (FP target) — no CONFIG_CRED
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
cat > "$TESTDIR/etc/exim.conf" <<'EOF'
acl_smtp_auth = acl_check_auth
#  server_prompts             = <| Username: | Password:
EOF
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "CONFIG_CRED" "T80: exim-style template line NOT matched"
teardown_fixture

# T81: known false-negative — multi-statement mid-line in non-.sh config file.
# Documented limitation: anchored INI/YAML deliberately drops the second assignment.
# This test pins the documented behavior (so any future change is explicit, not silent).
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "setting=foo; password=multiStatementValue" > "$TESTDIR/etc/app.conf"
OUT=$("$TESTDIR/config_enum.sh")
assert_not_contains "$OUT" "multiStatementValue" "T81: multi-statement second-assignment NOT matched (known FN)"
teardown_fixture

# T82: dot-namespaced key still matches (preserves T16 behavior under anchoring)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "spring.security.user.password=anchoredDotNs" > "$TESTDIR/etc/app.properties"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "anchoredDotNs" "T82: dot-namespaced key matched after anchoring"
teardown_fixture

# T83: XML attribute still matches (anchored INI doesn't catch mid-line, but XML-attr alternation does)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo '<datasource user="admin" password="xmlAttrAfterAnchor" />' > "$TESTDIR/etc/ds.xml"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "xmlAttrAfterAnchor" "T83: XML attribute matched after anchoring"
teardown_fixture

# T84: commented credential still matches (preserves T31 under anchoring)
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
echo "; password = commentedAfterAnchor" > "$TESTDIR/etc/app.ini"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "commentedAfterAnchor" "T84: commented (; style) still matched"
teardown_fixture

# T85: shell `export DB_PASS=secret` in .sh — caught via SH_VAR_PATTERN
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/var/www/html"
echo "export DB_PASS=shellExportSecret" > "$TESTDIR/var/www/html/setup.sh"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "shellExportSecret" "T85: shell export DB_PASS= matched via SH_VAR_PATTERN"
teardown_fixture

# T86: shell `let password=foo` in .sh — caught via SH_VAR_PATTERN
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/var/www/html"
echo "let password=shellLetSecret" > "$TESTDIR/var/www/html/init.sh"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "shellLetSecret" "T86: shell let password= matched via SH_VAR_PATTERN"
teardown_fixture

# T87: shell multi-statement (`set_x; password=foo`) in .sh — caught via SH_VAR_PATTERN
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/var/www/html"
echo "set -x; password=shellMultiStmtSecret" > "$TESTDIR/var/www/html/deploy.sh"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "shellMultiStmtSecret" "T87: shell multi-statement matched via SH_VAR_PATTERN"
teardown_fixture

# T88: shell `declare -x SECRET=foo` in .sh — caught via SH_VAR_PATTERN
setup_fixture
mk_user u 1000 "$TESTDIR/home/u"
mkdir -p "$TESTDIR/var/www/html"
echo "declare -x SECRET=shellDeclareSecret" > "$TESTDIR/var/www/html/env.sh"
OUT=$("$TESTDIR/config_enum.sh")
assert_contains "$OUT" "shellDeclareSecret" "T88: shell declare -x SECRET= matched via SH_VAR_PATTERN"
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
