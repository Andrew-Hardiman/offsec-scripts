#!/bin/bash
# loose_creds_triage_tests.sh — Regression tests for loose_creds_triage.sh
#
# Sources the script to define `triage` in this test shell, then calls
# `triage <file>` per test with a hermetic /var/tmp/lct.XXXXXX fixture.
#
# Run: ./loose_creds_triage_tests.sh
# Exit code: 0 if all pass, non-zero count = failures.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_SCRIPT="$SCRIPT_DIR/loose_creds_triage.sh"

if [ ! -f "$TARGET_SCRIPT" ]; then
  echo "ERROR: cannot find loose_creds_triage.sh at $TARGET_SCRIPT"
  exit 1
fi

# Source the function into this shell so we can call triage <file>
. "$TARGET_SCRIPT"

PASS=0
FAIL=0
SKIP=0

setup_fixture() {
  TESTDIR=$(mktemp -d /var/tmp/lct.XXXXXX)
}
teardown_fixture() {
  chmod -R u+rw "$TESTDIR" 2>/dev/null
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

assert_silent() {
  local output="$1" name="$2"
  if [ -z "$output" ]; then
    echo "PASS: $name"
    PASS=$((PASS+1))
  else
    echo "FAIL: $name"
    echo "  Expected silence (no output), got:"
    echo "$output" | sed 's/^/    /'
    FAIL=$((FAIL+1))
  fi
}

assert_exit() {
  local actual="$1" expected="$2" name="$3"
  if [ "$actual" = "$expected" ]; then
    echo "PASS: $name"
    PASS=$((PASS+1))
  else
    echo "FAIL: $name (exit=$actual expected $expected)"
    FAIL=$((FAIL+1))
  fi
}

# ============================================================================
# PEM detector
# ============================================================================

# T1: RSA private key
setup_fixture
echo "-----BEGIN RSA PRIVATE KEY-----" > "$TESTDIR/rsa.pem"
OUT=$(triage "$TESTDIR/rsa.pem")
assert_contains "$OUT" "LOOSE_CRED_PEM[$TESTDIR/rsa.pem]:" "T1: PEM RSA detected"
teardown_fixture

# T2: OpenSSH
setup_fixture
echo "-----BEGIN OPENSSH PRIVATE KEY-----" > "$TESTDIR/id.pem"
OUT=$(triage "$TESTDIR/id.pem")
assert_contains "$OUT" "LOOSE_CRED_PEM" "T2: PEM OpenSSH detected"
teardown_fixture

# T3: EC
setup_fixture
echo "-----BEGIN EC PRIVATE KEY-----" > "$TESTDIR/ec.pem"
OUT=$(triage "$TESTDIR/ec.pem")
assert_contains "$OUT" "LOOSE_CRED_PEM" "T3: PEM EC detected"
teardown_fixture

# T4: DSA
setup_fixture
echo "-----BEGIN DSA PRIVATE KEY-----" > "$TESTDIR/dsa.pem"
OUT=$(triage "$TESTDIR/dsa.pem")
assert_contains "$OUT" "LOOSE_CRED_PEM" "T4: PEM DSA detected"
teardown_fixture

# T5: PKCS#8 no-algo (BEGIN PRIVATE KEY without algo prefix)
setup_fixture
echo "-----BEGIN PRIVATE KEY-----" > "$TESTDIR/pk8.pem"
OUT=$(triage "$TESTDIR/pk8.pem")
assert_contains "$OUT" "LOOSE_CRED_PEM" "T5: PEM PKCS#8 no-algo detected"
teardown_fixture

# T6: ENCRYPTED
setup_fixture
echo "-----BEGIN ENCRYPTED PRIVATE KEY-----" > "$TESTDIR/enc.pem"
OUT=$(triage "$TESTDIR/enc.pem")
assert_contains "$OUT" "LOOSE_CRED_PEM" "T6: PEM ENCRYPTED detected"
teardown_fixture

# T7 (neg): CERTIFICATE not detected
setup_fixture
echo "-----BEGIN CERTIFICATE-----" > "$TESTDIR/ca.pem"
OUT=$(triage "$TESTDIR/ca.pem")
assert_not_contains "$OUT" "LOOSE_CRED_PEM" "T7: CERTIFICATE NOT detected as PEM"
teardown_fixture

# T8 (neg): PUBLIC KEY not detected
setup_fixture
echo "-----BEGIN PUBLIC KEY-----" > "$TESTDIR/pub.pem"
OUT=$(triage "$TESTDIR/pub.pem")
assert_not_contains "$OUT" "LOOSE_CRED_PEM" "T8: PUBLIC KEY NOT detected as PEM"
teardown_fixture

# ============================================================================
# HASH detector
# ============================================================================

# T9-T16: hash prefix families
setup_fixture; echo 'root:$6$saltvalue$hashvalue' > "$TESTDIR/h.dump"
OUT=$(triage "$TESTDIR/h.dump")
assert_contains "$OUT" "LOOSE_CRED_HASH" "T9: user:\$6\$ SHA-512 detected"
teardown_fixture

setup_fixture; echo 'admin:$5$salt$hash' > "$TESTDIR/h.dump"
OUT=$(triage "$TESTDIR/h.dump")
assert_contains "$OUT" "LOOSE_CRED_HASH" "T10: user:\$5\$ SHA-256 detected"
teardown_fixture

setup_fixture; echo 'user:$1$salt$hash' > "$TESTDIR/h.dump"
OUT=$(triage "$TESTDIR/h.dump")
assert_contains "$OUT" "LOOSE_CRED_HASH" "T11: user:\$1\$ MD5 detected"
teardown_fixture

setup_fixture; echo 'admin:$2y$10$saltandhash' > "$TESTDIR/h.dump"
OUT=$(triage "$TESTDIR/h.dump")
assert_contains "$OUT" "LOOSE_CRED_HASH" "T12: user:\$2y\$ bcrypt detected"
teardown_fixture

setup_fixture; echo 'webmaster:$apr1$salt$hash' > "$TESTDIR/h.dump"
OUT=$(triage "$TESTDIR/h.dump")
assert_contains "$OUT" "LOOSE_CRED_HASH" "T13: user:\$apr1\$ Apache MD5 detected"
teardown_fixture

setup_fixture; echo 'root:$argon2id$v=19$m=1024$saltvalue$hashvalue' > "$TESTDIR/h.dump"
OUT=$(triage "$TESTDIR/h.dump")
assert_contains "$OUT" "LOOSE_CRED_HASH" "T14: user:\$argon2id\$ detected"
teardown_fixture

setup_fixture; echo 'user:{SHA}abcdef' > "$TESTDIR/h.dump"
OUT=$(triage "$TESTDIR/h.dump")
assert_contains "$OUT" "LOOSE_CRED_HASH" "T15: user:{SHA} LDAP detected"
teardown_fixture

setup_fixture; echo 'user:{SSHA}saltedhash' > "$TESTDIR/h.dump"
OUT=$(triage "$TESTDIR/h.dump")
assert_contains "$OUT" "LOOSE_CRED_HASH" "T16: user:{SSHA} LDAP detected"
teardown_fixture

# T17-T18: bare hashes (no user)
setup_fixture; echo '$6$saltvalue$hashvalue' > "$TESTDIR/h.dump"
OUT=$(triage "$TESTDIR/h.dump")
assert_contains "$OUT" "LOOSE_CRED_HASH" "T17: bare \$6\$ hash (no user) detected"
teardown_fixture

setup_fixture; echo '{SHA}bareldaphash' > "$TESTDIR/h.dump"
OUT=$(triage "$TESTDIR/h.dump")
assert_contains "$OUT" "LOOSE_CRED_HASH" "T18: bare {SHA} hash (no user) detected"
teardown_fixture

# T19 (neg): plain not HASH
setup_fixture; echo 'root:hunter2' > "$TESTDIR/p.dump"
OUT=$(triage "$TESTDIR/p.dump")
assert_not_contains "$OUT" "LOOSE_CRED_HASH" "T19: plain user:password NOT detected as HASH"
teardown_fixture

# T20 (neg): raw hex not HASH (accepted FN — UUID/git-SHA collision avoidance)
setup_fixture; echo 'aabbccddeeff11223344556677889900aabbccddeeff112233445566778899' > "$TESTDIR/hex.dump"
OUT=$(triage "$TESTDIR/hex.dump")
assert_not_contains "$OUT" "LOOSE_CRED_HASH" "T20: raw hex NOT detected (accepted FN)"
teardown_fixture

# ============================================================================
# URL detector
# ============================================================================

setup_fixture; echo 'connection = https://alice:s3cret@example.com/api' > "$TESTDIR/u.txt"
OUT=$(triage "$TESTDIR/u.txt")
assert_contains "$OUT" "LOOSE_CRED_URL" "T21: https://user:pass@ detected"
teardown_fixture

setup_fixture; echo 'DATABASE_URL=mysql://root:hunter2@localhost/mydb' > "$TESTDIR/u.txt"
OUT=$(triage "$TESTDIR/u.txt")
assert_contains "$OUT" "LOOSE_CRED_URL" "T22: mysql://user:pass@ detected"
teardown_fixture

setup_fixture; echo 'uri = mongodb+srv://admin:mypass@cluster.mongodb.net' > "$TESTDIR/u.txt"
OUT=$(triage "$TESTDIR/u.txt")
assert_contains "$OUT" "LOOSE_CRED_URL" "T23: mongodb+srv://user:pass@ detected"
teardown_fixture

setup_fixture; echo 'https://example.com/no-auth' > "$TESTDIR/u.txt"
OUT=$(triage "$TESTDIR/u.txt")
assert_not_contains "$OUT" "LOOSE_CRED_URL" "T24: URL without user:pass NOT detected"
teardown_fixture

setup_fixture; echo 'ssh://alice@example.com' > "$TESTDIR/u.txt"
OUT=$(triage "$TESTDIR/u.txt")
assert_not_contains "$OUT" "LOOSE_CRED_URL" "T25: URL user-only-no-pass NOT detected"
teardown_fixture

# ============================================================================
# KV detector (inline + env-shape branches merged)
# ============================================================================

setup_fixture; echo 'export DB_PASSWORD=mysecret' > "$TESTDIR/e.sh"
OUT=$(triage "$TESTDIR/e.sh")
assert_contains "$OUT" "LOOSE_CRED_KV" "T26: export DB_PASSWORD (env-shape branch)"
teardown_fixture

setup_fixture; echo 'API_KEY=abcd1234' > "$TESTDIR/e.env"
OUT=$(triage "$TESTDIR/e.env")
assert_contains "$OUT" "LOOSE_CRED_KV" "T27: bare API_KEY (env-shape, 0-prefix)"
teardown_fixture

setup_fixture; echo 'export SECRET_TOKEN=xxx' > "$TESTDIR/e.sh"
OUT=$(triage "$TESTDIR/e.sh")
assert_contains "$OUT" "LOOSE_CRED_KV" "T28: SECRET_TOKEN (env-shape)"
teardown_fixture

setup_fixture; echo 'API-KEY=zzz' > "$TESTDIR/e.env"
OUT=$(triage "$TESTDIR/e.env")
assert_contains "$OUT" "LOOSE_CRED_KV" "T29: dash-form API-KEY (env-shape)"
teardown_fixture

setup_fixture; echo 'export PATH=/usr/local/bin' > "$TESTDIR/e.sh"
OUT=$(triage "$TESTDIR/e.sh")
assert_not_contains "$OUT" "LOOSE_CRED_KV" "T30: export PATH NOT detected (no cred kw)"
teardown_fixture

setup_fixture; echo 'MY_VAR=value' > "$TESTDIR/e.env"
OUT=$(triage "$TESTDIR/e.env")
assert_not_contains "$OUT" "LOOSE_CRED_KV" "T31: MY_VAR (no cred kw) NOT detected"
teardown_fixture

setup_fixture; echo 'password = mysecret' > "$TESTDIR/k.ini"
OUT=$(triage "$TESTDIR/k.ini")
assert_contains "$OUT" "LOOSE_CRED_KV" "T32: password = value (inline KV)"
teardown_fixture

setup_fixture; echo 'password: mysecret' > "$TESTDIR/k.yml"
OUT=$(triage "$TESTDIR/k.yml")
assert_contains "$OUT" "LOOSE_CRED_KV" "T33: password: value YAML (inline KV)"
teardown_fixture

setup_fixture; echo 'db_secret=xxx' > "$TESTDIR/k.cfg"
OUT=$(triage "$TESTDIR/k.cfg")
assert_contains "$OUT" "LOOSE_CRED_KV" "T34: db_secret=value (inline KV)"
teardown_fixture

setup_fixture; echo 'api_key = zzz' > "$TESTDIR/k.cfg"
OUT=$(triage "$TESTDIR/k.cfg")
assert_contains "$OUT" "LOOSE_CRED_KV" "T35: api_key = value (inline KV)"
teardown_fixture

setup_fixture; echo 'password_field = userPassword' > "$TESTDIR/k.cfg"
OUT=$(triage "$TESTDIR/k.cfg")
assert_not_contains "$OUT" "LOOSE_CRED_KV" "T36: password_field NOT detected (bounded)"
teardown_fixture

setup_fixture; echo 'user = alice' > "$TESTDIR/k.cfg"
OUT=$(triage "$TESTDIR/k.cfg")
assert_not_contains "$OUT" "LOOSE_CRED_KV" "T37: user = alice NOT detected (no kw)"
teardown_fixture

# ============================================================================
# USERPASS detector
# ============================================================================

setup_fixture; echo 'root:PDLrCVl1pLD91U0JMmCz' > "$TESTDIR/gpi.txt"
OUT=$(triage "$TESTDIR/gpi.txt")
assert_contains "$OUT" "LOOSE_CRED_USERPASS[$TESTDIR/gpi.txt]: 1:root:PDLrCVl1pLD91U0JMmCz" \
    "T38: GPI canonical case detected as USERPASS"
teardown_fixture

setup_fixture; echo 'admin:hunter2' > "$TESTDIR/c.txt"
OUT=$(triage "$TESTDIR/c.txt")
assert_contains "$OUT" "LOOSE_CRED_USERPASS" "T39: admin:hunter2 detected"
teardown_fixture

setup_fixture; echo 'root:x:0:0:root:/root:/bin/bash' > "$TESTDIR/pw.txt"
OUT=$(triage "$TESTDIR/pw.txt")
assert_not_contains "$OUT" "LOOSE_CRED_USERPASS" "T40: passwd-format line SUPPRESSED from USERPASS (passwd-format filter)"
teardown_fixture

setup_fixture; echo 'root:$6$salt$hash' > "$TESTDIR/h.txt"
OUT=$(triage "$TESTDIR/h.txt")
assert_contains "$OUT" "LOOSE_CRED_HASH" "T41a: root:\$6\$... IS HASH"
assert_not_contains "$OUT" "LOOSE_CRED_USERPASS" "T41b: root:\$6\$... NOT USERPASS (dedup)"
teardown_fixture

setup_fixture; echo 'user:{SHA}abc' > "$TESTDIR/l.txt"
OUT=$(triage "$TESTDIR/l.txt")
assert_not_contains "$OUT" "LOOSE_CRED_USERPASS" "T42: user:{SHA} NOT USERPASS (HASH wins)"
teardown_fixture

setup_fixture; echo '  yaml_key: value' > "$TESTDIR/y.txt"
OUT=$(triage "$TESTDIR/y.txt")
assert_not_contains "$OUT" "LOOSE_CRED_USERPASS" "T43: indented YAML NOT USERPASS"
teardown_fixture

# ============================================================================
# Priority / dedup
# ============================================================================

setup_fixture; echo 'password:$6$salt$hash' > "$TESTDIR/p.txt"
OUT=$(triage "$TESTDIR/p.txt")
assert_contains "$OUT" "LOOSE_CRED_HASH" "T44a: HASH marker present"
assert_not_contains "$OUT" "LOOSE_CRED_KV" "T44b: KV NOT present (dedup)"
assert_not_contains "$OUT" "LOOSE_CRED_USERPASS" "T44c: USERPASS NOT present (dedup)"
teardown_fixture

setup_fixture; echo 'password:mysecret' > "$TESTDIR/p.txt"
OUT=$(triage "$TESTDIR/p.txt")
assert_contains "$OUT" "LOOSE_CRED_KV" "T45a: KV marker present"
assert_not_contains "$OUT" "LOOSE_CRED_USERPASS" "T45b: USERPASS NOT present (dedup)"
teardown_fixture

setup_fixture
cat > "$TESTDIR/m.txt" <<EOF
root:PDLrCVl1pLD91U0JMmCz
admin:hunter2
alice:foobar
EOF
OUT=$(triage "$TESTDIR/m.txt")
assert_contains "$OUT" "1:root:PDL" "T46a: line 1 emitted"
assert_contains "$OUT" "2:admin:hunter2" "T46b: line 2 emitted"
assert_contains "$OUT" "3:alice:foobar" "T46c: line 3 emitted"
teardown_fixture

# ============================================================================
# Arg validation
# ============================================================================

# T47: no arg → usage to stderr, exit 1
OUT=$(triage 2>&1 >/dev/null)  # capture stderr only
RC=$?
assert_contains "$OUT" "usage: triage <file>" "T47a: no-arg emits usage to stderr"
assert_exit "$RC" "1" "T47b: no-arg exits 1"

# T48: nonexistent file → error to stderr, exit 1
OUT=$(triage /nope/does/not/exist 2>&1 >/dev/null)
RC=$?
assert_contains "$OUT" "not found" "T48a: nonexistent emits 'not found' to stderr"
assert_exit "$RC" "1" "T48b: nonexistent exits 1"

# T49: directory path → error, exit 1
setup_fixture
OUT=$(triage "$TESTDIR" 2>&1 >/dev/null)
RC=$?
assert_contains "$OUT" "not a regular file" "T49a: directory emits 'not a regular file' to stderr"
assert_exit "$RC" "1" "T49b: directory exits 1"
teardown_fixture

# T50: unreadable file (mode 000) — skip when running as root (chmod bypassed)
if [ "$(id -u)" != "0" ]; then
    setup_fixture
    echo 'root:x' > "$TESTDIR/locked.txt"
    chmod 000 "$TESTDIR/locked.txt"
    OUT=$(triage "$TESTDIR/locked.txt" 2>&1 >/dev/null)
    RC=$?
    assert_contains "$OUT" "not readable" "T50a: unreadable emits 'not readable' to stderr"
    assert_exit "$RC" "1" "T50b: unreadable exits 1"
    teardown_fixture
else
    echo "SKIP: T50a: unreadable emits 'not readable' (requires non-root — chmod 000 bypassed by root)"
    echo "SKIP: T50b: unreadable exits 1 (requires non-root)"
    SKIP=$((SKIP+2))
fi

# T51: valid file emits exit 0 (regardless of whether markers fire)
setup_fixture
echo 'just some prose' > "$TESTDIR/prose.txt"
triage "$TESTDIR/prose.txt" >/dev/null 2>&1
RC=$?
assert_exit "$RC" "0" "T51: valid file exits 0 even with no markers"
teardown_fixture

# ============================================================================
# Binary file handling
# ============================================================================

# T52: ELF binary skipped via grep -I even if magic bytes contain matching text
setup_fixture
printf '\x7fELF\x02\x01\x01\x00\nroot:hunter2\n' > "$TESTDIR/fake.o"
OUT=$(triage "$TESTDIR/fake.o")
assert_silent "$OUT" "T52: ELF binary skipped (grep -I)"
teardown_fixture

# ============================================================================
# Output format
# ============================================================================

# T53: exact marker format
setup_fixture
echo 'root:PDLrCVl1pLD91U0JMmCz' > "$TESTDIR/fmt.txt"
OUT=$(triage "$TESTDIR/fmt.txt")
EXPECTED="LOOSE_CRED_USERPASS[$TESTDIR/fmt.txt]: 1:root:PDLrCVl1pLD91U0JMmCz"
if [ "$OUT" = "$EXPECTED" ]; then
    echo "PASS: T53: exact marker format"
    PASS=$((PASS+1))
else
    echo "FAIL: T53: exact marker format"
    echo "  Expected: [$EXPECTED]"
    echo "  Got:      [$OUT]"
    FAIL=$((FAIL+1))
fi
teardown_fixture

# ============================================================================
# End-to-end: reproduce GPI target file set — 14 FPs + 1 real, one-file-per-call
# ============================================================================

# T54: iterate the GPI 15-file set; verify real hit surfaces, FPs where recognizable
setup_fixture
mkdir -p "$TESTDIR/etc/pki/fwupd" "$TESTDIR/etc/pki/fwupd-metadata" "$TESTDIR/etc/pollinate" \
         "$TESTDIR/etc/systemd" "$TESTDIR/opt/app/doc" "$TESTDIR/opt/app/include" \
         "$TESTDIR/opt/app/src/modules"
echo 'root:PDLrCVl1pLD91U0JMmCz' > "$TESTDIR/etc/password.txt"
echo 'root:x:0:0:root:/root:/bin/bash' > "$TESTDIR/etc/passwd.org"
echo '-----BEGIN CERTIFICATE-----' > "$TESTDIR/etc/pki/fwupd/LVFS-CA.pem"
echo '-----BEGIN CERTIFICATE-----' > "$TESTDIR/etc/pki/fwupd-metadata/LVFS-CA.pem"
echo '-----BEGIN CERTIFICATE-----' > "$TESTDIR/etc/pollinate/entropy.ubuntu.com.pem"
echo 'PASS_MAX_DAYS 99999' > "$TESTDIR/etc/login.defs"
echo '#KillUserProcesses=no' > "$TESTDIR/etc/systemd/logind.conf"
echo 'The token protocol described here...' > "$TESTDIR/opt/app/doc/token.txt"
echo 'unsigned int hash_string(const char *str);' > "$TESTDIR/opt/app/include/hash.h"
echo 'unsigned int hash_string(const char *str) { return 0; }' > "$TESTDIR/opt/app/src/hash.c"
printf '\x7fELF\x02\x01\x01\x00' > "$TESTDIR/opt/app/src/hash.o"
printf '\x7fELF\x02\x01\x01\x00' > "$TESTDIR/opt/app/src/modules/m_mkpasswd.o"
printf '\x7fELF\x02\x01\x01\x00' > "$TESTDIR/opt/app/src/modules/m_mkpasswd.so"

# Real hit
OUT=$(triage "$TESTDIR/etc/password.txt")
assert_contains "$OUT" "LOOSE_CRED_USERPASS[$TESTDIR/etc/password.txt]: 1:root:PDLrCVl1pLD91U0JMmCz" \
    "T54a: real hit /etc/password.txt surfaces"

# passwd.org format now suppressed by passwd-format filter
OUT=$(triage "$TESTDIR/etc/passwd.org")
assert_silent "$OUT" "T54b: passwd.org silent (passwd-format filter suppresses USERPASS)"

# Public CA cert silent
OUT=$(triage "$TESTDIR/etc/pki/fwupd/LVFS-CA.pem")
assert_silent "$OUT" "T54c: LVFS-CA.pem (fwupd) silent"

OUT=$(triage "$TESTDIR/etc/pki/fwupd-metadata/LVFS-CA.pem")
assert_silent "$OUT" "T54d: LVFS-CA.pem (fwupd-metadata) silent"

OUT=$(triage "$TESTDIR/etc/pollinate/entropy.ubuntu.com.pem")
assert_silent "$OUT" "T54e: entropy.ubuntu.com.pem silent"

# System configs silent
OUT=$(triage "$TESTDIR/etc/login.defs")
assert_silent "$OUT" "T54f: login.defs silent"

OUT=$(triage "$TESTDIR/etc/systemd/logind.conf")
assert_silent "$OUT" "T54g: logind.conf silent"

# Prose doc silent
OUT=$(triage "$TESTDIR/opt/app/doc/token.txt")
assert_silent "$OUT" "T54h: token.txt (prose) silent"

# C source silent (no cred syntax in code)
OUT=$(triage "$TESTDIR/opt/app/include/hash.h")
assert_silent "$OUT" "T54i: hash.h silent"

OUT=$(triage "$TESTDIR/opt/app/src/hash.c")
assert_silent "$OUT" "T54j: hash.c silent"

# Binaries silent (grep -I)
OUT=$(triage "$TESTDIR/opt/app/src/hash.o")
assert_silent "$OUT" "T54k: hash.o (binary) silent"

OUT=$(triage "$TESTDIR/opt/app/src/modules/m_mkpasswd.o")
assert_silent "$OUT" "T54l: m_mkpasswd.o (binary) silent"

OUT=$(triage "$TESTDIR/opt/app/src/modules/m_mkpasswd.so")
assert_silent "$OUT" "T54m: m_mkpasswd.so (binary) silent"

teardown_fixture

# ============================================================================
# Passwd-format filter — USERPASS-specific pre-filter suppressing
# `name:x:UID:GID:...` lines that would otherwise carpet-bomb output when
# an enum surfaced /etc/passwd.org / passwd.bak / etc.
# ============================================================================

# T55: full 35-line passwd fixture (real /etc/passwd content from GPI target) → silent
setup_fixture
cat > "$TESTDIR/passwd.org" <<EOF
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
EOF
OUT=$(triage "$TESTDIR/passwd.org")
assert_silent "$OUT" "T55: full passwd-format file silent (0 markers, was 35 lines before filter)"
teardown_fixture

# T56: mixed passwd-format + real cred → only real cred emits, passwd lines suppressed
setup_fixture
cat > "$TESTDIR/mixed.txt" <<EOF
root:x:0:0:root:/root:/bin/bash
admin:hunter2
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
EOF
OUT=$(triage "$TESTDIR/mixed.txt")
assert_contains "$OUT" "2:admin:hunter2" "T56a: real cred on line 2 still emits"
assert_not_contains "$OUT" "1:root:x" "T56b: passwd-format line 1 suppressed"
assert_not_contains "$OUT" "3:daemon:x" "T56c: passwd-format line 3 suppressed"
teardown_fixture

# T57: shadow with real hash — HASH still fires (higher priority than USERPASS,
# so passwd-format filter never gets a chance to run on this line)
setup_fixture
echo 'root:$6$salt$hashvalue:18000:0:99999:7:::' > "$TESTDIR/shadow.dump"
OUT=$(triage "$TESTDIR/shadow.dump")
assert_contains "$OUT" "LOOSE_CRED_HASH" "T57: shadow-format with real hash still emits HASH"
teardown_fixture

# T58: shadow-format with disabled placeholder (`!`/`*`/empty) — silent
# (USERPASS would fire without filter; filter catches `word:!:digits:digits:` shape)
setup_fixture; echo 'root:!:18000:0:99999:7:::' > "$TESTDIR/s.dump"
OUT=$(triage "$TESTDIR/s.dump")
assert_silent "$OUT" "T58a: shadow-format `root:!:...` silent (disabled account placeholder)"
teardown_fixture
setup_fixture; echo 'root:*:18000:0:99999:7:::' > "$TESTDIR/s.dump"
OUT=$(triage "$TESTDIR/s.dump")
assert_silent "$OUT" "T58b: shadow-format `root:*:...` silent (no-password-set placeholder)"
teardown_fixture
setup_fixture; echo 'root::18000:0:99999:7:::' > "$TESTDIR/s.dump"
OUT=$(triage "$TESTDIR/s.dump")
assert_silent "$OUT" "T58c: shadow-format `root::...` silent (empty password field)"
teardown_fixture

# T59: quirky cred with numeric middle field — still emits (filter requires TWO
# consecutive digit fields, `admin:secretpw:12345:extra_data` has only one)
setup_fixture; echo 'admin:secretpw:12345:extra_data' > "$TESTDIR/q.txt"
OUT=$(triage "$TESTDIR/q.txt")
assert_contains "$OUT" "LOOSE_CRED_USERPASS" \
    "T59: 3-field cred with single numeric field still emits (not passwd shape)"
teardown_fixture

# T60: legitimate `user:password` (single colon) still emits — baseline sanity
setup_fixture; echo 'root:PDLrCVl1pLD91U0JMmCz' > "$TESTDIR/legit.txt"
OUT=$(triage "$TESTDIR/legit.txt")
assert_contains "$OUT" "LOOSE_CRED_USERPASS" "T60: legit user:password (1 colon) still emits"
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
