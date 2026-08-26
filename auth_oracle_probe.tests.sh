#!/bin/bash
# auth_oracle_probe.tests.sh - Regression tests for auth_oracle_probe.sh
#
# Three test categories:
#   1. Unit tests (source main script, call helper functions with fixture
#      files/args, assert results). Fast, no network.
#   2. Integration tests (spin up ephemeral Python HTTP server with hand-crafted
#      endpoints for each app class, run main script against it, assert markers
#      in output AND execute emitted oracles against known-good/known-wrong
#      creds to verify oracle discrimination correctness).
#   3. Argument validation.
#
# Usage:
#   auth_oracle_probe.tests.sh                                       # default path
#   auth_oracle_probe.tests.sh /path/to/auth_oracle_probe.sh         # explicit path
#
# Exit code: 0 = all pass; non-zero = number of failures.
#
# Maintenance: When a new edge case surfaces during validation on a real box,
# add a test case reproducing the issue, watch it fail, modify the script to
# handle it, watch it pass, re-run full suite.

set -u

SCRIPT="${1:-$HOME/scripts/auth_oracle_probe.sh}"
if [ ! -f "$SCRIPT" ]; then
    SCRIPT="$(dirname "$0")/auth_oracle_probe.sh"
fi
if [ ! -f "$SCRIPT" ]; then
    echo "ERROR: cannot find auth_oracle_probe.sh (tried \$1, \$HOME/scripts/, dirname \$0)" >&2
    exit 2
fi

echo "Testing: $SCRIPT"
echo

# ------------------------------------------------------------------------------
# Prerequisite detection
# ------------------------------------------------------------------------------

echo "Prerequisite detection:"

HAVE_PYTHON3=no
HAVE_CURL=no

if command -v python3 >/dev/null 2>&1; then HAVE_PYTHON3=yes; fi
if command -v curl >/dev/null 2>&1; then HAVE_CURL=yes; fi

if [ "$HAVE_PYTHON3" = "yes" ]; then
    printf "  python3: yes\n"
else
    printf "  python3: NO  — integration tests will skip (needed for mock HTTP server)\n"
fi

if [ "$HAVE_CURL" = "yes" ]; then
    printf "  curl:    yes\n"
else
    printf "  curl:    NO  — integration tests will skip (needed by script under test)\n"
fi

echo

# ------------------------------------------------------------------------------
# Counters + assertion helpers
# ------------------------------------------------------------------------------

PASS=0
FAIL=0
SKIP=0
declare -a FAILURES

_pass() {
    local id="$1"
    local desc="$2"
    PASS=$((PASS + 1))
    echo "PASS: $id: $desc"
}

_fail() {
    local id="$1"
    local desc="$2"
    local reason="$3"
    FAIL=$((FAIL + 1))
    FAILURES+=("$id: $desc | $reason")
    echo "FAIL: $id: $desc"
    echo "        $reason"
}

_skip() {
    local id="$1"
    local desc="$2"
    local reason="$3"
    SKIP=$((SKIP + 1))
    echo "SKIP: $id: $desc ($reason)"
}

assert_eq() {
    local id="$1"
    local desc="$2"
    local expected="$3"
    local actual="$4"
    if [ "$expected" = "$actual" ]; then
        _pass "$id" "$desc"
    else
        _fail "$id" "$desc" "expected='$expected' actual='$actual'"
    fi
}

assert_contains() {
    local id="$1"
    local desc="$2"
    local needle="$3"
    local haystack="$4"
    if printf '%s' "$haystack" | grep -qF -- "$needle"; then
        _pass "$id" "$desc"
    else
        _fail "$id" "$desc" "output did not contain '$needle'"
    fi
}

assert_not_contains() {
    local id="$1"
    local desc="$2"
    local unwanted="$3"
    local haystack="$4"
    if printf '%s' "$haystack" | grep -qF -- "$unwanted"; then
        _fail "$id" "$desc" "output contained UNWANTED '$unwanted'"
    else
        _pass "$id" "$desc"
    fi
}

# ------------------------------------------------------------------------------
# CATEGORY 1: Unit tests (helper functions)
# ------------------------------------------------------------------------------

# Required globals must be set before sourcing to satisfy set -u.
HOST="x"; PORT="1"; LOGIN_PATH="/"; FORM_ACTION="/"
USER_FIELD="u"; PASS_FIELD="p"; SCHEME="http"; DELAY_MS=0; VERBOSE=no
WORK_DIR=""; COOKIES_FILE=""

G_CLASS=""; G_FAIL_STATUS=""; G_FAIL_LOCATION=""
G_FAIL_CONTENT_TYPE=""; G_FAIL_SIZE=""; G_FAIL_WWW_AUTH=""; G_CONFIDENCE=""

# shellcheck disable=SC1090
source "$SCRIPT"

# --- extract_location_path (T1-T5) ---

assert_eq "T1" "extract_location_path: absolute URL → path" \
    "/dashboard" "$(extract_location_path "http://target.com/dashboard")"

assert_eq "T2" "extract_location_path: absolute URL with query → path (query stripped)" \
    "/login" "$(extract_location_path "http://target.com/login?error=invalid")"

assert_eq "T3" "extract_location_path: path only → path unchanged" \
    "/login" "$(extract_location_path "/login")"

assert_eq "T4" "extract_location_path: absolute URL with port → path" \
    "/admin" "$(extract_location_path "http://10.10.10.5:8080/admin")"

assert_eq "T5" "extract_location_path: path with query only → path" \
    "/login" "$(extract_location_path "/login?error=empty")"

# --- tokenize (T6-T9) ---

TMP_TOK=$(mktemp)
printf '<html><body>Hello<div class="err">Fail</div></body></html>' > "$TMP_TOK"
tokens=$(tokenize "$TMP_TOK")
assert_contains "T6" "tokenize: extracts inter-tag text ('Hello')" "Hello" "$tokens"
assert_contains "T7" "tokenize: extracts attributes ('div class=\"err\"')" 'div class="err"' "$tokens"
assert_contains "T8" "tokenize: extracts 'Fail'" "Fail" "$tokens"

printf '' > "$TMP_TOK"
empty_tok=$(tokenize "$TMP_TOK")
assert_eq "T9" "tokenize: empty body → empty output" "" "$empty_tok"
rm -f "$TMP_TOK"

# --- check_rate_limited (T10-T14) ---

WORK_DIR=$(mktemp -d)
COOKIES_FILE="$WORK_DIR/cookies.txt"

# Fixture: 429 response
printf 'status=429|size=17|redirect=|type=text/html\n' > "$WORK_DIR/rl_429.meta"
printf 'Too many requests\n' > "$WORK_DIR/rl_429.body"
printf 'HTTP/1.1 429 Too Many Requests\nRetry-After: 60\n\n' > "$WORK_DIR/rl_429.hdr"
if out=$(check_rate_limited rl_429); then
    assert_contains "T10" "check_rate_limited: 429 status detected" "RATE_LIMITED" "$out"
else
    _fail "T10" "check_rate_limited: 429 status detected" "returned non-zero unexpectedly"
fi

# Fixture: 200 status with rate-limit body pattern
printf 'status=200|size=42|redirect=|type=text/html\n' > "$WORK_DIR/rl_body.meta"
printf 'Slow down please - too many attempts allowed\n' > "$WORK_DIR/rl_body.body"
printf 'HTTP/1.1 200 OK\n\n' > "$WORK_DIR/rl_body.hdr"
if out=$(check_rate_limited rl_body); then
    assert_contains "T11" "check_rate_limited: 200 with 'too many attempts' body detected" \
        "RATE_LIMITED" "$out"
else
    _fail "T11" "check_rate_limited: 200 with 'too many attempts' body detected" \
        "returned non-zero unexpectedly"
fi

# Fixture: case-insensitive body match
printf 'status=200|size=25|redirect=|type=text/html\n' > "$WORK_DIR/rl_case.meta"
printf 'RATE LIMIT enforced now\n' > "$WORK_DIR/rl_case.body"
printf 'HTTP/1.1 200 OK\n\n' > "$WORK_DIR/rl_case.hdr"
if out=$(check_rate_limited rl_case); then
    assert_contains "T12" "check_rate_limited: uppercase 'RATE LIMIT' matched case-insensitively" \
        "RATE_LIMITED" "$out"
else
    _fail "T12" "check_rate_limited: uppercase 'RATE LIMIT' matched case-insensitively" \
        "returned non-zero unexpectedly"
fi

# Fixture: 200 clean response — should NOT trigger
printf 'status=200|size=30|redirect=|type=text/html\n' > "$WORK_DIR/rl_clean.meta"
printf '<html>Login form here</html>\n' > "$WORK_DIR/rl_clean.body"
printf 'HTTP/1.1 200 OK\n\n' > "$WORK_DIR/rl_clean.hdr"
if check_rate_limited rl_clean >/dev/null; then
    _fail "T13" "check_rate_limited: clean 200 response does NOT trigger" \
        "returned 0 (triggered) — false positive"
else
    _pass "T13" "check_rate_limited: clean 200 response does NOT trigger"
fi

# Fixture: 500 error, no rate-limit body — should NOT trigger
printf 'status=500|size=15|redirect=|type=text/html\n' > "$WORK_DIR/rl_500.meta"
printf 'Server error\n' > "$WORK_DIR/rl_500.body"
printf 'HTTP/1.1 500 Internal Server Error\n\n' > "$WORK_DIR/rl_500.hdr"
if check_rate_limited rl_500 >/dev/null; then
    _fail "T14" "check_rate_limited: 500 with no rate-limit body does NOT trigger" \
        "returned 0 (triggered) — false positive"
else
    _pass "T14" "check_rate_limited: 500 with no rate-limit body does NOT trigger"
fi

# --- get_meta / get_header (T15-T18) ---

printf 'status=302|size=1234|redirect=http://x/y|type=text/html\n' > "$WORK_DIR/gh.meta"
assert_eq "T15" "get_meta: status extracted" "302" "$(get_meta gh status)"
assert_eq "T16" "get_meta: size extracted" "1234" "$(get_meta gh size)"

printf 'HTTP/1.1 302 Found\r\nLocation: /dashboard\r\nSet-Cookie: SESSID=abc; Path=/\r\nContent-Type: text/html\r\n\r\n' > "$WORK_DIR/gh.hdr"
assert_eq "T17" "get_header: Location extracted (case-insensitive header name)" \
    "/dashboard" "$(get_header gh Location)"
assert_eq "T18" "get_header: Content-Type extracted" \
    "text/html" "$(get_header gh Content-Type)"

rm -rf "$WORK_DIR"
WORK_DIR=""

# ------------------------------------------------------------------------------
# CATEGORY 2: Integration tests (mock HTTP server per app class)
# ------------------------------------------------------------------------------

if [ "$HAVE_PYTHON3" = "no" ] || [ "$HAVE_CURL" = "no" ]; then
    reason=""
    [ "$HAVE_PYTHON3" = "no" ] && reason="python3 missing"
    [ "$HAVE_CURL" = "no" ] && reason="${reason:+$reason, }curl missing"
    for tid in T19 T20 T21 T22 T23 T24 T25 T26 T27 T28 T29 T30 T31 T32 T33 T34 T35 T36 T37 T38 T39 T40 T41 T42 T43 T44 T45 T46 T47; do
        _skip "$tid" "integration test skipped" "$reason"
    done
else
    FIXTURE_DIR=$(mktemp -d)
    trap "kill \$SERVER_PID 2>/dev/null; rm -rf $FIXTURE_DIR" EXIT

    PORT_UT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

    cat > "$FIXTURE_DIR/server.py" << 'PYEOF'
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
PORT = int(sys.argv[1])

class H(BaseHTTPRequestHandler):
    def log_message(self, *a, **k): pass

    def _write(self, status, body_bytes, content_type='text/html', extra_headers=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body_bytes)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if body_bytes:
            self.wfile.write(body_bytes)

    def _read_body(self):
        n = int(self.headers.get('Content-Length', 0))
        return self.rfile.read(n).decode('utf-8', errors='replace') if n else ''

    def do_GET(self):
        p = self.path
        if p == '/content/login':
            b = b'<html><body><nav><a href="/content/login">Login</a></nav><form method="POST" action="/content/login"><input name="email"><input name="password" type="password"></form></body></html>'
            self._write(200, b); return
        if p == '/redirect/login':
            b = b'<html><body><nav><a href="/redirect/login">Login</a></nav><form method="POST" action="/redirect/login"><input name="user"><input name="pass" type="password"></form></body></html>'
            self._write(200, b); return
        if p == '/api/login':
            b = b'{"info":"POST only"}'
            self._write(200, b, content_type='application/json'); return
        if p == '/basic/':
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="area"')
            self.end_headers()
            self.wfile.write(b'Unauthorized'); return
        if p == '/ratelimit429/':
            self.send_response(429)
            self.send_header('Retry-After', '60')
            self.end_headers()
            self.wfile.write(b'Too many requests'); return
        if p == '/ratelimit_body/':
            b = b'<html><body>Please slow down. Too many attempts recorded.</body></html>'
            self._write(200, b); return
        if p == '/unusual/':
            b = b'<html><body><form method="POST"><input name="u"><input name="p" type="password"></form></body></html>'
            self._write(200, b); return
        if p == '/':
            b = b'<html><body><nav><a href="/content/login">Login</a></nav></body></html>'
            self._write(200, b); return
        self.send_response(404); self.end_headers()

    def do_POST(self):
        p = self.path
        body_raw = self._read_body()
        f = parse_qs(body_raw, keep_blank_values=True)

        if p == '/content/login':
            u = f.get('email', [''])[0]
            pw = f.get('password', [''])[0]
            if not u or not pw:
                b = b'<html><body><nav><a href="/content/login">Login</a></nav><div class="alert-warning">Please fill in all fields.</div><form method="POST" action="/content/login"><input name="email"><input name="password" type="password"></form></body></html>'
                self._write(200, b); return
            if u == 'admin@x.com' and pw == 'admin':
                self.send_response(302)
                self.send_header('Location', '/content/dashboard')
                self.end_headers(); return
            b = b'<html><body><nav><a href="/content/login">Login</a></nav><div class="alert-danger">Invalid email or password.</div><form method="POST" action="/content/login"><input name="email"><input name="password" type="password"></form></body></html>'
            self._write(200, b); return

        if p == '/redirect/login':
            u = f.get('user', [''])[0]
            pw = f.get('pass', [''])[0]
            if not u or not pw:
                self.send_response(302)
                self.send_header('Location', '/redirect/login?error=empty')
                self.end_headers(); return
            if u == 'admin' and pw == 'admin':
                self.send_response(302)
                self.send_header('Location', '/redirect/dashboard')
                self.end_headers(); return
            self.send_response(302)
            self.send_header('Location', '/redirect/login?error=invalid')
            self.end_headers(); return

        if p == '/api/login':
            u = f.get('email', [''])[0]
            pw = f.get('password', [''])[0]
            if u == 'admin@x.com' and pw == 'admin':
                b = b'{"success":true,"token":"abc123xyz"}'
                self._write(200, b, content_type='application/json'); return
            b = b'{"error":"invalid_credentials"}'
            self._write(401, b, content_type='application/json'); return

        if p == '/unusual/':
            self.send_response(500); self.end_headers()
            self.wfile.write(b'Internal Server Error'); return

        if p == '/basic/':
            # If script erroneously POSTs to basic-auth path (should skip after
            # baseline classification), respond 401 without WWW-Authenticate to
            # simulate a hardened server. This behavior would misclassify the
            # response as UNUSUAL and would surface via absent CLASS: basic.
            self.send_response(401); self.end_headers(); return

        self.send_response(404); self.end_headers()

HTTPServer(('', PORT), H).serve_forever()
PYEOF

    python3 "$FIXTURE_DIR/server.py" "$PORT_UT" &
    SERVER_PID=$!
    sleep 1

    if ! curl -sf "http://localhost:$PORT_UT/" > /dev/null; then
        echo "ERROR: mock server failed to start on port $PORT_UT"
        exit 3
    fi

    # ---------------- CONTENT class (T19-T25) ----------------

    content_out=$(bash "$SCRIPT" --host=localhost --port="$PORT_UT" \
        --login-path=/content/login --form-action=/content/login \
        --user-field=email --pass-field=password 2>&1)

    assert_contains "T19" "CONTENT: CLASS marker" "CLASS: content" "$content_out"
    assert_contains "T20" "CONTENT: FAIL_STATUS 200" "FAIL_STATUS: 200" "$content_out"
    assert_contains "T21" "CONTENT: FAIL_SIGNAL_CANDIDATE contains 'Invalid email or password.'" \
        "Invalid email or password." "$content_out"
    assert_contains "T22" "CONTENT: UNAUTH_MARKER present" "UNAUTH_MARKER:" "$content_out"
    assert_contains "T23" "CONTENT: ORACLE_HYDRA emitted with F=" \
        "ORACLE_HYDRA: F=" "$content_out"
    assert_contains "T24" "CONTENT: ORACLE_FFUF matches 3xx codes" \
        "ORACLE_FFUF: -mc 301,302,303,307,308" "$content_out"
    assert_contains "T25" "CONTENT: ORACLE_SUMMARY class=content confidence=high" \
        "ORACLE_SUMMARY: class=content confidence=high" "$content_out"

    # ---------------- CONTENT oracle execution (T26-T27) — the money tests ----------------

    curl_test=$(printf '%s' "$content_out" | grep '^ORACLE_CURL_SUCCESS_TEST:' | \
        sed 's/^ORACLE_CURL_SUCCESS_TEST: //')
    if [ -z "$curl_test" ]; then
        _fail "T26" "CONTENT: emitted oracle discriminates real SUCCESS" "no ORACLE_CURL_SUCCESS_TEST line"
        _fail "T27" "CONTENT: emitted oracle rejects wrong creds" "no ORACLE_CURL_SUCCESS_TEST line"
    else
        URL="http://localhost:$PORT_UT/content/login"
        U="admin@x.com"; P="admin"
        if eval "$curl_test"; then
            _pass "T26" "CONTENT: emitted oracle discriminates real SUCCESS (admin@x.com:admin)"
        else
            _fail "T26" "CONTENT: emitted oracle discriminates real SUCCESS (admin@x.com:admin)" \
                "oracle returned non-zero for known-good creds"
        fi
        U="wrong@x.com"; P="wrong"
        if eval "$curl_test"; then
            _fail "T27" "CONTENT: emitted oracle rejects wrong creds" \
                "oracle returned 0 for known-wrong creds (false SUCCESS)"
        else
            _pass "T27" "CONTENT: emitted oracle rejects wrong creds"
        fi
    fi

    # ---------------- REDIRECT class (T28-T33) ----------------

    redirect_out=$(bash "$SCRIPT" --host=localhost --port="$PORT_UT" \
        --login-path=/redirect/login --form-action=/redirect/login \
        --user-field=user --pass-field=pass 2>&1)

    assert_contains "T28" "REDIRECT: CLASS marker" "CLASS: redirect" "$redirect_out"
    assert_contains "T29" "REDIRECT: FAIL_STATUS 302" "FAIL_STATUS: 302" "$redirect_out"
    assert_contains "T30" "REDIRECT: FAIL_LOCATION points to /redirect/login" \
        "FAIL_LOCATION: /redirect/login" "$redirect_out"
    assert_contains "T31" "REDIRECT: ORACLE_HYDRA F=name=\"user\"" \
        'ORACLE_HYDRA: F=name="user"' "$redirect_out"
    assert_contains "T32" "REDIRECT: ORACLE_FFUF uses -r -fr" \
        "ORACLE_FFUF: -r -fr" "$redirect_out"
    assert_contains "T33" "REDIRECT: ORACLE_SUMMARY class=redirect" \
        "ORACLE_SUMMARY: class=redirect" "$redirect_out"

    # REDIRECT oracle execution (T34-T35)
    curl_test=$(printf '%s' "$redirect_out" | grep '^ORACLE_CURL_SUCCESS_TEST:' | \
        sed 's/^ORACLE_CURL_SUCCESS_TEST: //')
    if [ -z "$curl_test" ]; then
        _fail "T34" "REDIRECT: emitted oracle discriminates real SUCCESS" "no oracle line"
        _fail "T35" "REDIRECT: emitted oracle rejects wrong creds" "no oracle line"
    else
        URL="http://localhost:$PORT_UT/redirect/login"
        U="admin"; P="admin"
        if eval "$curl_test"; then
            _pass "T34" "REDIRECT: emitted oracle discriminates real SUCCESS (admin:admin)"
        else
            _fail "T34" "REDIRECT: emitted oracle discriminates real SUCCESS (admin:admin)" \
                "oracle returned non-zero for known-good creds"
        fi
        U="wrong"; P="wrong"
        if eval "$curl_test"; then
            _fail "T35" "REDIRECT: emitted oracle rejects wrong creds" \
                "oracle returned 0 for known-wrong creds (false SUCCESS)"
        else
            _pass "T35" "REDIRECT: emitted oracle rejects wrong creds"
        fi
    fi

    # ---------------- API class (T36-T40) ----------------

    api_out=$(bash "$SCRIPT" --host=localhost --port="$PORT_UT" \
        --login-path=/api/login --form-action=/api/login \
        --user-field=email --pass-field=password 2>&1)

    assert_contains "T36" "API: CLASS marker" "CLASS: api" "$api_out"
    assert_contains "T37" "API: FAIL_STATUS 401" "FAIL_STATUS: 401" "$api_out"
    assert_contains "T38" "API: FAIL_CONTENT_TYPE contains json" \
        "FAIL_CONTENT_TYPE: application/json" "$api_out"
    assert_contains "T39" "API: ORACLE_HYDRA S=\"token\"" \
        'ORACLE_HYDRA: S="token"' "$api_out"
    assert_contains "T40" "API: ORACLE_FFUF -mc 200" "ORACLE_FFUF: -mc 200" "$api_out"

    # API oracle execution (T41-T42)
    curl_test=$(printf '%s' "$api_out" | grep '^ORACLE_CURL_SUCCESS_TEST:' | \
        sed 's/^ORACLE_CURL_SUCCESS_TEST: //')
    if [ -z "$curl_test" ]; then
        _fail "T41" "API: emitted oracle discriminates real SUCCESS" "no oracle line"
        _fail "T42" "API: emitted oracle rejects wrong creds" "no oracle line"
    else
        URL="http://localhost:$PORT_UT/api/login"
        U="admin@x.com"; P="admin"
        if eval "$curl_test"; then
            _pass "T41" "API: emitted oracle discriminates real SUCCESS"
        else
            _fail "T41" "API: emitted oracle discriminates real SUCCESS" \
                "oracle returned non-zero for known-good creds"
        fi
        U="wrong"; P="wrong"
        if eval "$curl_test"; then
            _fail "T42" "API: emitted oracle rejects wrong creds" \
                "oracle returned 0 for known-wrong creds (false SUCCESS)"
        else
            _pass "T42" "API: emitted oracle rejects wrong creds"
        fi
    fi

    # ---------------- BASIC class (T43-T45) ----------------

    basic_out=$(bash "$SCRIPT" --host=localhost --port="$PORT_UT" \
        --login-path=/basic/ --form-action=/basic/ \
        --user-field=x --pass-field=y 2>&1)

    assert_contains "T43" "BASIC: CLASS marker" "CLASS: basic" "$basic_out"
    assert_contains "T44" "BASIC: ROUTE_OUT marker" \
        "ROUTE_OUT: Login Bypass Techniques Basic Auth section" "$basic_out"
    # Basic-auth short-circuits BEFORE POST samples, so content-class markers
    # (which are only emitted after fail sample analysis) must be absent.
    assert_not_contains "T45" "BASIC: no FAIL_SIGNAL_CANDIDATE (POST samples skipped)" \
        "FAIL_SIGNAL_CANDIDATE" "$basic_out"

    # ---------------- Rate limit self-defense (T46-T48) ----------------

    rl429_out=$(bash "$SCRIPT" --host=localhost --port="$PORT_UT" \
        --login-path=/ratelimit429/ --form-action=/ratelimit429/ \
        --user-field=x --pass-field=y 2>&1)
    assert_contains "T46" "RATE_LIMITED: 429 on baseline → RATE_LIMITED marker" \
        "RATE_LIMITED" "$rl429_out"

    rlbody_out=$(bash "$SCRIPT" --host=localhost --port="$PORT_UT" \
        --login-path=/ratelimit_body/ --form-action=/ratelimit_body/ \
        --user-field=x --pass-field=y 2>&1)
    assert_contains "T47" "RATE_LIMITED: 200 with rate-limit body → RATE_LIMITED marker" \
        "RATE_LIMITED" "$rlbody_out"

    # ---------------- UNUSUAL class (T48-T49) ----------------

    unusual_out=$(bash "$SCRIPT" --host=localhost --port="$PORT_UT" \
        --login-path=/unusual/ --form-action=/unusual/ \
        --user-field=u --pass-field=p 2>&1)
    assert_contains "T48" "UNUSUAL: 500 fail → CLASS: unusual" "CLASS: unusual" "$unusual_out"
    assert_contains "T49" "UNUSUAL: 500 fail → BAIL marker with escalation" \
        "BAIL:" "$unusual_out"

    # ---------------- Unreachable host (T50) ----------------

    BAD_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); p=s.getsockname()[1]; s.close(); print(p)')
    unreachable_out=$(bash "$SCRIPT" --host=localhost --port="$BAD_PORT" \
        --login-path=/ --form-action=/ --user-field=x --pass-field=y 2>&1)
    assert_contains "T50" "UNREACHABLE: dead port → BAIL: baseline GET failed" \
        "BAIL: baseline GET failed" "$unreachable_out"
fi

# ------------------------------------------------------------------------------
# CATEGORY 3: Argument validation (T51-T62)
# ------------------------------------------------------------------------------

out=$(bash "$SCRIPT" 2>&1 || true)
assert_contains "T51" "no args → --host required error" "--host required" "$out"

out=$(bash "$SCRIPT" --host=x 2>&1 || true)
assert_contains "T52" "only --host → --port required error" "--port required" "$out"

out=$(bash "$SCRIPT" --host=x --port=1 2>&1 || true)
assert_contains "T53" "--host --port only → --login-path required error" \
    "--login-path required" "$out"

out=$(bash "$SCRIPT" --host=x --port=1 --login-path=/ 2>&1 || true)
assert_contains "T54" "missing --form-action → error" "--form-action required" "$out"

out=$(bash "$SCRIPT" --host=x --port=1 --login-path=/ --form-action=/ 2>&1 || true)
assert_contains "T55" "missing --user-field → error" "--user-field required" "$out"

out=$(bash "$SCRIPT" --host=x --port=1 --login-path=/ --form-action=/ --user-field=e 2>&1 || true)
assert_contains "T56" "missing --pass-field → error" "--pass-field required" "$out"

out=$(bash "$SCRIPT" --host=x --port=1 --login-path=/ --form-action=/ \
    --user-field=e --pass-field=p --scheme=ftp 2>&1 || true)
assert_contains "T57" "bad --scheme=ftp → error" "invalid scheme" "$out"

out=$(bash "$SCRIPT" --host=x --port=1 --login-path=/ --form-action=/ \
    --user-field=e --pass-field=p --delay=abc 2>&1 || true)
assert_contains "T58" "bad --delay=abc → error" "--delay must be non-negative integer" "$out"

out=$(bash "$SCRIPT" --host=x --port=1 --login-path=/ --form-action=/ \
    --user-field=e --pass-field=p --delay=-5 2>&1 || true)
assert_contains "T59" "negative --delay=-5 → error" "--delay must be non-negative integer" "$out"

out=$(bash "$SCRIPT" --host=x --port=1 --login-path=/ --form-action=/ \
    --user-field=e --pass-field=p --bogus 2>&1 || true)
assert_contains "T60" "unknown flag → error" "unknown argument" "$out"

out=$(bash "$SCRIPT" --help 2>&1 || true)
assert_contains "T61" "--help → usage" "Usage:" "$out"

out=$(bash "$SCRIPT" -h 2>&1 || true)
assert_contains "T62" "-h → usage" "Usage:" "$out"

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------

echo
echo "============================="
echo "PASSED:  $PASS"
echo "FAILED:  $FAIL"
echo "SKIPPED: $SKIP"
echo "============================="

if [ "$FAIL" -gt 0 ]; then
    echo
    echo "Failures:"
    for f in "${FAILURES[@]}"; do echo "  - $f"; done
    exit "$FAIL"
fi

exit 0
