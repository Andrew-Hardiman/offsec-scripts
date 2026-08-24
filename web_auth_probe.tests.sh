#!/bin/bash
# web_auth_probe.tests.sh - Regression tests for web_auth_probe.sh
#
# Two test categories:
#   1. Unit tests (source main script, call classify_* functions with fixture
#      HTML strings, assert classifications). Fast, no network.
#   2. Integration tests (spin up ephemeral Python HTTP server with hand-crafted
#      endpoints, run main script against it, assert markers in output).
#
# Usage:
#   web_auth_probe.tests.sh                                      # default path
#   web_auth_probe.tests.sh /path/to/web_auth_probe.sh           # explicit path
#
# Exit code: 0 = all pass; non-zero = number of failures.
#
# Maintenance: When a new edge case surfaces during validation on a real box,
# add a test case reproducing the issue, watch it fail, modify the script to
# handle it, watch it pass, re-run full suite.

set -u

SCRIPT="${1:-$HOME/scripts/web_auth_probe.sh}"
if [ ! -f "$SCRIPT" ]; then
    SCRIPT="$(dirname "$0")/web_auth_probe.sh"
fi
if [ ! -f "$SCRIPT" ]; then
    echo "ERROR: cannot find web_auth_probe.sh (tried \$1, \$HOME/scripts/, dirname \$0)" >&2
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
    printf "  python3: NO  — 25 integration tests will skip (needed for mock HTTP server)\n"
fi

if [ "$HAVE_CURL" = "yes" ]; then
    printf "  curl:    yes\n"
else
    printf "  curl:    NO  — 25 integration tests will skip (needed by script under test)\n"
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
# CATEGORY 1: Unit tests (classifier functions + helpers)
# ------------------------------------------------------------------------------

MODE="login"; HOST="x"; PORT="1"
# shellcheck disable=SC1090
source "$SCRIPT"

# --- classify_login (T1–T10) ---

login_classic='<html><form><input type="text" name="u"><input type="password" name="p"><button>Login</button></form></html>'
assert_eq "T1" "login_classic → FORM_FOUND" "FORM_FOUND" "$(classify_login "$login_classic")"

login_ident_first_email='<html><form><input type="email" name="e"><button>Next</button></form></html>'
assert_eq "T2" "login_ident_first (email input) → CANDIDATE" "CANDIDATE" "$(classify_login "$login_ident_first_email")"

login_ident_first_text='<html><form><input type="text" name="u"><button>Next</button></form></html>'
assert_eq "T3" "login_ident_first (text input) → CANDIDATE" "CANDIDATE" "$(classify_login "$login_ident_first_text")"

login_ident_first_notype='<html><form><input name="u"><button>Next</button></form></html>'
assert_eq "T4" "login_ident_first (untyped input) → CANDIDATE" "CANDIDATE" "$(classify_login "$login_ident_first_notype")"

login_multi_pw='<html><form><input type="password"><input type="password"></form></html>'
assert_eq "T5" "login_multi_pw (register-shape) → NO_FORM in login mode" "NO_FORM" "$(classify_login "$login_multi_pw")"

login_no_form='<html><body>Just some text, no form here.</body></html>'
assert_eq "T6" "login_no_form → NO_FORM" "NO_FORM" "$(classify_login "$login_no_form")"

login_empty_form='<html><form></form></html>'
assert_eq "T7" "login_empty_form → NO_FORM" "NO_FORM" "$(classify_login "$login_empty_form")"

login_unquoted_type='<html><form><input type=password name=p></form></html>'
assert_eq "T8" "login_unquoted_type → FORM_FOUND" "FORM_FOUND" "$(classify_login "$login_unquoted_type")"

login_single_quote_type="<html><form><input type='password' name='p'></form></html>"
assert_eq "T9" "login_single_quote_type → FORM_FOUND" "FORM_FOUND" "$(classify_login "$login_single_quote_type")"

login_uppercase_type='<html><form><INPUT TYPE="PASSWORD"></form></html>'
assert_eq "T10" "login_uppercase_type (case-insensitive match) → FORM_FOUND" "FORM_FOUND" "$(classify_login "$login_uppercase_type")"

# --- classify_register (T11–T15) ---

register_classic='<html><form><input type="text" name="u"><input type="email" name="e"><input type="password" name="p"><input type="password" name="c"></form></html>'
assert_eq "T11" "register_classic → FORM_FOUND" "FORM_FOUND" "$(classify_register "$register_classic")"

register_no_email='<html><form><input type="text" name="u"><input type="password"><input type="password" name="c"></form></html>'
assert_eq "T12" "register_no_email (multi-pw, no email) → CANDIDATE" "CANDIDATE" "$(classify_register "$register_no_email")"

register_single_pw='<html><form><input type="email" name="e"><input type="password" name="p"></form></html>'
assert_eq "T13" "register_single_pw (single-pw with email) → CANDIDATE" "CANDIDATE" "$(classify_register "$register_single_pw")"

register_login_shape='<html><form><input type="text"><input type="password"></form></html>'
assert_eq "T14" "register_login_shape (single pw, no email) → NO_FORM in register mode" "NO_FORM" "$(classify_register "$register_login_shape")"

register_no_form='<html><body>No form.</body></html>'
assert_eq "T15" "register_no_form → NO_FORM" "NO_FORM" "$(classify_register "$register_no_form")"

# --- classify_forgot (T16–T19) ---

forgot_classic='<html><form><input type="email" name="e"><button>Reset</button></form></html>'
assert_eq "T16" "forgot_classic → FORM_FOUND" "FORM_FOUND" "$(classify_forgot "$forgot_classic")"

forgot_username='<html><form><input type="text" name="u"><button>Send reset link</button></form></html>'
assert_eq "T17" "forgot_username (text input, no pw) → CANDIDATE" "CANDIDATE" "$(classify_forgot "$forgot_username")"

forgot_has_password='<html><form><input type="email"><input type="password"></form></html>'
assert_eq "T18" "forgot_has_password (password present) → NO_FORM in forgot mode" "NO_FORM" "$(classify_forgot "$forgot_has_password")"

forgot_no_form='<html><body>Just text.</body></html>'
assert_eq "T19" "forgot_no_form → NO_FORM" "NO_FORM" "$(classify_forgot "$forgot_no_form")"

# --- extract_form_signals internals (T20a–T20f) ---

signals_html='<html><form><input type="text"><input type="email"><input type="password"><input name="notype"></form></html>'
extract_form_signals "$signals_html"
assert_eq "T20a" "signals: G_HAS_FORM = 1" "1" "$G_HAS_FORM"
assert_eq "T20b" "signals: G_PW_COUNT = 1" "1" "$G_PW_COUNT"
assert_eq "T20c" "signals: G_TEXT_COUNT = 1" "1" "$G_TEXT_COUNT"
assert_eq "T20d" "signals: G_EMAIL_COUNT = 1" "1" "$G_EMAIL_COUNT"
assert_eq "T20e" "signals: G_ALL_INPUT_COUNT = 4" "4" "$G_ALL_INPUT_COUNT"
assert_eq "T20f" "signals: G_NO_TYPE_INPUT_COUNT = 1" "1" "$G_NO_TYPE_INPUT_COUNT"

# --- fmt_path (T21a–T21d) ---

assert_eq "T21a" "fmt_path: no redirect returns bare path" "/login.php" "$(fmt_path '/login.php' 'http://x:80/login.php')"
assert_eq "T21b" "fmt_path: redirect returns 'orig → final'" "/admin → /login.php" "$(fmt_path '/admin' 'http://x:80/login.php')"
assert_eq "T21c" "fmt_path: query string preserved in final path" "/admin → /login.php?next=/" "$(fmt_path '/admin' 'http://x:80/login.php?next=/')"
assert_eq "T21d" "fmt_path: empty path falls back to '/'" "/" "$(fmt_path '/' 'http://x:80')"

# ------------------------------------------------------------------------------
# CATEGORY 2: Integration tests via mock HTTP server (T22–T36)
# ------------------------------------------------------------------------------

if [ "$HAVE_PYTHON3" = "no" ] || [ "$HAVE_CURL" = "no" ]; then
    reason=""
    if [ "$HAVE_PYTHON3" = "no" ]; then reason="python3 unavailable"; fi
    if [ "$HAVE_CURL" = "no" ]; then reason="${reason:+$reason, }curl unavailable"; fi
    _skip "T22" "login integration: /login.php FOUND" "$reason"
    _skip "T23" "login integration: /admin redirect chain surfaced" "$reason"
    _skip "T24" "login integration: /signin CANDIDATE (identifier-first)" "$reason"
    _skip "T25a" "AUTH_CHALLENGE: Basic scheme detected" "$reason"
    _skip "T25b" "AUTH_CHALLENGE: Bearer scheme detected" "$reason"
    _skip "T26" "RESTRICTED marker on 403" "$reason"
    _skip "T27" "METHOD_MISMATCH marker on 405" "$reason"
    _skip "T28" "SERVER_ERROR marker on 500" "$reason"
    _skip "T29" "LOGIN_FORM_FOUND direct hit via wrapper" "$reason"
    _skip "T30" "LOGIN_FORM_FOUND via redirect via wrapper" "$reason"
    _skip "T31" "LOGIN_FORM_FOUND via multi-hop redirect (3 hops)" "$reason"
    _skip "T32a" "SUMMARY marker present" "$reason"
    _skip "T32b" "SUMMARY: found count = 3" "$reason"
    _skip "T32c" "SUMMARY: challenges count = 2" "$reason"
    _skip "T32d" "SUMMARY: restricted count = 1" "$reason"
    _skip "T32e" "SUMMARY: method_mismatch count = 1" "$reason"
    _skip "T32f" "SUMMARY: server_error count = 1" "$reason"
    _skip "T33" "register mode integration: /register.php FOUND" "$reason"
    _skip "T34" "forgot mode integration: /forgot FOUND" "$reason"
    _skip "T35" "mode isolation: register form not flagged as LOGIN_FORM_FOUND" "$reason"
    _skip "T36" "unreachable host emits UNREACHABLE marker" "$reason"
else
    FIXTURE_DIR=$(mktemp -d)
    trap "kill \$SERVER_PID 2>/dev/null; rm -rf $FIXTURE_DIR" EXIT

    PORT_UT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

    cat > "$FIXTURE_DIR/login.php" << 'EOF'
<html><body><form method="post" action="/login.php">
<input type="text" name="u"><input type="password" name="p"><button>Login</button>
</form></body></html>
EOF

    cat > "$FIXTURE_DIR/register.php" << 'EOF'
<html><body><form method="post"><input type="text" name="u"><input type="email" name="e">
<input type="password" name="p"><input type="password" name="c"><button>Sign Up</button>
</form></body></html>
EOF

    cat > "$FIXTURE_DIR/forgot_page" << 'EOF'
<html><body><form><input type="email" name="e"><button>Reset</button></form></body></html>
EOF

    cat > "$FIXTURE_DIR/signin_ident_first" << 'EOF'
<html><body><form><input type="text" name="account"><button>Continue</button></form></body></html>
EOF

    echo "<html>Homepage no form</html>" > "$FIXTURE_DIR/index.html"

    cat > "$FIXTURE_DIR/server.py" << 'PYEOF'
import os, sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
os.chdir(sys.argv[1])
PORT = int(sys.argv[2])

class H(SimpleHTTPRequestHandler):
    def log_message(self, *a, **k): pass
    def do_GET(self):
        if self.path == '/admin':
            self.send_response(301); self.send_header('Location', '/login.php')
            self.end_headers(); return
        if self.path == '/basicauth':
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Admin Zone"')
            self.end_headers(); return
        if self.path == '/bearer':
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Bearer realm="API"')
            self.end_headers(); return
        if self.path == '/signin':
            with open('signin_ident_first','rb') as f: b=f.read()
            self.send_response(200); self.send_header('Content-Type','text/html')
            self.end_headers(); self.wfile.write(b); return
        if self.path == '/forgot':
            with open('forgot_page','rb') as f: b=f.read()
            self.send_response(200); self.send_header('Content-Type','text/html')
            self.end_headers(); self.wfile.write(b); return
        if self.path == '/administrator':
            self.send_response(403); self.end_headers(); return
        if self.path == '/api/login':
            self.send_response(405); self.end_headers(); return
        if self.path == '/broken':
            self.send_response(500); self.end_headers(); return
        # Multi-hop redirect chain: /longredir -> /step1 -> /step2 -> /login.php
        if self.path == '/longredir':
            self.send_response(302); self.send_header('Location','/step1')
            self.end_headers(); return
        if self.path == '/step1':
            self.send_response(302); self.send_header('Location','/step2')
            self.end_headers(); return
        if self.path == '/step2':
            self.send_response(302); self.send_header('Location','/login.php')
            self.end_headers(); return
        super().do_GET()

HTTPServer(('', PORT), H).serve_forever()
PYEOF

    python3 "$FIXTURE_DIR/server.py" "$FIXTURE_DIR" "$PORT_UT" &
    SERVER_PID=$!
    sleep 1

    if ! curl -sf "http://localhost:$PORT_UT/" > /dev/null; then
        echo "ERROR: mock server failed to start on port $PORT_UT"
        exit 3
    fi

    login_out=$(bash "$SCRIPT" localhost "$PORT_UT" --mode=login 2>&1)
    assert_contains "T22" "login integration: /login.php FOUND" "LOGIN_FORM_FOUND: /login.php" "$login_out"
    assert_contains "T23" "login integration: /admin → /login.php redirect surfaced" "LOGIN_FORM_FOUND: /admin → /login.php" "$login_out"
    assert_contains "T24" "login integration: /signin CANDIDATE (identifier-first)" "LOGIN_CANDIDATE: /signin" "$login_out"

    cat > "$FIXTURE_DIR/wrapper_login.sh" << WEOF
#!/bin/bash
set -u
source "$SCRIPT"
LOGIN_PATHS=(/basicauth /bearer /administrator /api/login /broken /login.php /admin /longredir)
main "\$@"
WEOF
    chmod +x "$FIXTURE_DIR/wrapper_login.sh"
    wrapper_out=$(bash "$FIXTURE_DIR/wrapper_login.sh" localhost "$PORT_UT" --mode=login 2>&1)

    assert_contains "T25a" "AUTH_CHALLENGE: Basic scheme detected via WWW-Authenticate" \
        "AUTH_CHALLENGE: /basicauth (code=401 scheme=Basic)" "$wrapper_out"
    assert_contains "T25b" "AUTH_CHALLENGE: Bearer scheme detected via WWW-Authenticate" \
        "AUTH_CHALLENGE: /bearer (code=401 scheme=Bearer)" "$wrapper_out"
    assert_contains "T26" "RESTRICTED marker emitted on 403" \
        "RESTRICTED: /administrator (code=403)" "$wrapper_out"
    assert_contains "T27" "METHOD_MISMATCH marker emitted on 405" \
        "METHOD_MISMATCH: /api/login (code=405)" "$wrapper_out"
    assert_contains "T28" "SERVER_ERROR marker emitted on 500" \
        "SERVER_ERROR: /broken (code=500)" "$wrapper_out"
    assert_contains "T29" "LOGIN_FORM_FOUND direct hit /login.php" \
        "LOGIN_FORM_FOUND: /login.php" "$wrapper_out"
    assert_contains "T30" "LOGIN_FORM_FOUND via single redirect /admin → /login.php" \
        "LOGIN_FORM_FOUND: /admin → /login.php" "$wrapper_out"
    assert_contains "T31" "LOGIN_FORM_FOUND via multi-hop redirect /longredir → /login.php (3 hops)" \
        "LOGIN_FORM_FOUND: /longredir → /login.php" "$wrapper_out"

    assert_contains "T32a" "SUMMARY marker present" "AUTH_PROBE_SUMMARY: mode=login" "$wrapper_out"
    assert_contains "T32b" "SUMMARY: found count = 3" "found=3" "$wrapper_out"
    assert_contains "T32c" "SUMMARY: challenges count = 2" "challenges=2" "$wrapper_out"
    assert_contains "T32d" "SUMMARY: restricted count = 1" "restricted=1" "$wrapper_out"
    assert_contains "T32e" "SUMMARY: method_mismatch count = 1" "method_mismatch=1" "$wrapper_out"
    assert_contains "T32f" "SUMMARY: server_error count = 1" "server_error=1" "$wrapper_out"

    register_out=$(bash "$SCRIPT" localhost "$PORT_UT" --mode=register 2>&1)
    assert_contains "T33" "register integration: /register.php FOUND" \
        "REGISTER_FORM_FOUND: /register.php" "$register_out"

    forgot_out=$(bash "$SCRIPT" localhost "$PORT_UT" --mode=forgot 2>&1)
    assert_contains "T34" "forgot integration: /forgot FOUND" \
        "FORGOT_FORM_FOUND: /forgot" "$forgot_out"

    assert_not_contains "T35" "mode isolation: /register.php not LOGIN_FORM_FOUND" \
        "LOGIN_FORM_FOUND: /register.php" "$login_out"

    BAD_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); p=s.getsockname()[1]; s.close(); print(p)')
    unreachable_out=$(bash "$SCRIPT" localhost "$BAD_PORT" --mode=login 2>&1)
    if echo "$unreachable_out" | grep -q '^UNREACHABLE:'; then
        _pass "T36" "unreachable host emits UNREACHABLE marker"
    else
        _fail "T36" "unreachable host emits UNREACHABLE marker" "no UNREACHABLE markers in output"
    fi
fi

# ------------------------------------------------------------------------------
# CATEGORY 3: Argument validation (T37–T42)
# ------------------------------------------------------------------------------

out=$(bash "$SCRIPT" 2>&1 || true)
assert_contains "T37" "no args → usage" "Usage:" "$out"

out=$(bash "$SCRIPT" host 80 2>&1 || true)
assert_contains "T38" "no --mode → error" "--mode required" "$out"

out=$(bash "$SCRIPT" host 80 --mode=bogus 2>&1 || true)
assert_contains "T39" "invalid mode → error" "invalid mode" "$out"

out=$(bash "$SCRIPT" host 80 --mode=login --scheme=ftp 2>&1 || true)
assert_contains "T40" "invalid scheme → error" "invalid scheme" "$out"

out=$(bash "$SCRIPT" host 80 --mode=login --bogus 2>&1 || true)
assert_contains "T41" "unknown flag → error" "unknown flag" "$out"

out=$(bash "$SCRIPT" --help 2>&1 || true)
assert_contains "T42" "--help → usage" "Usage:" "$out"

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
