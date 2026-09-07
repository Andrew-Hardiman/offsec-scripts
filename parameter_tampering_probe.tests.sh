#!/bin/bash
# parameter_tampering_probe.tests.sh
#
# Regression suite for parameter_tampering_probe.sh v1.
#
# Usage:
#   ./parameter_tampering_probe_tests.sh          # uses ~/scripts/parameter_tampering_probe.sh
#   PTP=/path/to/script ./tests                    # override path
#
# Structure:
#   Section 1: Argument validation (subprocess — bash "$PTP" ...)
#   Section 2: Function units (source "$PTP", call functions directly)
#              - authority()
#              - label_to_filename()
#              - is_fail() including quote/regex/dash edge cases
#              - get_meta()
#              - check_rate_limited() including status-429 and body-pattern paths
#   Section 3: Integration (spins up embedded mock HTTP server, runs full probe,
#              asserts on output lines). Skipped if python3 unavailable or port
#              in use — reported as SKIP, not FAIL.
#
# Not covered (require live target — Phase 5 live-target validation):
#   - Actual THM box behaviour
#   - Real WAF / CAPTCHA / bot detection interception
#   - Genuine application-level rate limiter under load
#   - HTTPS to targets with cert quirks beyond -k tolerance

set -u

PTP="${PTP:-$HOME/scripts/parameter_tampering_probe.sh}"

if [ ! -f "$PTP" ]; then
    echo "ERROR: script not found at $PTP" >&2
    echo "Override with: PTP=<path> $0" >&2
    exit 2
fi

# Source for unit tests (main() gated by BASH_SOURCE guard — will not run)
source "$PTP"
set +u

echo "Testing: $PTP"
echo ""

PASSED=0
FAILED=0
SKIPPED=0
failed_names=()

check() {
    local name="$1" actual="$2" expected="$3"
    if [ "$actual" = "$expected" ]; then
        PASSED=$((PASSED+1))
        echo "PASS: $name"
    else
        FAILED=$((FAILED+1))
        failed_names+=("$name")
        echo "FAIL: $name"
        printf '  expected: %q\n' "$expected"
        printf '  actual:   %q\n' "$actual"
    fi
}

check_contains() {
    local name="$1" actual="$2" needle="$3"
    if [[ "$actual" == *"$needle"* ]]; then
        PASSED=$((PASSED+1))
        echo "PASS: $name"
    else
        FAILED=$((FAILED+1))
        failed_names+=("$name")
        echo "FAIL: $name"
        printf '  expected substring: %q\n' "$needle"
        printf '  actual:             %q\n' "$actual"
    fi
}

new_workdir() {
    [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ] && rm -rf "$WORK_DIR"
    WORK_DIR=$(mktemp -d)
}

CLEANUP_MOCK_PID=""
cleanup() {
    [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ] && rm -rf "$WORK_DIR"
    [ -n "$CLEANUP_MOCK_PID" ] && kill -9 "$CLEANUP_MOCK_PID" 2>/dev/null
}
trap cleanup EXIT

# ==============================================================================
# 1. Argument validation (subprocess)
# ==============================================================================

REQ_MIN="--host=x --port=80 --form-action=/x --user-field=email --pass-field=password --fail-status=200 --fail-marker=abc"

out=$(bash "$PTP" 2>&1); rc=$?
check          "T1a: no args exits 1"                       "$rc"  "1"
check_contains "T1b: no args error message"                 "$out" "ERROR: --host required"

out=$(bash "$PTP" --port=80 --form-action=/x --user-field=e --pass-field=p --fail-status=200 --fail-marker=abc 2>&1); rc=$?
check          "T2a: missing --host exits 1"                "$rc"  "1"
check_contains "T2b: missing --host message"                "$out" "ERROR: --host required"

out=$(bash "$PTP" --host=x --form-action=/x --user-field=e --pass-field=p --fail-status=200 --fail-marker=abc 2>&1); rc=$?
check          "T3a: missing --port exits 1"                "$rc"  "1"
check_contains "T3b: missing --port message"                "$out" "ERROR: --port required"

out=$(bash "$PTP" --host=x --port=80 --user-field=e --pass-field=p --fail-status=200 --fail-marker=abc 2>&1); rc=$?
check          "T4a: missing --form-action exits 1"         "$rc"  "1"
check_contains "T4b: missing --form-action message"         "$out" "ERROR: --form-action required"

out=$(bash "$PTP" --host=x --port=80 --form-action=/x --pass-field=p --fail-status=200 --fail-marker=abc 2>&1); rc=$?
check          "T5a: missing --user-field exits 1"          "$rc"  "1"
check_contains "T5b: missing --user-field message"          "$out" "ERROR: --user-field required"

out=$(bash "$PTP" --host=x --port=80 --form-action=/x --user-field=e --fail-status=200 --fail-marker=abc 2>&1); rc=$?
check          "T6a: missing --pass-field exits 1"          "$rc"  "1"
check_contains "T6b: missing --pass-field message"          "$out" "ERROR: --pass-field required"

out=$(bash "$PTP" --host=x --port=80 --form-action=/x --user-field=e --pass-field=p --fail-marker=abc 2>&1); rc=$?
check          "T7a: missing --fail-status exits 1"         "$rc"  "1"
check_contains "T7b: missing --fail-status message"         "$out" "ERROR: --fail-status required"

out=$(bash "$PTP" --host=x --port=80 --form-action=/x --user-field=e --pass-field=p --fail-status=200 2>&1); rc=$?
check          "T8a: missing --fail-marker exits 1"         "$rc"  "1"
check_contains "T8b: missing --fail-marker message"         "$out" "ERROR: --fail-marker required"

out=$(bash "$PTP" $REQ_MIN --form-action=login.php 2>&1); rc=$?
check          "T9a: --form-action without leading / exits 1" "$rc"  "1"
check_contains "T9b: --form-action without / message"       "$out" "must start with /"

out=$(bash "$PTP" $REQ_MIN --scheme=ftp 2>&1); rc=$?
check          "T10a: invalid --scheme exits 1"             "$rc"  "1"
check_contains "T10b: invalid --scheme message"             "$out" "invalid scheme"

out=$(bash "$PTP" $REQ_MIN --delay=abc 2>&1); rc=$?
check          "T11a: non-numeric --delay exits 1"          "$rc"  "1"
check_contains "T11b: non-numeric --delay message"          "$out" "must be non-negative integer"

out=$(bash "$PTP" $REQ_MIN --delay=-1 2>&1); rc=$?
check          "T12: negative --delay exits 1"              "$rc"  "1"

out=$(bash "$PTP" --host=x --port=80 --form-action=/x --user-field=e --pass-field=p --fail-status=999 --fail-marker=abc 2>&1); rc=$?
check          "T13a: --fail-status out of range exits 1"   "$rc"  "1"
check_contains "T13b: --fail-status range message"          "$out" "must be a valid HTTP status code"

out=$(bash "$PTP" --host=x --port=80 --form-action=/x --user-field=e --pass-field=p --fail-status=abc --fail-marker=abc 2>&1); rc=$?
check          "T14a: --fail-status non-numeric exits 1"    "$rc"  "1"

out=$(bash "$PTP" --unknown 2>&1); rc=$?
check          "T15a: unknown flag exits 1"                 "$rc"  "1"
check_contains "T15b: unknown flag message"                 "$out" "unknown argument"

out=$(bash "$PTP" --help 2>&1)
check_contains "T16: --help prints usage"                   "$out" "Usage:"

out=$(bash "$PTP" -h 2>&1)
check_contains "T17: -h prints usage"                       "$out" "Usage:"

# ==============================================================================
# 2. Function units
# ==============================================================================

# --- authority() ---
SCHEME=http PORT=80 HOST=example.com
check "T20: authority http:80 omits port"           "$(authority)" "http://example.com"

SCHEME=https PORT=443 HOST=example.com
check "T21: authority https:443 omits port"         "$(authority)" "https://example.com"

SCHEME=http PORT=8080 HOST=example.com
check "T22: authority http:8080 keeps port"         "$(authority)" "http://example.com:8080"

SCHEME=https PORT=8443 HOST=example.com
check "T23: authority https:8443 keeps port"        "$(authority)" "https://example.com:8443"

SCHEME=http PORT=80 HOST=127.0.0.1
check "T24: authority IP host omits default port"   "$(authority)" "http://127.0.0.1"

SCHEME=http PORT=443 HOST=example.com
check "T25: authority http:443 keeps non-default"   "$(authority)" "http://example.com:443"

# --- label_to_filename() ---
check "T30: label plain word"                       "$(label_to_filename 'foo')"              "foo"
check "T31: label uppercase → lowered"              "$(label_to_filename 'FooBar')"            "foobar"
check "T32: label spaces → underscores"             "$(label_to_filename 'foo bar baz')"       "foo_bar_baz"
check "T33: label parens/brackets stripped"         "$(label_to_filename 'foo (bar) [baz]')"   "foo_bar_baz"
check "T34: label dollar/dot stripped"              "$(label_to_filename 'JSON $ne null')"     "json_ne_null"
check "T35: label real variant name"                "$(label_to_filename 'form user[] pass[] (PHP both)')" "form_user_pass_php_both"

# --- is_fail() ---
new_workdir
FAIL_STATUS='200'
FAIL_MARKER='login-fail-marker-xyz'

printf 'some body <html>login-fail-marker-xyz</html>' > "$WORK_DIR/t.body"
if is_fail "200" "$WORK_DIR/t.body"; then rc=match; else rc=nomatch; fi
check "T40: is_fail: matching status + matching marker → match" "$rc" "match"

if is_fail "302" "$WORK_DIR/t.body"; then rc=match; else rc=nomatch; fi
check "T41: is_fail: wrong status + matching marker → nomatch" "$rc" "nomatch"

printf 'some body without the token' > "$WORK_DIR/t.body"
if is_fail "200" "$WORK_DIR/t.body"; then rc=match; else rc=nomatch; fi
check "T42: is_fail: matching status + no marker → nomatch" "$rc" "nomatch"

printf '' > "$WORK_DIR/t.body"
if is_fail "200" "$WORK_DIR/t.body"; then rc=match; else rc=nomatch; fi
check "T43: is_fail: matching status + empty body → nomatch" "$rc" "nomatch"

FAIL_MARKER='foo.*bar[baz]{1,2}'
printf 'body contains foo.*bar[baz]{1,2} literally' > "$WORK_DIR/t.body"
if is_fail "200" "$WORK_DIR/t.body"; then rc=match; else rc=nomatch; fi
check "T44: is_fail: regex metachars in marker treated literally (grep -F)" "$rc" "match"

FAIL_MARKER='input type="password" required'
printf '<form><input type="password" required></form>' > "$WORK_DIR/t.body"
if is_fail "200" "$WORK_DIR/t.body"; then rc=match; else rc=nomatch; fi
check "T45: is_fail: marker with double quotes matches" "$rc" "match"

FAIL_MARKER='-dashprefix-marker'
printf 'body has -dashprefix-marker in it' > "$WORK_DIR/t.body"
if is_fail "200" "$WORK_DIR/t.body"; then rc=match; else rc=nomatch; fi
check "T46: is_fail: dash-prefixed marker (-- guard works)" "$rc" "match"

FAIL_MARKER="don't panic please"
printf "the page says don't panic please to users" > "$WORK_DIR/t.body"
if is_fail "200" "$WORK_DIR/t.body"; then rc=match; else rc=nomatch; fi
check "T47: is_fail: single-quote in marker matches" "$rc" "match"

# --- get_meta() ---
new_workdir
printf 'status=200|size=15267|type=text/html; charset=UTF-8\n' > "$WORK_DIR/s.meta"
check "T50: get_meta status"                     "$(get_meta s status)" "200"
check "T51: get_meta size"                       "$(get_meta s size)"   "15267"
check "T52: get_meta type"                       "$(get_meta s type)"   "text/html; charset=UTF-8"
check "T53: get_meta missing key → empty"        "$(get_meta s foobar)" ""
check "T54: get_meta missing file → empty"       "$(get_meta nonexistent status)" ""

# --- check_rate_limited() ---
new_workdir
printf 'status=429|size=100|type=text/html\n' > "$WORK_DIR/rl.meta"
printf 'you are being throttled' > "$WORK_DIR/rl.body"
out=$(check_rate_limited rl); rc=$?
check          "T60a: rate-limited by status 429 returns 0"  "$rc"  "0"
check_contains "T60b: rate-limited by status 429 message"    "$out" "status=429"

printf 'status=200|size=100|type=text/html\n' > "$WORK_DIR/rl.meta"
printf 'Too Many Attempts detected for this IP' > "$WORK_DIR/rl.body"
out=$(check_rate_limited rl); rc=$?
check          "T61a: rate-limited by body pattern returns 0" "$rc"  "0"
check_contains "T61b: rate-limited by body pattern message"   "$out" "body_matched"

printf 'status=200|size=100|type=text/html\n' > "$WORK_DIR/rl.meta"
printf 'ordinary response body no rate-limit words' > "$WORK_DIR/rl.body"
out=$(check_rate_limited rl); rc=$?
check "T62: not rate-limited returns 1" "$rc" "1"

# Rate-limit pattern coverage — one test per pattern
new_workdir
for pattern in "too many attempts" "too many requests" "rate limit" "rate-limited" "slow down" "try again later" "temporarily unavailable"; do
    printf 'status=200|size=100|type=text/html\n' > "$WORK_DIR/rl.meta"
    printf 'body says %s here' "$pattern" > "$WORK_DIR/rl.body"
    out=$(check_rate_limited rl); rc=$?
    check "T63: rate-limit pattern '$pattern' triggers" "$rc" "0"
done

# ==============================================================================
# 3. Integration (embedded mock; skipped if python3 unavailable or port busy)
# ==============================================================================

if ! command -v python3 >/dev/null 2>&1; then
    SKIPPED=$((SKIPPED+15))
    echo "SKIP: python3 not available — integration tests (T80-T104) skipped"
else
    MOCK_PORT=18099

    # Check port free
    if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q ":${MOCK_PORT} "; then
        SKIPPED=$((SKIPPED+15))
        echo "SKIP: port $MOCK_PORT in use — integration tests skipped"
    else
        # Write embedded mock server (Python http.server, simulates PHP-style login)
        MOCK_PY=$(mktemp --suffix=.py)
        cat > "$MOCK_PY" <<'PYEOF'
"""Embedded mock: PHP-style login form, simulates realistic tampering outcomes."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse, sys

FAIL_MARKER = 'input type="password" class="form-control" name="password" placeholder="Enter your password" required'
FAIL_BODY = f'<html><body><div>Invalid email or password.</div><form>{FAIL_MARKER}</form></body></html>'

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _fail(self):
        self.send_response(200); self.send_header('Content-Type','text/html'); self.end_headers()
        self.wfile.write(FAIL_BODY.encode())
    def _bypass(self):
        self.send_response(302); self.send_header('Location','/dashboard')
        self.send_header('Set-Cookie','AUTH=abc; Path=/'); self.end_headers()
    def _500(self):
        self.send_response(500); self.send_header('Content-Type','text/html'); self.end_headers()
        self.wfile.write(b'<html><body>Internal Server Error</body></html>')
    def _405(self):
        self.send_response(405); self.end_headers()
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        ct = self.headers.get('Content-Type', '')
        if 'json' in ct.lower():
            self._fail(); return
        parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
        if 'email[]' in body or 'password[]' in body:
            self._bypass(); return
        if 'password' not in parsed:
            self._500(); return
        self._fail()
    def do_GET(self): self._405()
    def do_PUT(self): self._405()

port = int(sys.argv[1]) if len(sys.argv) > 1 else 18099
HTTPServer(('127.0.0.1', port), H).serve_forever()
PYEOF

        python3 "$MOCK_PY" $MOCK_PORT > /tmp/mock_${MOCK_PORT}.log 2>&1 &
        CLEANUP_MOCK_PID=$!
        sleep 0.5

        if ! curl -s -o /dev/null --max-time 2 "http://127.0.0.1:${MOCK_PORT}/login.php"; then
            SKIPPED=$((SKIPPED+15))
            echo "SKIP: mock server failed to start — integration tests skipped"
            cat /tmp/mock_${MOCK_PORT}.log
        else
            out=$(bash "$PTP" \
                --host=127.0.0.1 --port=$MOCK_PORT \
                --form-action=/login.php \
                --user-field=email --pass-field=password \
                --fail-status=200 \
                --fail-marker='input type="password" class="form-control" name="password" placeholder="Enter your password" required' \
                2>&1)

            check_contains "T80: run-config box emitted"       "$out" "parameter_tampering_probe.sh — run config"
            check_contains "T81: coverage warnings emitted"    "$out" "COVERAGE WARNINGS"
            check_contains "T82: baseline OK marker emitted"   "$out" "BASELINE_OK"
            check_contains "T83: PHP array bypass → CHECK"     "$out" "CHECK [302][0] form user[]=arr (PHP)"
            check_contains "T84: missing pass → CHECK"         "$out" "CHECK [500][47] form pass field absent"
            check_contains "T85: GET → CHECK"                  "$out" "CHECK [405][0] GET query string"
            check_contains "T86: PUT → CHECK"                  "$out" "CHECK [405][0] PUT form body"
            check_contains "T87: JSON pass=true → fail (PHP)"  "$out" "fail  [200]"
            check_contains "T88: summary variants=14"          "$out" "variants=14"
            check_contains "T89: ROUTE verify_candidates"      "$out" "ROUTE: verify_candidates"

            # Baseline mismatch → BAIL
            out=$(bash "$PTP" \
                --host=127.0.0.1 --port=$MOCK_PORT \
                --form-action=/login.php \
                --user-field=email --pass-field=password \
                --fail-status=200 \
                --fail-marker='definitely_not_in_response_xyz' \
                2>&1)
            check_contains "T90: baseline marker mismatch → BAIL"  "$out" "BAIL: baseline"
            check_contains "T91: BAIL includes actionable next step" "$out" "re-run auth_oracle_probe.sh"

            # Baseline status mismatch → BAIL
            out=$(bash "$PTP" \
                --host=127.0.0.1 --port=$MOCK_PORT \
                --form-action=/login.php \
                --user-field=email --pass-field=password \
                --fail-status=404 \
                --fail-marker='input type="password" class="form-control" name="password" placeholder="Enter your password" required' \
                2>&1)
            check_contains "T92: baseline status mismatch → BAIL"  "$out" "BAIL: baseline"

            # Forwarded state flags threaded through
            out=$(bash "$PTP" \
                --host=127.0.0.1 --port=$MOCK_PORT \
                --form-action=/login.php \
                --user-field=email --pass-field=password \
                --fail-status=200 \
                --fail-marker='input type="password" class="form-control" name="password" placeholder="Enter your password" required' \
                --cookies='TEST=1; ANOTHER=2' \
                --hidden-fields='csrf=abc123' \
                --extra-headers='X-Test: 1' \
                2>&1)
            check_contains "T93: cookies flag threaded"        "$out" "TEST=1; ANOTHER=2"
            check_contains "T94: hidden-fields flag threaded"  "$out" "csrf=abc123"
            check_contains "T95: extra-headers flag threaded"  "$out" "X-Test: 1"
        fi

        rm -f "$MOCK_PY"
    fi
fi

# ==============================================================================
# Summary
# ==============================================================================

echo ""
echo "============================="
printf "PASSED:  %d\n" "$PASSED"
printf "FAILED:  %d\n" "$FAILED"
printf "SKIPPED: %d\n" "$SKIPPED"
echo "============================="

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "Failed tests:"
    for t in "${failed_names[@]}"; do
        echo "  - $t"
    done
    exit 1
fi

exit 0
