#!/bin/bash
# statefulness_probe.tests.sh
#
# Regression suite for statefulness_probe.sh v1.
#
# Usage:
#   ./statefulness_probe.tests.sh                    # uses ~/scripts/statefulness_probe.sh
#   SP=/path/to/statefulness_probe.sh ./tests        # override path
#
# Not covered (require network / live target — Phase 5 live-target validation):
#   - get_page (HTTP sampling)
#   - sample_all (bail-on-curl-error path)
#   - Redirect chain accumulation of Set-Cookie
#   - Cookie-jar chain semantics against real server

set -u

# ==============================================================================
# Setup
# ==============================================================================

SP="${SP:-$HOME/scripts/statefulness_probe.sh}"

if [ ! -f "$SP" ]; then
    echo "ERROR: script not found at $SP" >&2
    echo "Override with: SP=<path> $0" >&2
    exit 2
fi

# Source for unit tests (main() gated by BASH_SOURCE guard — will not run)
source "$SP"
set +u

echo "Testing: $SP"
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

trap '[ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ] && rm -rf "$WORK_DIR"' EXIT

# ==============================================================================
# 1. Argument validation (subprocess)
# ==============================================================================

out=$(bash "$SP" --port=80 --path=/x 2>&1); rc=$?
check          "T1a: missing --host exits 1"                "$rc"  "1"
check_contains "T1b: missing --host message"                "$out" "ERROR: --host required"

out=$(bash "$SP" --host=localhost --path=/x 2>&1); rc=$?
check          "T2a: missing --port exits 1"                "$rc"  "1"
check_contains "T2b: missing --port message"                "$out" "ERROR: --port required"

out=$(bash "$SP" --host=localhost --port=80 2>&1); rc=$?
check          "T3a: missing --path exits 1"                "$rc"  "1"
check_contains "T3b: missing --path message"                "$out" "ERROR: --path required"

out=$(bash "$SP" --host=localhost --port=80 --path=login.php 2>&1); rc=$?
check          "T4a: --path without leading / exits 1"      "$rc"  "1"
check_contains "T4b: --path without leading / message"      "$out" "must start with /"

out=$(bash "$SP" --host=localhost --port=80 --path=/x --scheme=ftp 2>&1); rc=$?
check          "T5a: invalid --scheme exits 1"              "$rc"  "1"
check_contains "T5b: invalid --scheme message"              "$out" "invalid scheme"

out=$(bash "$SP" --host=localhost --port=80 --path=/x --delay=abc 2>&1); rc=$?
check          "T6a: non-numeric --delay exits 1"           "$rc"  "1"
check_contains "T6b: non-numeric --delay message"           "$out" "must be non-negative integer"

out=$(bash "$SP" --host=localhost --port=80 --path=/x --delay=-1 2>&1); rc=$?
check          "T7: negative --delay exits 1"               "$rc"  "1"

out=$(bash "$SP" --unknown 2>&1); rc=$?
check          "T8a: unknown flag exits 1"                  "$rc"  "1"
check_contains "T8b: unknown flag message"                  "$out" "unknown argument"

out=$(bash "$SP" --help 2>&1)
check_contains "T9: --help prints usage"                    "$out" "Usage:"

# ==============================================================================
# 2. parse_set_cookies
# ==============================================================================

new_workdir

cat > "$WORK_DIR/h.hdr" <<'EOF'
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: SESSID=abc123; Path=/; HttpOnly

EOF
check "T10: cookies: single, attrs stripped" \
      "$(parse_set_cookies "$WORK_DIR/h.hdr")" \
      "SESSID=abc123"

cat > "$WORK_DIR/h.hdr" <<'EOF'
HTTP/1.1 200 OK
Set-Cookie: SESSID=abc; Path=/
Set-Cookie: CSRF=xyz; SameSite=Lax; Secure
Set-Cookie: pref=en-GB

EOF
expected=$'SESSID=abc\nCSRF=xyz\npref=en-GB'
check "T11: cookies: multiple with mixed attrs" \
      "$(parse_set_cookies "$WORK_DIR/h.hdr")" \
      "$expected"

cat > "$WORK_DIR/h.hdr" <<'EOF'
HTTP/1.1 200 OK
Set-Cookie: token=abc=def=; Path=/

EOF
check "T12: cookies: value with = signs preserved" \
      "$(parse_set_cookies "$WORK_DIR/h.hdr")" \
      "token=abc=def="

cat > "$WORK_DIR/h.hdr" <<'EOF'
HTTP/1.1 200 OK
Set-Cookie: SESSID=; Path=/; Max-Age=0

EOF
check "T13: cookies: empty value (deletion pattern)" \
      "$(parse_set_cookies "$WORK_DIR/h.hdr")" \
      "SESSID="

cat > "$WORK_DIR/h.hdr" <<'EOF'
HTTP/1.1 200 OK
Content-Type: text/html

EOF
check "T14: cookies: no Set-Cookie → empty" \
      "$(parse_set_cookies "$WORK_DIR/h.hdr")" \
      ""

cat > "$WORK_DIR/h.hdr" <<'EOF'
HTTP/1.1 200 OK
set-cookie: SESSID=abc

EOF
check "T15: cookies: lowercase set-cookie matched" \
      "$(parse_set_cookies "$WORK_DIR/h.hdr")" \
      "SESSID=abc"

cat > "$WORK_DIR/h.hdr" <<'EOF'
HTTP/1.1 200 OK
SET-COOKIE: A=1
Set-cookie: B=2
sEt-CoOkIe: C=3

EOF
expected=$'A=1\nB=2\nC=3'
check "T16: cookies: mixed-case header names" \
      "$(parse_set_cookies "$WORK_DIR/h.hdr")" \
      "$expected"

printf 'HTTP/1.1 200 OK\r\nSet-Cookie: SESSID=abc; Path=/\r\n\r\n' > "$WORK_DIR/h.hdr"
check "T17: cookies: CRLF line endings" \
      "$(parse_set_cookies "$WORK_DIR/h.hdr")" \
      "SESSID=abc"

cat > "$WORK_DIR/h.hdr" <<'EOF'
HTTP/1.1 200 OK
Set-Cookie: justflags; Path=/

EOF
check "T18: cookies: malformed (no name=value) skipped" \
      "$(parse_set_cookies "$WORK_DIR/h.hdr")" \
      ""

cat > "$WORK_DIR/h.hdr" <<'EOF'
HTTP/1.1 302 Found
Location: /login
Set-Cookie: SESSID=abc

HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: CSRF=xyz

EOF
expected=$'SESSID=abc\nCSRF=xyz'
check "T19: cookies: redirect chain cumulative Set-Cookie" \
      "$(parse_set_cookies "$WORK_DIR/h.hdr")" \
      "$expected"

# ==============================================================================
# 3. parse_hidden_fields
# ==============================================================================

cat > "$WORK_DIR/b.html" <<'EOF'
<html><body>
<form action="/login">
<input type="hidden" name="csrf_token" value="abc123">
<input type="text" name="username">
<input type="password" name="password">
</form>
</body></html>
EOF
check "T20: hidden: single field, ignores non-hidden input types" \
      "$(parse_hidden_fields "$WORK_DIR/b.html")" \
      "csrf_token=abc123"

cat > "$WORK_DIR/b.html" <<'EOF'
<input type="hidden" name="a" value="1">
<input name="b" type="hidden" value="2">
<input value="3" type="hidden" name="c">
EOF
expected=$'a=1\nb=2\nc=3'
check "T21: hidden: attribute order variance" \
      "$(parse_hidden_fields "$WORK_DIR/b.html" | sort)" \
      "$expected"

cat > "$WORK_DIR/b.html" <<'EOF'
<input type='hidden' name='x' value='1'>
<input type="hidden" name="y" value="2">
EOF
expected=$'x=1\ny=2'
check "T22: hidden: single AND double quote delimiters" \
      "$(parse_hidden_fields "$WORK_DIR/b.html" | sort)" \
      "$expected"

cat > "$WORK_DIR/b.html" <<'EOF'
<input type=hidden name=uq value=raw>
EOF
check "T23: hidden: unquoted attributes" \
      "$(parse_hidden_fields "$WORK_DIR/b.html")" \
      "uq=raw"

cat > "$WORK_DIR/b.html" <<'EOF'
<input type="hidden" name="t" value="a&amp;b">
<input type="hidden" name="u" value="a&quot;b">
<input type="hidden" name="v" value="a&lt;b&gt;c">
<input type="hidden" name="w" value="a&#39;b">
<input type="hidden" name="x" value="a&apos;b">
EOF
expected='t=a&b
u=a"b
v=a<b>c
w=a'\''b
x=a'\''b'
check "T24: hidden: HTML entity decoding (&amp; &quot; &lt; &gt; &#39; &apos;)" \
      "$(parse_hidden_fields "$WORK_DIR/b.html" | sort)" \
      "$expected"

cat > "$WORK_DIR/b.html" <<'EOF'
<input type="hidden" name="x" value="">
<input type="hidden" name="y">
EOF
expected=$'x=\ny='
check "T25: hidden: empty and absent value attribute" \
      "$(parse_hidden_fields "$WORK_DIR/b.html" | sort)" \
      "$expected"

cat > "$WORK_DIR/b.html" <<'EOF'
<!-- <input type="hidden" name="commented" value="skipme"> -->
<input type="hidden" name="real" value="keepme">
EOF
check "T26: hidden: comment contents ignored" \
      "$(parse_hidden_fields "$WORK_DIR/b.html")" \
      "real=keepme"

cat > "$WORK_DIR/b.html" <<'EOF'
<script>var x = '<input type="hidden" name="scripty" value="skipme">';</script>
<input type="hidden" name="real" value="keepme">
EOF
check "T27: hidden: script contents ignored" \
      "$(parse_hidden_fields "$WORK_DIR/b.html")" \
      "real=keepme"

cat > "$WORK_DIR/b.html" <<'EOF'
<input type="hidden" name="xhtml" value="closed" />
EOF
check "T28: hidden: XHTML self-closing tag" \
      "$(parse_hidden_fields "$WORK_DIR/b.html")" \
      "xhtml=closed"

cat > "$WORK_DIR/b.html" <<'EOF'
<form>
<input type="text" name="user">
<input type="password" name="pass">
</form>
EOF
check "T29: hidden: no hidden fields → empty" \
      "$(parse_hidden_fields "$WORK_DIR/b.html")" \
      ""

cat > "$WORK_DIR/b.html" <<'EOF'
<input type="hidden" name="token" value="a=b=c">
<input type="hidden" name="url" value="http://x.com/?q=1&r=2">
EOF
expected='token=a=b=c
url=http://x.com/?q=1&r=2'
check "T30: hidden: value with = and & preserved" \
      "$(parse_hidden_fields "$WORK_DIR/b.html" | sort)" \
      "$expected"

cat > "$WORK_DIR/b.html" <<'EOF'
<input type="HIDDEN" name="a" value="1">
<input type="Hidden" name="b" value="2">
<input type="hIdDeN" name="c" value="3">
EOF
expected=$'a=1\nb=2\nc=3'
check "T31: hidden: type attribute case-insensitive" \
      "$(parse_hidden_fields "$WORK_DIR/b.html" | sort)" \
      "$expected"

cat > "$WORK_DIR/b.html" <<'EOF'
<input type="hidden" name="multiline" value="line1
line2">
EOF
check "T32: hidden: newline in value → space (line integrity preserved)" \
      "$(parse_hidden_fields "$WORK_DIR/b.html")" \
      "multiline=line1 line2"

cat > "$WORK_DIR/b.html" <<'EOF'
<input type="hidden" name="a" value="1">
<input type="hidden" name="b" value="2">
<input type="hidden" name="c" value="3">
<input type="hidden" name="d" value="4">
<input type="hidden" name="e" value="5">
EOF
check "T33: hidden: 5 fields all extracted" \
      "$(parse_hidden_fields "$WORK_DIR/b.html" | wc -l)" \
      "5"

cat > "$WORK_DIR/b.html" <<'EOF'
<input   type="hidden"		name="ws"    value="tab and space">
EOF
check "T34: hidden: extra whitespace/tabs between attributes" \
      "$(parse_hidden_fields "$WORK_DIR/b.html")" \
      "ws=tab and space"

# ==============================================================================
# 4. urlencode
# ==============================================================================

check "T35: urlencode: alnum passthrough"        "$(urlencode 'abc123XYZ')"    "abc123XYZ"
check "T36: urlencode: space encoded"            "$(urlencode 'a b')"          "a%20b"
check "T37: urlencode: ampersand"                "$(urlencode 'a&b')"          "a%26b"
check "T38: urlencode: equals"                   "$(urlencode 'a=b')"          "a%3Db"
check "T39: urlencode: percent"                  "$(urlencode 'a%b')"          "a%25b"
check "T40: urlencode: unreserved preserved"     "$(urlencode 'a-b_c.d~e')"    "a-b_c.d~e"
check "T41: urlencode: empty string"             "$(urlencode '')"             ""
check "T42: urlencode: slash"                    "$(urlencode 'a/b')"          "a%2Fb"
check "T43: urlencode: plus"                     "$(urlencode 'a+b')"          "a%2Bb"
check "T44: urlencode: hash"                     "$(urlencode 'a#b')"          "a%23b"
check "T45: urlencode: multiple specials"        "$(urlencode 'a&b=c d')"      "a%26b%3Dc%20d"

# ==============================================================================
# 5. Rate-limit detection
# ==============================================================================

new_workdir

# 429 status
echo "status=429|size=100|type=text/html" > "$WORK_DIR/get1.meta"
echo "throttled" > "$WORK_DIR/get1.body"
out=$(check_rate_limited get1); rc=$?
check "T46a: rate-limit: 429 status returns 0"    "$rc"  "0"
check "T46b: rate-limit: 429 message"             "$out" "RATE_LIMITED: sample=get1 status=429"

# All 7 body patterns
patterns=("too many attempts" "too many requests" "rate limit" "rate-limited" "slow down" "try again later" "temporarily unavailable")
t=47
for p in "${patterns[@]}"; do
    echo "status=200|size=100|type=text/html" > "$WORK_DIR/get1.meta"
    echo "server says: $p, please wait" > "$WORK_DIR/get1.body"
    out=$(check_rate_limited get1); rc=$?
    check          "T${t}a: rate-limit: body pattern '$p' returns 0" "$rc"  "0"
    check_contains "T${t}b: rate-limit: body pattern '$p' message"   "$out" "body_matched='$p'"
    t=$((t+1))
done

# Benign 200 + benign body
echo "status=200|size=1234|type=text/html" > "$WORK_DIR/get1.meta"
echo "<html><body><form><input type=hidden name=csrf value=abc></form></body></html>" > "$WORK_DIR/get1.body"
out=$(check_rate_limited get1); rc=$?
check "T54a: rate-limit: benign 200+body returns 1 (no throttle)" "$rc"  "1"
check "T54b: rate-limit: benign 200+body no output"               "$out" ""

# Case-insensitive
echo "status=200|size=100|type=text/html" > "$WORK_DIR/get1.meta"
echo "TOO MANY ATTEMPTS" > "$WORK_DIR/get1.body"
out=$(check_rate_limited get1); rc=$?
check "T55: rate-limit: pattern case-insensitive" "$rc" "0"

# ==============================================================================
# 6. check_bail_status
# ==============================================================================

# BAIL on client/server errors
bail_codes=(400 401 403 404 500 502 503)
t=56
for code in "${bail_codes[@]}"; do
    echo "status=$code|size=0|type=text/html" > "$WORK_DIR/get1.meta"
    echo -n "" > "$WORK_DIR/get1.body"
    out=$(check_bail_status get1); rc=$?
    check          "T${t}a: bail-status: $code returns 0" "$rc"  "0"
    check_contains "T${t}b: bail-status: $code message"   "$out" "status=$code"
    t=$((t+1))
done

# OK: 2xx/3xx
ok_codes=(200 201 204 301 302 303 307 308)
t=63
for code in "${ok_codes[@]}"; do
    echo "status=$code|size=0|type=text/html" > "$WORK_DIR/get1.meta"
    check_bail_status get1; rc=$?
    check "T${t}: bail-status: $code accepted (no bail)" "$rc" "1"
    t=$((t+1))
done

# ==============================================================================
# 7. check_bail_content_type
# ==============================================================================

# BAIL on non-HTML content-types
bail_types=(
    "application/json"
    "application/json; charset=utf-8"
    "application/xml"
    "image/png"
    "image/jpeg"
    "application/pdf"
    "application/octet-stream"
    "video/mp4"
    "audio/mpeg"
)
t=71
for ct in "${bail_types[@]}"; do
    echo "status=200|size=100|type=$ct" > "$WORK_DIR/get1.meta"
    out=$(check_bail_content_type get1); rc=$?
    check          "T${t}a: bail-ct: '$ct' returns 0" "$rc"  "0"
    check_contains "T${t}b: bail-ct: '$ct' message"   "$out" "type=$ct"
    t=$((t+1))
done

# ACCEPT HTML and HTML-adjacent
ok_types=(
    "text/html"
    "text/html; charset=utf-8"
    "application/xhtml+xml"
    "text/plain"
    ""
)
t=80
for ct in "${ok_types[@]}"; do
    echo "status=200|size=100|type=$ct" > "$WORK_DIR/get1.meta"
    check_bail_content_type get1; rc=$?
    check "T${t}: bail-ct: '$ct' accepted (no bail)" "$rc" "1"
    t=$((t+1))
done

# ==============================================================================
# 8. classify_cookies
# ==============================================================================

# Type A: no state either side
echo -n "" > "$WORK_DIR/get1.cookies"
echo -n "" > "$WORK_DIR/get2.cookies"
classify_cookies
check "T85a: classify-cookies A: empty→static empty"   "$(cat "$WORK_DIR/static.cookies")"   ""
check "T85b: classify-cookies A: empty→rotating empty" "$(cat "$WORK_DIR/rotating.cookies")" ""
check "T85c: classify-cookies A: empty→new empty"      "$(cat "$WORK_DIR/new.cookies")"      ""

# Type B: silent GET#2 → static
echo "SESSID=abc" > "$WORK_DIR/get1.cookies"
echo -n ""        > "$WORK_DIR/get2.cookies"
classify_cookies
check "T86: classify-cookies B: silent GET#2 → STATIC" "$(cat "$WORK_DIR/static.cookies")" "SESSID=abc"

# Type C: same value (touch/refresh)
echo "SESSID=abc" > "$WORK_DIR/get1.cookies"
echo "SESSID=abc" > "$WORK_DIR/get2.cookies"
classify_cookies
check "T87a: classify-cookies C: same value → STATIC"    "$(cat "$WORK_DIR/static.cookies")"   "SESSID=abc"
check "T87b: classify-cookies C: same value → no rotate" "$(cat "$WORK_DIR/rotating.cookies")" ""

# Type D: different value (rotation)
echo "SESSID=abc" > "$WORK_DIR/get1.cookies"
echo "SESSID=xyz" > "$WORK_DIR/get2.cookies"
classify_cookies
check "T88a: classify-cookies D: diff value → no static"  "$(cat "$WORK_DIR/static.cookies")"   ""
check "T88b: classify-cookies D: diff value → ROTATING"   "$(cat "$WORK_DIR/rotating.cookies")" "SESSID"

# Type E: new cookie on GET#2 (progressive state)
echo "SESSID=abc"                > "$WORK_DIR/get1.cookies"
printf 'SESSID=abc\nCSRF=new\n'  > "$WORK_DIR/get2.cookies"
classify_cookies
check "T89a: classify-cookies E: existing unchanged in static" "$(cat "$WORK_DIR/static.cookies")" "SESSID=abc"
check "T89b: classify-cookies E: new cookie in new list"       "$(cat "$WORK_DIR/new.cookies")"    "CSRF"

# Type F: mixed
printf 'SESSID=stay\nCSRF=old\n'          > "$WORK_DIR/get1.cookies"
printf 'SESSID=stay\nCSRF=new\nEXTRA=x\n' > "$WORK_DIR/get2.cookies"
classify_cookies
check "T90a: classify-cookies F: static line"   "$(cat "$WORK_DIR/static.cookies")"   "SESSID=stay"
check "T90b: classify-cookies F: rotating line" "$(cat "$WORK_DIR/rotating.cookies")" "CSRF"
check "T90c: classify-cookies F: new line"      "$(cat "$WORK_DIR/new.cookies")"      "EXTRA"

# Sort determinism
printf 'zeta=1\nalpha=2\nmiddle=3\n' > "$WORK_DIR/get1.cookies"
printf 'zeta=1\nalpha=2\nmiddle=3\n' > "$WORK_DIR/get2.cookies"
classify_cookies
expected=$'alpha=2\nmiddle=3\nzeta=1'
check "T91: classify-cookies: static output sorted (determinism)" \
      "$(cat "$WORK_DIR/static.cookies")" "$expected"

# Cookie deletion (Max-Age=0 → empty value emitted → differs from prior value)
echo "SESSID=abc" > "$WORK_DIR/get1.cookies"
echo "SESSID="    > "$WORK_DIR/get2.cookies"
classify_cookies
check "T92: classify-cookies: deletion (empty value) treated as ROTATING" \
      "$(cat "$WORK_DIR/rotating.cookies")" "SESSID"

# ==============================================================================
# 9. classify_hidden_fields
# ==============================================================================

echo "csrf=abc" > "$WORK_DIR/get1.hidden"
echo "csrf=abc" > "$WORK_DIR/get2.hidden"
classify_hidden_fields
check "T93: classify-hidden: identical → STATIC" \
      "$(cat "$WORK_DIR/static.hidden")" "csrf=abc"

echo "csrf=abc" > "$WORK_DIR/get1.hidden"
echo "csrf=xyz" > "$WORK_DIR/get2.hidden"
classify_hidden_fields
check "T94: classify-hidden: diff value → ROTATING" \
      "$(cat "$WORK_DIR/rotating.hidden")" "csrf"

echo "csrf=abc" > "$WORK_DIR/get1.hidden"
echo -n ""     > "$WORK_DIR/get2.hidden"
classify_hidden_fields
check "T95: classify-hidden: absent GET#2 → ROTATING" \
      "$(cat "$WORK_DIR/rotating.hidden")" "csrf"

echo -n ""       > "$WORK_DIR/get1.hidden"
echo "csrf=new"  > "$WORK_DIR/get2.hidden"
classify_hidden_fields
check "T96: classify-hidden: appears GET#2 → NEW" \
      "$(cat "$WORK_DIR/new.hidden")" "csrf"

printf 'z=1\na=2\nm=3\n' > "$WORK_DIR/get1.hidden"
printf 'z=1\na=2\nm=3\n' > "$WORK_DIR/get2.hidden"
classify_hidden_fields
expected=$'a=2\nm=3\nz=1'
check "T97: classify-hidden: sorted output" \
      "$(cat "$WORK_DIR/static.hidden")" "$expected"

# ==============================================================================
# 10. Emission helpers
# ==============================================================================

printf 'a=1\nb=2\nc=3\n' > "$WORK_DIR/static.cookies"
check "T98: emit-static-cookies: multi-value joined with '; '" \
      "$(emit_static_cookies)" "STATIC_COOKIES: a=1; b=2; c=3"

echo -n "" > "$WORK_DIR/static.cookies"
check "T99: emit-static-cookies: empty → 'STATIC_COOKIES: '" \
      "$(emit_static_cookies)" "STATIC_COOKIES: "

printf 'a=1\nb=2\n' > "$WORK_DIR/static.hidden"
check "T100: emit-static-hidden: multi-field joined with '&'" \
      "$(emit_static_hidden)" "STATIC_HIDDEN_FIELDS: a=1&b=2"

echo "csrf=a&b=c" > "$WORK_DIR/static.hidden"
check "T101: emit-static-hidden: URL-encodes special chars in value" \
      "$(emit_static_hidden)" "STATIC_HIDDEN_FIELDS: csrf=a%26b%3Dc"

echo "my field=value" > "$WORK_DIR/static.hidden"
check "T102: emit-static-hidden: URL-encodes name" \
      "$(emit_static_hidden)" "STATIC_HIDDEN_FIELDS: my%20field=value"

echo -n "" > "$WORK_DIR/static.hidden"
check "T103: emit-static-hidden: empty → 'STATIC_HIDDEN_FIELDS: '" \
      "$(emit_static_hidden)" "STATIC_HIDDEN_FIELDS: "

printf 'a\nb\nc\n' > "$WORK_DIR/rotating.cookies"
check "T104: emit-names: multi-name joined with ', '" \
      "$(emit_names "ROTATING_COOKIES" "$WORK_DIR/rotating.cookies")" "ROTATING_COOKIES: a, b, c"

echo -n "" > "$WORK_DIR/rotating.cookies"
check "T105: emit-names: empty → 'LABEL: '" \
      "$(emit_names "ROTATING_COOKIES" "$WORK_DIR/rotating.cookies")" "ROTATING_COOKIES: "

check "T106: emit-coverage-warnings: 5 warning bullet lines emitted" \
      "$(emit_coverage_warnings | grep -c '^- ')" "5"

warnings=$(emit_coverage_warnings)
check_contains "T107a: emit-coverage-warnings: JS tokens"          "$warnings" "JS-computed tokens"
check_contains "T107b: emit-coverage-warnings: Two-request flows"  "$warnings" "Two-request flows"
check_contains "T107c: emit-coverage-warnings: Bot-detection"      "$warnings" "Bot-detection"
check_contains "T107d: emit-coverage-warnings: Custom JS headers"  "$warnings" "Custom JS-set request headers"
check_contains "T107e: emit-coverage-warnings: POST-response state rotation"  "$warnings" "POST-response state rotation"

# ==============================================================================
# 11. Route decision integration
# ==============================================================================

# Shell scenario: all state static/absent
echo "SESSID=abc" > "$WORK_DIR/get1.cookies"
echo "SESSID=abc" > "$WORK_DIR/get2.cookies"
echo -n ""        > "$WORK_DIR/get1.hidden"
echo -n ""        > "$WORK_DIR/get2.hidden"
classify_cookies
classify_hidden_fields
full=$(emit_all)
check "T108a: route: shell scenario ROUTE line" \
      "$(echo "$full" | grep '^ROUTE:')" "ROUTE: shell"
check "T108b: route: shell scenario ROUTE_REASON (always populated)" \
      "$(echo "$full" | grep '^ROUTE_REASON:')" \
      "ROUTE_REASON: all state carriers static (or none present)"

# Only rotating hidden
echo -n ""    > "$WORK_DIR/get1.cookies"
echo -n ""    > "$WORK_DIR/get2.cookies"
echo "csrf=a" > "$WORK_DIR/get1.hidden"
echo "csrf=b" > "$WORK_DIR/get2.hidden"
classify_cookies
classify_hidden_fields
full=$(emit_all)
check "T109a: route: rotating hidden ROUTE=burp" \
      "$(echo "$full" | grep '^ROUTE:')" "ROUTE: burp"
check "T109b: route: rotating hidden REASON" \
      "$(echo "$full" | grep '^ROUTE_REASON:')" "ROUTE_REASON: hidden fields rotate: csrf"

# Only rotating cookies
echo "SESSID=old" > "$WORK_DIR/get1.cookies"
echo "SESSID=new" > "$WORK_DIR/get2.cookies"
echo -n ""        > "$WORK_DIR/get1.hidden"
echo -n ""        > "$WORK_DIR/get2.hidden"
classify_cookies
classify_hidden_fields
check "T110: route: rotating cookies REASON" \
      "$(emit_all | grep '^ROUTE_REASON:')" "ROUTE_REASON: cookies rotate: SESSID"

# Only new cookies on GET#2
echo -n ""            > "$WORK_DIR/get1.cookies"
echo "SESSID=fresh"   > "$WORK_DIR/get2.cookies"
echo -n ""            > "$WORK_DIR/get1.hidden"
echo -n ""            > "$WORK_DIR/get2.hidden"
classify_cookies
classify_hidden_fields
check "T111: route: new cookies GET#2 REASON" \
      "$(emit_all | grep '^ROUTE_REASON:')" "ROUTE_REASON: new cookies on GET#2: SESSID"

# Only new hidden on GET#2
echo -n ""       > "$WORK_DIR/get1.cookies"
echo -n ""       > "$WORK_DIR/get2.cookies"
echo -n ""       > "$WORK_DIR/get1.hidden"
echo "csrf=new"  > "$WORK_DIR/get2.hidden"
classify_cookies
classify_hidden_fields
check "T112: route: new hidden GET#2 REASON" \
      "$(emit_all | grep '^ROUTE_REASON:')" "ROUTE_REASON: new hidden fields on GET#2: csrf"

# All four channels rotating
printf 'SESSID=old\n'        > "$WORK_DIR/get1.cookies"
printf 'SESSID=new\nNEW=x\n' > "$WORK_DIR/get2.cookies"
printf 'csrf=old\n'          > "$WORK_DIR/get1.hidden"
printf 'csrf=new\nHIDE=y\n'  > "$WORK_DIR/get2.hidden"
classify_cookies
classify_hidden_fields
check "T113: route: all four channels REASON joined with '; '" \
      "$(emit_all | grep '^ROUTE_REASON:')" \
      "ROUTE_REASON: hidden fields rotate: csrf; cookies rotate: SESSID; new hidden fields on GET#2: HIDE; new cookies on GET#2: NEW"

# Mixed static + rotating cookies
printf 'STAY=1\nGO=old\n' > "$WORK_DIR/get1.cookies"
printf 'STAY=1\nGO=new\n' > "$WORK_DIR/get2.cookies"
echo -n ""                > "$WORK_DIR/get1.hidden"
echo -n ""                > "$WORK_DIR/get2.hidden"
classify_cookies
classify_hidden_fields
full=$(emit_all)
check "T114a: route: mixed static+rotating STATIC_COOKIES" \
      "$(echo "$full" | grep '^STATIC_COOKIES:')" "STATIC_COOKIES: STAY=1"
check "T114b: route: mixed static+rotating ROTATING_COOKIES" \
      "$(echo "$full" | grep '^ROTATING_COOKIES:')" "ROTATING_COOKIES: GO"
check "T114c: route: mixed static+rotating ROUTE=burp" \
      "$(echo "$full" | grep '^ROUTE:')" "ROUTE: burp"

# Marker emit order (all empty inputs → all empty markers still emitted)
echo -n "" > "$WORK_DIR/get1.cookies"; echo -n "" > "$WORK_DIR/get2.cookies"
echo -n "" > "$WORK_DIR/get1.hidden";  echo -n "" > "$WORK_DIR/get2.hidden"
classify_cookies
classify_hidden_fields
markers=$(emit_all | grep -oE '^[A-Z0-9_]+:' | tr -d ':')
expected=$'STATIC_COOKIES\nSTATIC_HIDDEN_FIELDS\nROTATING_COOKIES\nROTATING_HIDDEN_FIELDS\nNEW_COOKIES_GET2\nNEW_HIDDEN_FIELDS_GET2\nROUTE\nROUTE_REASON'
check "T115: route: signal marker emit order (empty state)" "$markers" "$expected"

# T116: coverage warning box precedes signal — first line of emit_all is the box top border
first_line=$(emit_all | head -1)
check "T116: coverage warning box precedes signal (first line is box border)" \
      "$first_line" "=============================================================================="

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
