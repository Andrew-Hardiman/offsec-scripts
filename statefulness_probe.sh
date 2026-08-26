#!/bin/bash
# statefulness_probe.sh
#
# Enumerate all shell-forwardable auth-state carriers on a form-serving page —
# cookies (Set-Cookie / Cookie) and hidden form fields (<input type="hidden">) —
# classify each as static vs rotating via two-GET cookie-jar-chain diff, and
# emit categorised markers driving ROUTE decision.
#
# Enters from WAC 1.6 (login form), 1.7 (register form), 1.8 (forgot form)
# after form metadata capture and before technique dispatch. Form-agnostic:
# probes a GET path; does not POST; does not need form-field awareness.
#
# Usage:
#   statefulness_probe.sh --host=<h> --port=<p> --path=<p> \
#                         [--scheme=<http|https>] [--delay=<ms>] [--verbose]
#
# Required flags:
#   --host=<h>       Target hostname or IP
#   --port=<p>       Target HTTP/HTTPS port
#   --path=<p>       GET path of form-serving page (e.g. /login.php)
#
# Optional flags:
#   --scheme=<s>     http (default) or https
#   --delay=<ms>     Milliseconds between the two GETs (default 0)
#   --verbose        Preserve WORK_DIR sample dumps on exit for inspection
#
# Marker output contract:
#
#   Shell-forwardable state (always emitted; empty if none):
#     STATIC_COOKIES: <name1=val1; name2=val2>
#         Browser Cookie:-header format. Confirmed reusable across GETs.
#         Consume via curl -b, Hydra -h "Cookie: ...", ffuf -b.
#     STATIC_HIDDEN_FIELDS: <name1=val1&name2=val2>
#         URL-encoded, POST-body format. Confirmed byte-identical across GETs.
#         Consume via curl -d, ffuf -d, Hydra http-post-form field appendage.
#
#   Rotating state (always emitted; empty if none — names only, values change):
#     ROTATING_COOKIES: <name1, name2>
#         Cookies whose values differed between GET#1 and GET#2 responses
#         (server rejected the presented cookie and issued a fresh value).
#     ROTATING_HIDDEN_FIELDS: <name1, name2>
#         Hidden fields whose values differed byte-for-byte between GETs.
#     NEW_COOKIES_GET2: <name1, name2>
#         Cookies introduced by GET#2 not present in GET#1 response.
#         Treated as rotating (progressive state — shell cannot capture
#         full jar upfront).
#     NEW_HIDDEN_FIELDS_GET2: <name1, name2>
#         Hidden fields introduced by GET#2 not present in GET#1 response.
#         Treated as rotating.
#
#   Coverage warnings (always emitted FIRST — informational preamble; never affect
#   ROUTE; wrapped in a boxed section with `====` bars; bulleted lines inside the
#   box, no COVERAGE_WARNING: prefix since the box header establishes context;
#   operator's eye passes over caveats first, then lands on actionable signal below;
#   operator escalates to Burp/browser if any suspected):
#     - JS-computed tokens not detectable shell-side ...
#     - Two-request flows (email/MFA/verify) not detectable ...
#     - Bot-detection challenges (CAPTCHA/Turnstile/hCaptcha) ...
#     - Custom JS-set request headers not detectable shell-side ...
#
#   Route decision (always emitted LAST on non-bail classification):
#     ROUTE: shell | burp
#         shell = all ROTATING_* AND NEW_*_GET2 markers empty; forward
#                 STATIC_* vars via downstream POSTs.
#         burp  = any ROTATING_* or NEW_*_GET2 non-empty; escalate to
#                 [[Automating Fresh State in Burp]], using ROTATING_* +
#                 NEW_*_GET2 names for the "Update only the following
#                 parameters and headers" list.
#     ROUTE_REASON: <text>
#         On shell: "all state carriers static (or none present)"
#         On burp: which channel(s) rotated, e.g.:
#                  "hidden fields rotate: csrf_token, nonce"
#                  "cookies rotate: XSRF-TOKEN"
#                  "hidden fields rotate: csrf_token; cookies rotate: PHPSESSID"
#                  "new cookies on GET#2: session_marker"
#
#   Bail markers (mutually exclusive with ROUTE — abort before classification):
#     BAIL: <reason>
#         Fatal (curl error, non-2xx/3xx status, non-HTML content-type,
#         internal error). Sample dumps in ${WORK_DIR} preserved on --verbose.
#     RATE_LIMITED: sample=<get1|get2> <detail>
#         429 or rate-limit body pattern before contamination. Re-run with
#         higher --delay.
#
# Sampling protocol (2 requests, cookie-jar chain):
#   1. GET <path> cookieless             — save headers/body; capture Set-Cookie
#   2. GET <path> presenting GET#1 jar   — save headers/body
#
#   Both GETs send Chrome User-Agent (curl default UA trips WAF UA filters).
#   Referer/Origin deliberately omitted on GETs (browsers do not send Origin
#   on same-origin GETs; Referer varies by navigation source and is optional).
#   Downstream POST doctrine — always send Referer=login-page-URL, Origin,
#   User-Agent — is Phase 2/3/4 concern (script updates + walkthrough F&Rs).
#
#   Redirect chain (-L): both GETs follow redirects; cumulative Set-Cookie
#   across the chain captured in the header dump. Final status must be 2xx
#   or 3xx (with -L, terminal 3xx implies max-redirects hit or Location loop).
#
# Cookie classification (per cookie name from GET#1 response Set-Cookie):
#   GET#2 has NO Set-Cookie for name          → STATIC (server accepted
#                                                presented cookie silently —
#                                                normal browser session flow)
#   GET#2 has Set-Cookie for name, SAME val   → STATIC (touch/refresh only —
#                                                expiry bump, attribute update)
#   GET#2 has Set-Cookie for name, DIFF val   → ROTATING (server rejected
#                                                presented cookie)
#   Cookie in GET#2 not in GET#1              → NEW_COOKIES_GET2 (progressive)
#
# Hidden field classification (per name from GET#1 body):
#   Parser: <input type="hidden" name="..." value="..."> — attribute-order-
#   agnostic; single/double-quote agnostic; HTML entities decoded on values
#   before comparison. HTML comments and <script> contents stripped before
#   parsing (avoids false-positive matches on commented-out or JS-string
#   input tags).
#     Same name, SAME value in GET#2       → STATIC
#     Same name, DIFF value in GET#2       → ROTATING
#     In GET#1, absent from GET#2          → ROTATING (server non-deterministic)
#     In GET#2, absent from GET#1          → NEW_HIDDEN_FIELDS_GET2
#
#   STATIC_HIDDEN_FIELDS values URL-encoded on emission (RFC 3986 unreserved
#   set: A-Z a-z 0-9 - _ . ~) for direct paste into POST body.
#
# Rate-limit self-defense:
#   Sample response status=429 OR body matches known rate-limit patterns
#   (case-insensitive substring) → BAIL with RATE_LIMITED before contamination.
#   Same pattern list as auth_oracle_probe.sh (kept in sync — drift-warning
#   convention applies if either script's list changes).
#
# Deferred (not v1):
#   - Case C: POST-response state rotation. Probe issues GETs only; if server
#     is stable on GET reads but rotates state in POST responses (including
#     failed auth POSTs), Probe emits false ROUTE=shell → downstream attack
#     silently CSRF-rejected on every attempt → false negative on credential
#     attack, potentially miss valid creds. Mainstream framework defaults
#     (Laravel/Django/Rails/ASP.NET Core) don't do this; hardened configs,
#     custom middleware, or older CodeIgniter with csrf_regenerate=TRUE may.
#     Symptom: zero SUCCESS on plausible wordlist → escalate to Burp manually.
#     v2 enhancement: add POST-diff step (dummy-POST + GET#3, compare state
#     carriers to GET#2; any change forces ROUTE=burp). Cost: 4 requests
#     instead of 2, one extra classification path.
#   - Multi-form-per-page handling (--form-selector flag). YAGNI until real
#     encounter demands it. First encounter → build.
#   - Multi-valued hidden fields with same name (`tags[]=a`, `tags[]=b`).
#     Classifier keeps last value only. Rare on auth forms.
#   - UTF-8 multi-byte in hidden field values (URL-encoding treats bytes).
#     Emitted encoding may differ from browser behavior for non-ASCII.
#   - Cookie deletion semantics (Max-Age=0, past Expires). Treated
#     conservatively as ROTATING in v1 (empty value differs from prior value).
#   - POST-based state carriers (apps that only issue state on specific POST).
#   - JavaScript execution (persistent coverage gap; browser required).

set -u

# ==============================================================================
# Constants
# ==============================================================================

TIMEOUT_SEC=10
BROWSER_UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"

# Rate-limit body patterns (case-insensitive substring, checked per sample).
# ⚠️ DRIFT-WARNING: mirrors auth_oracle_probe.sh RATE_LIMIT_PATTERNS. Any
# change here MUST be mirrored there (and vice versa).
RATE_LIMIT_PATTERNS=(
    "too many attempts"
    "too many requests"
    "rate limit"
    "rate-limited"
    "slow down"
    "try again later"
    "temporarily unavailable"
)

# ==============================================================================
# Globals populated by parse_args
# ==============================================================================

HOST=""
PORT=""
PROBE_PATH=""
SCHEME="http"
DELAY_MS=0
VERBOSE=no

# WORK_DIR — mktemp'd; per-sample files stored as <name>.body, .hdr, .jar,
# .meta; parsed intermediates as <name>.cookies, .hidden; classified results
# as static.*, rotating.*, new.*. Trap-cleaned on exit unless --verbose.
WORK_DIR=""

# ==============================================================================
# Usage / help
# ==============================================================================

usage() {
    cat >&2 <<'EOF'
Usage: statefulness_probe.sh --host=<h> --port=<p> --path=<p> \
                             [--scheme=<http|https>] [--delay=<ms>] [--verbose]

Required flags:
  --host=<h>       Target hostname or IP
  --port=<p>       Target HTTP/HTTPS port
  --path=<p>       GET path of form-serving page (e.g. /login.php)

Optional flags:
  --scheme=<s>     http (default) or https
  --delay=<ms>     Milliseconds between the two GETs (default 0)
  --verbose        Preserve WORK_DIR sample dumps on exit
  --help, -h       Show this help

See top-of-script comment for full marker output contract.
EOF
    exit 1
}

# ==============================================================================
# Argument parsing
# ==============================================================================

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --host=*)    HOST="${1#--host=}"; shift ;;
            --port=*)    PORT="${1#--port=}"; shift ;;
            --path=*)    PROBE_PATH="${1#--path=}"; shift ;;
            --scheme=*)  SCHEME="${1#--scheme=}"; shift ;;
            --delay=*)   DELAY_MS="${1#--delay=}"; shift ;;
            --verbose)   VERBOSE=yes; shift ;;
            --help|-h)   usage ;;
            *)           echo "ERROR: unknown argument: $1" >&2; usage ;;
        esac
    done

    [ -z "$HOST" ]       && { echo "ERROR: --host required" >&2; usage; }
    [ -z "$PORT" ]       && { echo "ERROR: --port required" >&2; usage; }
    [ -z "$PROBE_PATH" ] && { echo "ERROR: --path required" >&2; usage; }

    if [[ ! "$PROBE_PATH" =~ ^/ ]]; then
        echo "ERROR: --path must start with / (got: '$PROBE_PATH')" >&2
        usage
    fi

    case "$SCHEME" in
        http|https) ;;
        *) echo "ERROR: invalid scheme '$SCHEME' (must be http|https)" >&2; usage ;;
    esac

    if ! [[ "$DELAY_MS" =~ ^[0-9]+$ ]]; then
        echo "ERROR: --delay must be non-negative integer (milliseconds)" >&2
        usage
    fi
}

# ==============================================================================
# Workdir setup / teardown
# ==============================================================================

setup_workdir() {
    WORK_DIR=$(mktemp -d) || { echo "ERROR: mktemp failed" >&2; exit 1; }
    if [ "$VERBOSE" = "no" ]; then
        trap "rm -rf '$WORK_DIR'" EXIT
    else
        trap "echo 'WORK_DIR preserved: $WORK_DIR' >&2" EXIT
    fi
}

# ==============================================================================
# HTTP sampling
# ==============================================================================

# get_page <name> [<jar_in>] — GET the probe path.
#   name    — sample identifier (get1, get2); files written as <name>.body,
#             <name>.hdr, <name>.jar, <name>.meta
#   jar_in  — optional cookie jar to present via -b (browser sends stored
#             cookies on outgoing requests)
get_page() {
    local name="$1" jar_in="${2:-}"
    local url="${SCHEME}://${HOST}:${PORT}${PROBE_PATH}"
    local args=(
        -s -k -L
        --max-time "$TIMEOUT_SEC"
        -o "${WORK_DIR}/${name}.body"
        -D "${WORK_DIR}/${name}.hdr"
        -c "${WORK_DIR}/${name}.jar"
        -H "User-Agent: $BROWSER_UA"
        -w 'status=%{http_code}|size=%{size_download}|type=%{content_type}\n'
    )
    if [ -n "$jar_in" ]; then
        args+=(-b "$jar_in")
    fi
    curl "${args[@]}" "$url" > "${WORK_DIR}/${name}.meta" 2>/dev/null
    return $?
}

delay_between() {
    if [ "$DELAY_MS" -gt 0 ]; then
        sleep "$(awk "BEGIN{printf \"%.3f\", $DELAY_MS/1000}")"
    fi
}

# get_meta <name> <key> — extract key=value from meta file
get_meta() {
    local name="$1" key="$2"
    grep -oE "${key}=[^|]*" "${WORK_DIR}/${name}.meta" 2>/dev/null \
        | head -1 | cut -d= -f2- | tr -d '\n'
}

# check_rate_limited <name> — emit RATE_LIMITED and return 0 if throttled
check_rate_limited() {
    local name="$1"
    local status
    status=$(get_meta "$name" status)
    if [ "$status" = "429" ]; then
        echo "RATE_LIMITED: sample=$name status=429"
        return 0
    fi
    local pattern
    for pattern in "${RATE_LIMIT_PATTERNS[@]}"; do
        if grep -qiF -- "$pattern" "${WORK_DIR}/${name}.body" 2>/dev/null; then
            echo "RATE_LIMITED: sample=$name body_matched='$pattern'"
            return 0
        fi
    done
    return 1
}

# check_bail_status <name> — emit BAIL and return 0 if status not 2xx/3xx
check_bail_status() {
    local name="$1"
    local status
    status=$(get_meta "$name" status)
    if [[ ! "$status" =~ ^[23][0-9][0-9]$ ]]; then
        echo "BAIL: unexpected status on ${name} GET (status=${status})"
        return 0
    fi
    return 1
}

# check_bail_content_type <name> — emit BAIL and return 0 if non-HTML content
check_bail_content_type() {
    local name="$1"
    local ct
    ct=$(get_meta "$name" type)
    case "$ct" in
        application/json*|application/xml*|image/*|application/pdf*|application/octet-stream*|video/*|audio/*)
            echo "BAIL: non-HTML content-type on ${name} GET (type=${ct} — Probe expects HTML form page)"
            return 0
            ;;
    esac
    return 1
}

# sample_all — two GETs, cookie-jar chain
sample_all() {
    get_page get1 || { echo "BAIL: get1 GET failed (curl error)"; exit 1; }
    check_rate_limited get1 && exit 1
    check_bail_status get1 && exit 1
    check_bail_content_type get1 && exit 1
    delay_between

    get_page get2 "${WORK_DIR}/get1.jar" || { echo "BAIL: get2 GET failed (curl error)"; exit 1; }
    check_rate_limited get2 && exit 1
    check_bail_status get2 && exit 1
    check_bail_content_type get2 && exit 1
}

# ==============================================================================
# Set-Cookie parsing
# ==============================================================================

# parse_set_cookies <hdr_file> — output one "name=value" line per Set-Cookie
# header. Duplicates permitted; classify_cookies dedupes (last wins, matching
# browser same-name-replace behavior).
parse_set_cookies() {
    local hdr="$1"
    grep -i '^set-cookie:' "$hdr" 2>/dev/null | \
        sed -E 's/^[^:]*:[[:space:]]*//' | \
        while IFS= read -r line; do
            line="${line%$'\r'}"
            local nv="${line%%;*}"
            # Trim leading/trailing whitespace
            nv="${nv#"${nv%%[![:space:]]*}"}"
            nv="${nv%"${nv##*[![:space:]]}"}"
            if [[ "$nv" == *=* ]]; then
                local name="${nv%%=*}"
                if [ -n "$name" ]; then
                    printf '%s\n' "$nv"
                fi
            fi
        done
}

# ==============================================================================
# Hidden field parsing
# ==============================================================================

# parse_hidden_fields <body_file> — output one "name=value" line per
# <input type="hidden"> tag. Values HTML-entity-decoded (common entities).
# Attribute-order-agnostic; single/double-quote-agnostic; unquoted attributes
# supported. Comments and <script> contents stripped before parsing.
parse_hidden_fields() {
    local body="$1"
    perl -0777 -ne '
        # Strip HTML comments and <script> contents to avoid false matches
        s/<!--.*?-->//gs;
        s/<script\b[^>]*>.*?<\/script>/<script><\/script>/gsi;

        while (m|<input\b([^>]*?)/?>|gi) {
            my $tag = "<input" . $1 . ">";
            my $type = extract_attr($tag, "type");
            next unless lc($type) eq "hidden";
            my $name = extract_attr($tag, "name");
            next unless length $name;
            my $value = extract_attr($tag, "value");
            $name  = html_decode($name);
            $value = html_decode($value);
            # Strip CR/LF that would corrupt our line-per-field emit format
            $name  =~ s/[\r\n]/ /g;
            $value =~ s/[\r\n]/ /g;
            next unless length $name;
            print "$name=$value\n";
        }

        sub extract_attr {
            my ($tag, $attr) = @_;
            if ($tag =~ /\b\Q$attr\E\s*=\s*"([^"]*)"/i)             { return $1; }
            if ($tag =~ /\b\Q$attr\E\s*=\s*\x27([^\x27]*)\x27/i)    { return $1; }
            if ($tag =~ /\b\Q$attr\E\s*=\s*([^\s>\/]+)/i)           { return $1; }
            return "";
        }

        sub html_decode {
            my $s = shift;
            $s =~ s/&lt;/</g;
            $s =~ s/&gt;/>/g;
            $s =~ s/&quot;/"/g;
            $s =~ s/&#39;/\x27/g;
            $s =~ s/&apos;/\x27/g;
            $s =~ s/&amp;/&/g;   # Must be last to avoid double-decoding
            return $s;
        }
    ' "$body"
}

# ==============================================================================
# URL encoding
# ==============================================================================

# urlencode <string> — output RFC 3986 percent-encoded string.
# Only unreserved chars (A-Z a-z 0-9 - _ . ~) pass through.
urlencode() {
    local string="$1" i char encoded=""
    for (( i=0; i<${#string}; i++ )); do
        char="${string:i:1}"
        case "$char" in
            [a-zA-Z0-9.~_-]) encoded+="$char" ;;
            *) encoded+=$(printf '%%%02X' "'$char") ;;
        esac
    done
    printf '%s' "$encoded"
}

# ==============================================================================
# Classification
# ==============================================================================

classify_cookies() {
    declare -A g1 g2

    while IFS='=' read -r name value; do
        [ -n "$name" ] && g1["$name"]="$value"
    done < "${WORK_DIR}/get1.cookies"

    while IFS='=' read -r name value; do
        [ -n "$name" ] && g2["$name"]="$value"
    done < "${WORK_DIR}/get2.cookies"

    : > "${WORK_DIR}/static.cookies"
    : > "${WORK_DIR}/rotating.cookies"
    : > "${WORK_DIR}/new.cookies"

    local name v1
    for name in "${!g1[@]}"; do
        v1="${g1[$name]}"
        if [ "${g2[$name]+set}" = "set" ]; then
            if [ "${g2[$name]}" = "$v1" ]; then
                # Same value: server touched/refreshed
                echo "${name}=${v1}" >> "${WORK_DIR}/static.cookies"
            else
                # Different value: server rejected presented cookie
                echo "$name" >> "${WORK_DIR}/rotating.cookies"
            fi
        else
            # Silent on GET#2: server accepted presented cookie
            echo "${name}=${v1}" >> "${WORK_DIR}/static.cookies"
        fi
    done

    for name in "${!g2[@]}"; do
        if [ "${g1[$name]+set}" != "set" ]; then
            echo "$name" >> "${WORK_DIR}/new.cookies"
        fi
    done

    # Deterministic output order
    sort "${WORK_DIR}/static.cookies"   -o "${WORK_DIR}/static.cookies"
    sort "${WORK_DIR}/rotating.cookies" -o "${WORK_DIR}/rotating.cookies"
    sort "${WORK_DIR}/new.cookies"      -o "${WORK_DIR}/new.cookies"
}

classify_hidden_fields() {
    declare -A g1 g2

    while IFS='=' read -r name value; do
        [ -n "$name" ] && g1["$name"]="$value"
    done < "${WORK_DIR}/get1.hidden"

    while IFS='=' read -r name value; do
        [ -n "$name" ] && g2["$name"]="$value"
    done < "${WORK_DIR}/get2.hidden"

    : > "${WORK_DIR}/static.hidden"
    : > "${WORK_DIR}/rotating.hidden"
    : > "${WORK_DIR}/new.hidden"

    local name v1
    for name in "${!g1[@]}"; do
        v1="${g1[$name]}"
        if [ "${g2[$name]+set}" = "set" ]; then
            if [ "${g2[$name]}" = "$v1" ]; then
                echo "${name}=${v1}" >> "${WORK_DIR}/static.hidden"
            else
                echo "$name" >> "${WORK_DIR}/rotating.hidden"
            fi
        else
            # Present in GET#1 body, absent from GET#2: server non-deterministic
            echo "$name" >> "${WORK_DIR}/rotating.hidden"
        fi
    done

    for name in "${!g2[@]}"; do
        if [ "${g1[$name]+set}" != "set" ]; then
            echo "$name" >> "${WORK_DIR}/new.hidden"
        fi
    done

    sort "${WORK_DIR}/static.hidden"   -o "${WORK_DIR}/static.hidden"
    sort "${WORK_DIR}/rotating.hidden" -o "${WORK_DIR}/rotating.hidden"
    sort "${WORK_DIR}/new.hidden"      -o "${WORK_DIR}/new.hidden"
}

# ==============================================================================
# Emission
# ==============================================================================

# emit_static_cookies — "STATIC_COOKIES: n1=v1; n2=v2" (browser Cookie format)
emit_static_cookies() {
    local out=""
    while IFS= read -r nv; do
        [ -z "$nv" ] && continue
        if [ -z "$out" ]; then out="$nv"; else out+="; $nv"; fi
    done < "${WORK_DIR}/static.cookies"
    echo "STATIC_COOKIES: $out"
}

# emit_static_hidden — "STATIC_HIDDEN_FIELDS: n1=v1&n2=v2" (URL-encoded)
emit_static_hidden() {
    local out=""
    while IFS='=' read -r name value; do
        [ -z "$name" ] && continue
        local en ev
        en=$(urlencode "$name")
        ev=$(urlencode "$value")
        if [ -z "$out" ]; then out="${en}=${ev}"; else out+="&${en}=${ev}"; fi
    done < "${WORK_DIR}/static.hidden"
    echo "STATIC_HIDDEN_FIELDS: $out"
}

# emit_names <label> <file> — "LABEL: name1, name2" from file of names
emit_names() {
    local label="$1" file="$2"
    local out=""
    while IFS= read -r name; do
        [ -z "$name" ] && continue
        if [ -z "$out" ]; then out="$name"; else out+=", $name"; fi
    done < "$file"
    echo "${label}: ${out}"
}

# emit_coverage_warnings — always four, verbatim; boxed preamble printed
# BEFORE signal so the operator's eye passes over caveats first, then lands
# on the actionable signal below. Bullets (not prefix) since the box header
# already establishes each inner line is a warning.
emit_coverage_warnings() {
    echo "=============================================================================="
    echo "COVERAGE WARNINGS (informational — always emitted; do not affect ROUTE)"
    echo "=============================================================================="
    echo "- JS-computed tokens not detectable shell-side — inspect page manually if JS present."
    echo "- Two-request flows (email/MFA/verify) not detectable from GET-diff — if POST triggers a second challenge, escalate to Burp."
    echo "- Bot-detection challenges (CAPTCHA/Turnstile/hCaptcha) not defeatable via Burp macro either — if detected, manual browser required."
    echo "- Custom JS-set request headers not detectable shell-side — inspect via browser dev tools if suspected."
    echo "- POST-response state rotation not detectable from GET-only diff — if credential attack yields zero SUCCESS on a plausible wordlist, escalate to Burp (state may rotate on failed POSTs)."
    echo "=============================================================================="
    echo ""
}

# join_names <file> — comma-space-joined names from a one-per-line file
join_names() {
    tr '\n' ',' < "$1" | sed 's/,$//;s/,/, /g'
}

# emit_route — "ROUTE: shell|burp" + "ROUTE_REASON: <text>"
emit_route() {
    local any_rotating=no
    [ -s "${WORK_DIR}/rotating.cookies" ] && any_rotating=yes
    [ -s "${WORK_DIR}/rotating.hidden" ]  && any_rotating=yes
    [ -s "${WORK_DIR}/new.cookies" ]      && any_rotating=yes
    [ -s "${WORK_DIR}/new.hidden" ]       && any_rotating=yes

    if [ "$any_rotating" = "no" ]; then
        echo "ROUTE: shell"
        echo "ROUTE_REASON: all state carriers static (or none present)"
        return
    fi

    # Build reason string: joined by "; " over non-empty channels
    local reasons=()
    [ -s "${WORK_DIR}/rotating.hidden" ] && reasons+=("hidden fields rotate: $(join_names "${WORK_DIR}/rotating.hidden")")
    [ -s "${WORK_DIR}/rotating.cookies" ] && reasons+=("cookies rotate: $(join_names "${WORK_DIR}/rotating.cookies")")
    [ -s "${WORK_DIR}/new.hidden" ] && reasons+=("new hidden fields on GET#2: $(join_names "${WORK_DIR}/new.hidden")")
    [ -s "${WORK_DIR}/new.cookies" ] && reasons+=("new cookies on GET#2: $(join_names "${WORK_DIR}/new.cookies")")

    local joined=""
    local r
    for r in "${reasons[@]}"; do
        if [ -z "$joined" ]; then joined="$r"; else joined+="; $r"; fi
    done

    echo "ROUTE: burp"
    echo "ROUTE_REASON: $joined"
}

emit_all() {
    emit_coverage_warnings
    emit_static_cookies
    emit_static_hidden
    emit_names "ROTATING_COOKIES"       "${WORK_DIR}/rotating.cookies"
    emit_names "ROTATING_HIDDEN_FIELDS" "${WORK_DIR}/rotating.hidden"
    emit_names "NEW_COOKIES_GET2"       "${WORK_DIR}/new.cookies"
    emit_names "NEW_HIDDEN_FIELDS_GET2" "${WORK_DIR}/new.hidden"
    emit_route
}

# ==============================================================================
# Main
# ==============================================================================

main() {
    parse_args "$@"
    setup_workdir
    sample_all
    parse_set_cookies   "${WORK_DIR}/get1.hdr"  > "${WORK_DIR}/get1.cookies"
    parse_set_cookies   "${WORK_DIR}/get2.hdr"  > "${WORK_DIR}/get2.cookies"
    parse_hidden_fields "${WORK_DIR}/get1.body" > "${WORK_DIR}/get1.hidden"
    parse_hidden_fields "${WORK_DIR}/get2.body" > "${WORK_DIR}/get2.hidden"
    classify_cookies
    classify_hidden_fields
    emit_all
}

# ==============================================================================
# Source guard: only run main if executed, not sourced (for tests)
# ==============================================================================

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
