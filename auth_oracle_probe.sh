#!/bin/bash
# auth_oracle_probe.sh
#
# Derive SUCCESS/FAIL oracle for a discovered login form via multi-sample
# probing, app-class classification, and per-class oracle emission.
#
# Enters from Credential Attacks SUCCESS/FAIL oracle section. Consumes vars
# captured by WAC 1.6 (login form discovery). Emits ready-to-paste oracle
# snippets for Hydra, ffuf, and curl-loop consumption by Sections 1-5.
#
# Usage:
#   auth_oracle_probe.sh --host=<h> --port=<p> --login-path=<p> \
#                        --form-action=<p> --user-field=<f> --pass-field=<f> \
#                        [--scheme=<http|https>] [--delay=<ms>] [--verbose]
#
# Marker output contract:
#
#   Classification marker (always emitted first on success):
#     CLASS: <redirect|content|api|basic|unusual>
#         App class from fail-sample response. Determines which oracles fire.
#
#   Sample metadata (always emitted on non-bail classification):
#     FAIL_STATUS: <code>
#     FAIL_LOCATION: <url>              (only when 3xx)
#     FAIL_CONTENT_TYPE: <mime>
#     FAIL_SIZE: <bytes>
#
#   Derived oracles (per class — ready-to-paste snippets):
#     ORACLE_HYDRA: F=<string>   (or S=<string> for api class)
#         Substring match on final response body after Hydra follows redirects.
#     ORACLE_FFUF: <flag block>
#         Matcher/filter flags for ffuf. May include -r (follow redirects).
#     ORACLE_CURL_SUCCESS_TEST: <shell test expression>
#         Bash test expression using $U, $P, $URL. Exit 0 iff response = SUCCESS.
#         Used by Credential Attacks Section 1 default-creds loop. Requires
#         bash (uses [[ =~ ]] regex match); the vault's Section 1 loop is bash.
#
#   Content-class supplementary markers (emitted only for CLASS: content):
#     UNAUTH_MARKER: "<string>"
#         Token stable across baseline + fail samples + public page. Used as
#         F= value in ORACLE_HYDRA. Highest-EV candidate first.
#     FAIL_SIGNAL_CANDIDATE: "<string>"
#         Token stable across fail_a + fail_b, absent from baseline AND
#         absent from empty-field validation response. Multiple emitted.
#         Alternative oracle for manual pivot if primary oracle underperforms.
#
#   Basic-auth routing marker (mutually exclusive with oracles):
#     ROUTE_OUT: Login Bypass Techniques Basic Auth section
#         Emitted when CLASS=basic. Credential Attacks does not apply.
#
#   Bail markers (mutually exclusive with oracles):
#     BAIL: <reason>
#         Fatal. Escalate to Burp Repeater + Comparer for interactive
#         oracle derivation. Sample dumps in ${WORK_DIR} preserved on --verbose.
#     RATE_LIMITED: sample=<name> <detail>
#         429 or rate-limit body pattern observed during sampling. Sampling
#         aborted before contamination. Re-run with higher --delay.
#
#   Summary marker (always last on non-bail classification):
#     ORACLE_SUMMARY: class=<c> confidence=<high|medium|low>
#
# Sampling protocol (5 requests, all stateless — no cookie jar):
#   1. GET  <login_path>          baseline (unauth form)
#   2. POST <form_action>         fail A (email-shaped invalid user + wrong pass)
#   3. POST <form_action>         fail B (different invalid user + different wrong pass)
#   4. POST <form_action>         fail C (empty fields — validation-error class)
#   5. GET  /                     public page (unauth-marker source, best-effort)
#
# All requests: -o body -D headers -w metadata. NO -L. Immediate response is
# the classification input; following redirects would confuse the oracle for
# both content and redirect classes.
#
# Rate-limit self-defense:
#   Any sample response with status=429 OR body matching known rate-limit
#   patterns (case-insensitive substring) → BAIL with RATE_LIMITED marker
#   before contamination. Operator increases --delay and re-runs.
#
# CSRF interaction:
#   NOT SUPPORTED. If Pre-flight CSRF sub-block found tokens, do NOT run this
#   script — escalate to Burp per Automating Fresh State in Burp. Caller's
#   responsibility to gate; script does not verify token absence. Token-per-
#   request forms need session-handling state incompatible with stateless
#   scripted probing.
#
# Wrong-credential values used (constants, not configurable):
#   User A: "xyzabc123xxx@invalid.test"    Pass A: "wrong_ZZZ_9999"
#   User B: "noone999zz@invalid.test"      Pass B: "wrongB_XXX_5555"
#   Empty:  ""                             Empty:  ""
#   Email-shaped invalid users survive email-typed field pattern-validation.
#
# Field-name constraints:
#   --user-field and --pass-field expected to be simple identifiers (letters,
#   digits, underscores, hyphens). Exotic names like "user[email]" (framework
#   array style) not escaped in emitted oracles — escalate to Burp if seen.
#
# Deferred (not v1):
#   - Multi-step auth flows (email verify, MFA, CAPTCHA) → UNUSUAL bail
#   - JS-only redirect success (window.location) → CANDIDATE, manual verify
#   - Compound oracle expressions (fallback markers emitted separately)
#   - HTTPS with self-signed certs handled implicitly via -k

set -u

# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------

TIMEOUT_SEC=10

FAIL_A_USER="xyzabc123xxx@invalid.test"
FAIL_A_PASS="wrong_ZZZ_9999"
FAIL_B_USER="noone999zz@invalid.test"
FAIL_B_PASS="wrongB_XXX_5555"

# Rate-limit body patterns (case-insensitive substring, checked per sample).
RATE_LIMIT_PATTERNS=(
    "too many attempts"
    "too many requests"
    "rate limit"
    "rate-limited"
    "slow down"
    "try again later"
    "temporarily unavailable"
)

# ------------------------------------------------------------------------------
# Globals populated by parse_args
# ------------------------------------------------------------------------------

HOST=""
PORT=""
LOGIN_PATH=""
FORM_ACTION=""
USER_FIELD=""
PASS_FIELD=""
SCHEME="http"
DELAY_MS=0
VERBOSE=no

# WORK_DIR — mktemp'd directory; per-sample files stored here as
# <name>.body, <name>.hdr, <name>.meta. Trap-cleaned on exit.
WORK_DIR=""

# Classification globals (populated by classify)
G_CLASS=""
G_FAIL_STATUS=""
G_FAIL_LOCATION=""
G_FAIL_CONTENT_TYPE=""
G_FAIL_SIZE=""
G_FAIL_WWW_AUTH=""
G_CONFIDENCE=""

# ------------------------------------------------------------------------------
# Usage / help
# ------------------------------------------------------------------------------

usage() {
    cat >&2 <<'EOF'
Usage: auth_oracle_probe.sh --host=<h> --port=<p> --login-path=<p> \
                            --form-action=<p> --user-field=<f> --pass-field=<f> \
                            [--scheme=<http|https>] [--delay=<ms>] [--verbose]

Required flags:
  --host=<h>          Target hostname or IP
  --port=<p>          Target HTTP/HTTPS port
  --login-path=<p>    Login form GET path (e.g., /login.php)
  --form-action=<p>   Login form POST action path (e.g., /login.php)
  --user-field=<f>    Login form username field name (e.g., email)
  --pass-field=<f>    Login form password field name (e.g., password)

Optional flags:
  --scheme=<s>        URL scheme: http (default) or https
  --delay=<ms>        Milliseconds between sample requests (default 0).
                      Set from Credential Attacks Pre-flight rate-limit result.
  --verbose           Preserve sample dumps in WORK_DIR on exit for inspection.
  --help, -h          Show this help

See top-of-script comment for full marker output contract.
EOF
    exit 1
}

# ------------------------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------------------------

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --host=*)         HOST="${1#--host=}"; shift ;;
            --port=*)         PORT="${1#--port=}"; shift ;;
            --login-path=*)   LOGIN_PATH="${1#--login-path=}"; shift ;;
            --form-action=*)  FORM_ACTION="${1#--form-action=}"; shift ;;
            --user-field=*)   USER_FIELD="${1#--user-field=}"; shift ;;
            --pass-field=*)   PASS_FIELD="${1#--pass-field=}"; shift ;;
            --scheme=*)       SCHEME="${1#--scheme=}"; shift ;;
            --delay=*)        DELAY_MS="${1#--delay=}"; shift ;;
            --verbose)        VERBOSE=yes; shift ;;
            --help|-h)        usage ;;
            *)                echo "ERROR: unknown argument: $1" >&2; usage ;;
        esac
    done

    [ -z "$HOST" ]        && { echo "ERROR: --host required" >&2; usage; }
    [ -z "$PORT" ]        && { echo "ERROR: --port required" >&2; usage; }
    [ -z "$LOGIN_PATH" ]  && { echo "ERROR: --login-path required" >&2; usage; }
    [ -z "$FORM_ACTION" ] && { echo "ERROR: --form-action required" >&2; usage; }
    [ -z "$USER_FIELD" ]  && { echo "ERROR: --user-field required" >&2; usage; }
    [ -z "$PASS_FIELD" ]  && { echo "ERROR: --pass-field required" >&2; usage; }

    case "$SCHEME" in
        http|https) ;;
        *) echo "ERROR: invalid scheme '$SCHEME' (must be http|https)" >&2; usage ;;
    esac

    if ! [[ "$DELAY_MS" =~ ^[0-9]+$ ]]; then
        echo "ERROR: --delay must be non-negative integer (milliseconds)" >&2; usage
    fi
}

# ------------------------------------------------------------------------------
# Workdir setup / teardown
# ------------------------------------------------------------------------------

setup_workdir() {
    WORK_DIR=$(mktemp -d) || { echo "ERROR: mktemp failed" >&2; exit 1; }
    if [ "$VERBOSE" = "no" ]; then
        trap "rm -rf '$WORK_DIR'" EXIT
    else
        trap "echo 'WORK_DIR preserved: $WORK_DIR' >&2" EXIT
    fi
}

# ------------------------------------------------------------------------------
# HTTP sampling
# ------------------------------------------------------------------------------

# sample_get <path> <name> — GET path, store body/hdr/meta under <name>.*
sample_get() {
    local path="$1" name="$2"
    local url="${SCHEME}://${HOST}:${PORT}${path}"
    curl -s -k \
         -o "${WORK_DIR}/${name}.body" \
         -D "${WORK_DIR}/${name}.hdr" \
         --max-time "$TIMEOUT_SEC" \
         -w 'status=%{http_code}|size=%{size_download}|redirect=%{redirect_url}|type=%{content_type}\n' \
         "$url" > "${WORK_DIR}/${name}.meta" 2>/dev/null
    return $?
}

# sample_post <user> <pass> <name> — POST form-action with user/pass, store as <name>.*
sample_post() {
    local user="$1" pass="$2" name="$3"
    local url="${SCHEME}://${HOST}:${PORT}${FORM_ACTION}"
    curl -s -k -X POST \
         -o "${WORK_DIR}/${name}.body" \
         -D "${WORK_DIR}/${name}.hdr" \
         --max-time "$TIMEOUT_SEC" \
         --data-urlencode "${USER_FIELD}=${user}" \
         --data-urlencode "${PASS_FIELD}=${pass}" \
         -w 'status=%{http_code}|size=%{size_download}|redirect=%{redirect_url}|type=%{content_type}\n' \
         "$url" > "${WORK_DIR}/${name}.meta" 2>/dev/null
    return $?
}

# delay_between — sleep DELAY_MS milliseconds
delay_between() {
    if [ "$DELAY_MS" -gt 0 ]; then
        sleep "$(awk "BEGIN{printf \"%.3f\", $DELAY_MS/1000}")"
    fi
}

# check_rate_limited <sample_name> — emit RATE_LIMITED marker and return 0 if throttled
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

# baseline_is_basic_auth — return 0 if baseline GET returned 401+WWW-Authenticate
baseline_is_basic_auth() {
    local s wa
    s=$(get_meta baseline status)
    wa=$(get_header baseline WWW-Authenticate)
    [ "$s" = "401" ] && [ -n "$wa" ]
}

# sample_all — run baseline GET first; if basic-auth detected, skip POSTs
# entirely (they're pointless for header-based auth and cost requests toward
# rate limits). Otherwise run the full 5-sample protocol.
sample_all() {
    sample_get "$LOGIN_PATH" baseline || { echo "BAIL: baseline GET failed (curl error)"; exit 1; }
    check_rate_limited baseline && exit 1
    delay_between

    if baseline_is_basic_auth; then
        return   # classify() will detect basic and dispatch to route-out
    fi

    sample_post "$FAIL_A_USER" "$FAIL_A_PASS" fail_a || { echo "BAIL: fail_a POST failed"; exit 1; }
    check_rate_limited fail_a && exit 1
    delay_between

    sample_post "$FAIL_B_USER" "$FAIL_B_PASS" fail_b || { echo "BAIL: fail_b POST failed"; exit 1; }
    check_rate_limited fail_b && exit 1
    delay_between

    sample_post "" "" fail_c || { echo "BAIL: fail_c POST failed"; exit 1; }
    check_rate_limited fail_c && exit 1
    delay_between

    # Public page best-effort — failure is not fatal (only used for unauth-marker enrichment)
    sample_get "/" public 2>/dev/null || true
}

# ------------------------------------------------------------------------------
# Sample-metadata accessors
# ------------------------------------------------------------------------------

# get_meta <sample_name> <key> — extract key=value from meta file
get_meta() {
    local name="$1" key="$2"
    grep -oE "${key}=[^|]*" "${WORK_DIR}/${name}.meta" 2>/dev/null \
        | head -1 | cut -d= -f2- | tr -d '\n'
}

# get_header <sample_name> <header_name> — extract header value from hdr file
# (immediate response only; we don't follow redirects during sampling)
get_header() {
    local name="$1" hdr="$2"
    grep -iE "^${hdr}:" "${WORK_DIR}/${name}.hdr" 2>/dev/null \
        | head -1 | sed -E 's/^[^:]*:[[:space:]]*//' | tr -d '\r\n'
}

# ------------------------------------------------------------------------------
# Classification
# ------------------------------------------------------------------------------

classify() {
    # BASIC AUTH detection FIRST — from baseline GET.
    # Basic auth is HTTP-header based, not form-based. If the login path returns
    # 401+WWW-Authenticate on GET, form-based POSTs are pointless (they return
    # 401 too, often without WWW-Auth header depending on server config). Route
    # out immediately — the fail_a POST sample data is not used for basic class.
    local baseline_status baseline_www_auth
    baseline_status=$(get_meta baseline status)
    baseline_www_auth=$(get_header baseline WWW-Authenticate)
    if [ "$baseline_status" = "401" ] && [ -n "$baseline_www_auth" ]; then
        G_CLASS="basic"
        G_CONFIDENCE="high"
        G_FAIL_STATUS="$baseline_status"
        G_FAIL_WWW_AUTH="$baseline_www_auth"
        return
    fi

    # Otherwise classify from fail_a POST response.
    G_FAIL_STATUS=$(get_meta fail_a status)
    G_FAIL_LOCATION=$(get_header fail_a Location)
    G_FAIL_CONTENT_TYPE=$(get_header fail_a Content-Type)
    G_FAIL_SIZE=$(get_meta fail_a size)
    G_FAIL_WWW_AUTH=$(get_header fail_a WWW-Authenticate)

    # API/JSON — 4xx with JSON content-type
    if [[ "$G_FAIL_STATUS" =~ ^(400|401|403|422)$ ]] && \
       [[ "$G_FAIL_CONTENT_TYPE" == *json* || "$G_FAIL_CONTENT_TYPE" == *JSON* ]]; then
        G_CLASS="api"
        G_CONFIDENCE="high"
        return
    fi

    # REDIRECT — 3xx with Location
    if [[ "$G_FAIL_STATUS" =~ ^3[0-9][0-9]$ ]] && [ -n "$G_FAIL_LOCATION" ]; then
        G_CLASS="redirect"
        G_CONFIDENCE="high"
        return
    fi

    # CONTENT — 200
    if [ "$G_FAIL_STATUS" = "200" ]; then
        G_CLASS="content"
        G_CONFIDENCE="high"
        return
    fi

    G_CLASS="unusual"
    G_CONFIDENCE="low"
}

# ------------------------------------------------------------------------------
# Metadata emission
# ------------------------------------------------------------------------------

emit_metadata() {
    echo "CLASS: $G_CLASS"
    echo "FAIL_STATUS: $G_FAIL_STATUS"
    [ -n "$G_FAIL_LOCATION" ]     && echo "FAIL_LOCATION: $G_FAIL_LOCATION"
    [ -n "$G_FAIL_CONTENT_TYPE" ] && echo "FAIL_CONTENT_TYPE: $G_FAIL_CONTENT_TYPE"
    [ -n "$G_FAIL_SIZE" ]         && echo "FAIL_SIZE: $G_FAIL_SIZE"
}

# ------------------------------------------------------------------------------
# Content-class marker derivation (token-set arithmetic)
# ------------------------------------------------------------------------------

# tokenize <body_file> — split on '<' and '>', trim, dedupe, write to stdout
tokenize() {
    tr '<>' '\n\n' < "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
        | grep -v '^$' | sort -u
}

# derive_content_markers — populate token files under WORK_DIR for later emission
derive_content_markers() {
    tokenize "${WORK_DIR}/baseline.body" > "${WORK_DIR}/baseline.tok"
    tokenize "${WORK_DIR}/fail_a.body"   > "${WORK_DIR}/fail_a.tok"
    tokenize "${WORK_DIR}/fail_b.body"   > "${WORK_DIR}/fail_b.tok"
    tokenize "${WORK_DIR}/fail_c.body"   > "${WORK_DIR}/fail_c.tok"
    if [ -f "${WORK_DIR}/public.body" ]; then
        tokenize "${WORK_DIR}/public.body" > "${WORK_DIR}/public.tok"
    else
        : > "${WORK_DIR}/public.tok"
    fi

    # Fail-signal candidates: (fail_a ∩ fail_b) − baseline − fail_c
    comm -12 "${WORK_DIR}/fail_a.tok" "${WORK_DIR}/fail_b.tok" > "${WORK_DIR}/_ab.tok"
    comm -23 "${WORK_DIR}/_ab.tok" "${WORK_DIR}/baseline.tok"  > "${WORK_DIR}/_ab_minus_base.tok"
    comm -23 "${WORK_DIR}/_ab_minus_base.tok" "${WORK_DIR}/fail_c.tok" \
        > "${WORK_DIR}/fail_signal_candidates.tok"

    # Unauth marker candidates: tokens present in baseline AND fail_a AND (public if available)
    # Then filter to auth-nav-ish patterns.
    comm -12 "${WORK_DIR}/baseline.tok" "${WORK_DIR}/fail_a.tok" > "${WORK_DIR}/_base_a.tok"
    if [ -s "${WORK_DIR}/public.tok" ]; then
        comm -12 "${WORK_DIR}/_base_a.tok" "${WORK_DIR}/public.tok" > "${WORK_DIR}/_stable_unauth.tok"
    else
        cp "${WORK_DIR}/_base_a.tok" "${WORK_DIR}/_stable_unauth.tok"
    fi

    # Rank candidates: form field markers > login-path hrefs > login-word markers
    {
        grep -E "name=[\"']?${USER_FIELD}[\"']?" "${WORK_DIR}/_stable_unauth.tok" 2>/dev/null
        grep -E "name=[\"']?${PASS_FIELD}[\"']?" "${WORK_DIR}/_stable_unauth.tok" 2>/dev/null
        grep -F "$LOGIN_PATH" "${WORK_DIR}/_stable_unauth.tok" 2>/dev/null
        grep -E "^(Login|Sign In|Sign in|Log In|Log in)$" "${WORK_DIR}/_stable_unauth.tok" 2>/dev/null
    } | awk '!seen[$0]++' > "${WORK_DIR}/unauth_marker_candidates.tok"
}

# emit_content_supplementary — emit UNAUTH_MARKER and FAIL_SIGNAL_CANDIDATE lines
emit_content_supplementary() {
    # UNAUTH_MARKER (up to 3)
    local n=0
    while IFS= read -r line && [ "$n" -lt 3 ]; do
        [ "${#line}" -gt 200 ] && line="${line:0:200}..."
        echo "UNAUTH_MARKER: \"$line\""
        n=$((n + 1))
    done < "${WORK_DIR}/unauth_marker_candidates.tok"

    # FAIL_SIGNAL_CANDIDATE (up to 5)
    n=0
    while IFS= read -r line && [ "$n" -lt 5 ]; do
        [ "${#line}" -gt 200 ] && line="${line:0:200}..."
        echo "FAIL_SIGNAL_CANDIDATE: \"$line\""
        n=$((n + 1))
    done < "${WORK_DIR}/fail_signal_candidates.tok"
}

# ------------------------------------------------------------------------------
# Oracle emission (per class)
# ------------------------------------------------------------------------------

# extract_location_path <url> — return path (query-stripped) portion of URL,
# or the input itself if already a path
extract_location_path() {
    printf '%s' "$1" | sed -E 's|^https?://[^/]+||' | cut -d'?' -f1
}

# emit_oracle_redirect — REDIRECT-class oracles.
# Fail sample was a 3xx to a login-ish path (query stripped = LOGIN_PATH prefix).
# Success = 3xx to a path NOT under LOGIN_PATH's prefix.
emit_oracle_redirect() {
    local fail_loc_path
    fail_loc_path=$(extract_location_path "$G_FAIL_LOCATION")
    [ -z "$fail_loc_path" ] && { echo "BAIL: redirect class but fail Location has empty path"; exit 1; }

    # Login-form marker used by Hydra/ffuf after following redirects.
    # Followed page = success dashboard (no login form) or the login-with-error
    # page (has login form). Match on login-form presence = fail.
    local login_form_marker="name=\"${USER_FIELD}\""

    echo "ORACLE_HYDRA: F=${login_form_marker}"
    echo "ORACLE_FFUF: -r -fr '${login_form_marker}'"
    # curl fragment: capture immediate redirect URL, check its path does not
    # start with the fail Location's path (i.e., the redirect leaves login zone)
    printf 'ORACLE_CURL_SUCCESS_TEST: R=$(curl -s -k -o /dev/null -w '\''%%{redirect_url}'\'' -X POST --data-urlencode "%s=$U" --data-urlencode "%s=$P" "$URL") && [ -n "$R" ] && ! printf '\''%%s'\'' "$R" | grep -qE '\''^https?://[^/]+%s'\''\n' \
        "$USER_FIELD" "$PASS_FIELD" "$fail_loc_path"
}

# emit_oracle_content — CONTENT-class oracles.
# Fail = 200 with form re-render. Success = 302 to dashboard (POST-redirect-GET
# is the modern default). Uses status delta as the primary oracle for ffuf/curl;
# uses derived unauth-marker for Hydra (Hydra can't match on status).
emit_oracle_content() {
    local marker
    marker=$(head -1 "${WORK_DIR}/unauth_marker_candidates.tok" 2>/dev/null)
    if [ -n "$marker" ]; then
        echo "ORACLE_HYDRA: F=${marker}"
    else
        echo "ORACLE_HYDRA: (no stable unauth marker derived — use ffuf or curl status oracle instead)"
    fi
    echo "ORACLE_FFUF: -mc 301,302,303,307,308"
    # Match 3xx explicitly (not "!= 200") — prevents 429/500/anomalous mid-attack
    # responses from triggering false SUCCESS.
    printf 'ORACLE_CURL_SUCCESS_TEST: STATUS=$(curl -s -k -o /dev/null -w '\''%%{http_code}'\'' -X POST --data-urlencode "%s=$U" --data-urlencode "%s=$P" "$URL"); [[ "$STATUS" =~ ^3[0-9][0-9]$ ]]\n' \
        "$USER_FIELD" "$PASS_FIELD"
}

# emit_oracle_api — API/JSON-class oracles.
# Fail = 4xx JSON. Success = 200 JSON (often with "token" or "success":true).
emit_oracle_api() {
    echo "ORACLE_HYDRA: S=\"token\""
    echo "ORACLE_FFUF: -mc 200"
    printf 'ORACLE_CURL_SUCCESS_TEST: [ "$(curl -s -k -o /dev/null -w '\''%%{http_code}'\'' -X POST --data-urlencode "%s=$U" --data-urlencode "%s=$P" "$URL")" = "200" ]\n' \
        "$USER_FIELD" "$PASS_FIELD"
}

# emit_oracle_basic — BASIC-class routing marker. No oracles.
emit_oracle_basic() {
    echo "ROUTE_OUT: Login Bypass Techniques Basic Auth section"
}

# ------------------------------------------------------------------------------
# Main dispatch
# ------------------------------------------------------------------------------

emit_summary() {
    echo "ORACLE_SUMMARY: class=$G_CLASS confidence=$G_CONFIDENCE"
}

dispatch() {
    case "$G_CLASS" in
        redirect)
            emit_metadata
            emit_oracle_redirect
            emit_summary
            ;;
        content)
            emit_metadata
            derive_content_markers
            emit_content_supplementary
            emit_oracle_content
            emit_summary
            ;;
        api)
            emit_metadata
            emit_oracle_api
            emit_summary
            ;;
        basic)
            emit_metadata
            emit_oracle_basic
            emit_summary
            ;;
        unusual)
            emit_metadata
            echo "BAIL: unusual fail response — status=$G_FAIL_STATUS content-type=$G_FAIL_CONTENT_TYPE (escalate to Burp Repeater + Comparer for interactive derivation)"
            ;;
        *)
            echo "BAIL: internal error — unclassified"
            exit 1
            ;;
    esac
}

main() {
    parse_args "$@"
    setup_workdir
    sample_all
    classify
    dispatch
}

# ------------------------------------------------------------------------------
# Source guard: only run main if executed, not sourced (for tests)
# ------------------------------------------------------------------------------

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
