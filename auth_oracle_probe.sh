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
# CSRF / forwarded static state:
#   SUPPORTED for STATIC carriers. Statefulness Probe (WAC 1.6) classifies each
#   cookie / hidden field (incl. any CSRF token) as static or rotating. On
#   ROUTE: shell it forwards the static values; the caller passes them via
#   --cookies / --hidden-fields and this script bakes them into both its samples
#   and the emitted oracle. ROTATING carriers → Probe emits ROUTE: burp and this
#   script is NOT invoked → escalate to Burp per Automating Fresh State in Burp
#   (rotating tokens need per-request session-handling, incompatible with
#   stateless scripted probing). Gate is Probe's ROUTE; this script does not
#   re-verify token presence or rotation.
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

# Chrome UA — curl's default UA trips WAF UA filters. Sent on every request
# (GET UA-only; POST adds Referer+Origin — see sample_get / sample_post).
# MUST stay byte-identical to statefulness_probe.sh BROWSER_UA (drift-warning).
BROWSER_UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"

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

# Forwarded state from Statefulness Probe (WAC 1.6). Empty = none forwarded.
#   COOKIES        — browser Cookie format "n1=v1; n2=v2" (STATIC_COOKIES) → curl -b
#   HIDDEN_FIELDS  — POST-body format "n1=v1&n2=v2", values already URL-encoded
#                    (STATIC_HIDDEN_FIELDS) → curl --data (raw; NOT --data-urlencode,
#                    which would double-encode the already-encoded values)
#   EXTRA_HEADERS  — single operator-supplied header "Name: value" → curl -H
COOKIES=""
HIDDEN_FIELDS=""
EXTRA_HEADERS=""

# Derived from parsed args (set in main, after parse_args). Consumed by
# sample_post AND all emit_oracle_* functions — centralised so the emitted
# oracle POSTs with byte-identical headers to what the probe sampled with.
# AUTHORITY omits the scheme-default port (80/http, 443/https) to match browser
# URL serialization; REFERER/ORIGIN and the connection URLs all derive from it.
AUTHORITY=""
REFERER=""
ORIGIN=""

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
                            [--cookies=<s>] [--hidden-fields=<s>] [--extra-headers=<s>] \
                            [--scheme=<http|https>] [--delay=<ms>] [--verbose]

Required flags:
  --host=<h>          Target hostname or IP
  --port=<p>          Target HTTP/HTTPS port
  --login-path=<p>    Login form GET path (e.g., /login.php)
  --form-action=<p>   Login form POST action path (e.g., /login.php)
  --user-field=<f>    Login form username field name (e.g., email)
  --pass-field=<f>    Login form password field name (e.g., password)

Optional flags:
  --cookies=<s>       Forwarded static cookies, browser Cookie format
                      "n1=v1; n2=v2" (Statefulness Probe STATIC_COOKIES). curl -b.
  --hidden-fields=<s> Forwarded static hidden fields, POST-body format
                      "n1=v1&n2=v2", values already URL-encoded (Statefulness
                      Probe STATIC_HIDDEN_FIELDS). curl --data (raw).
  --extra-headers=<s> One operator-supplied header "Name: value" (e.g. a
                      JS-set X-CSRF-Token manually extracted). curl -H.
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
            --cookies=*)      COOKIES="${1#--cookies=}"; shift ;;
            --hidden-fields=*) HIDDEN_FIELDS="${1#--hidden-fields=}"; shift ;;
            --extra-headers=*) EXTRA_HEADERS="${1#--extra-headers=}"; shift ;;
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

# authority — scheme://host[:port], omitting the port when it is the scheme
# default (80 for http, 443 for https), matching how browsers serialize URLs
# (and thus Referer/Origin). Connection URLs use it too: http://host and
# http://host:80 hit the same endpoint, so omission is connection-safe.
authority() {
    if { [ "$SCHEME" = "http" ]  && [ "$PORT" = "80" ]; } || \
       { [ "$SCHEME" = "https" ] && [ "$PORT" = "443" ]; }; then
        printf '%s://%s' "$SCHEME" "$HOST"
    else
        printf '%s://%s:%s' "$SCHEME" "$HOST" "$PORT"
    fi
}

# sample_get <path> <name> — GET path, store body/hdr/meta under <name>.*
sample_get() {
    local path="$1" name="$2"
    local url="${AUTHORITY}${path}"
    curl -s -k \
         -o "${WORK_DIR}/${name}.body" \
         -D "${WORK_DIR}/${name}.hdr" \
         --max-time "$TIMEOUT_SEC" \
         -H "User-Agent: $BROWSER_UA" \
         -w 'status=%{http_code}|size=%{size_download}|redirect=%{redirect_url}|type=%{content_type}\n' \
         "$url" > "${WORK_DIR}/${name}.meta" 2>/dev/null
    return $?
}

# sample_post <user> <pass> <name> — POST form-action with user/pass, store as <name>.*
# Always-on browser headers (UA/Referer/Origin). Forwarded state (cookies /
# hidden fields / extra header) appended only when non-empty — MUST match the
# emitted oracle's baked flags (see emit_extra_flags) so the probe samples the
# same request the attack will send.
sample_post() {
    local user="$1" pass="$2" name="$3"
    local url="${AUTHORITY}${FORM_ACTION}"
    local args=(
        -s -k -X POST
        -o "${WORK_DIR}/${name}.body"
        -D "${WORK_DIR}/${name}.hdr"
        --max-time "$TIMEOUT_SEC"
        -H "User-Agent: $BROWSER_UA"
        -H "Referer: $REFERER"
        -H "Origin: $ORIGIN"
    )
    [ -n "$COOKIES" ]       && args+=(-b "$COOKIES")
    [ -n "$EXTRA_HEADERS" ] && args+=(-H "$EXTRA_HEADERS")
    args+=(--data-urlencode "${USER_FIELD}=${user}" --data-urlencode "${PASS_FIELD}=${pass}")
    # Hidden fields arrive pre-URL-encoded → --data (raw), not --data-urlencode.
    [ -n "$HIDDEN_FIELDS" ] && args+=(--data "$HIDDEN_FIELDS")
    args+=(-w 'status=%{http_code}|size=%{size_download}|redirect=%{redirect_url}|type=%{content_type}\n')
    curl "${args[@]}" "$url" > "${WORK_DIR}/${name}.meta" 2>/dev/null
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

# emit_hdr_flags — " -b <q> -H <q>" for forwarded cookies / extra-header, or
# empty. %q-escaped so the values re-parse correctly when the operator pastes
# the emitted oracle into bash. Placed among headers to mirror sample_post.
emit_hdr_flags() {
    local seg=""
    [ -n "$COOKIES" ]       && seg+=" -b $(printf '%q' "$COOKIES")"
    [ -n "$EXTRA_HEADERS" ] && seg+=" -H $(printf '%q' "$EXTRA_HEADERS")"
    printf '%s' "$seg"
}

# emit_data_flags — " --data <q>" for forwarded hidden fields (pre-URL-encoded),
# or empty. Appended after user/pass data to mirror sample_post.
emit_data_flags() {
    [ -n "$HIDDEN_FIELDS" ] && printf ' --data %s' "$(printf '%q' "$HIDDEN_FIELDS")"
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
    printf 'ORACLE_CURL_SUCCESS_TEST: R=$(curl -s -k -o /dev/null -w '\''%%{redirect_url}'\'' -X POST -H '\''User-Agent: %s'\'' -H '\''Referer: %s'\'' -H '\''Origin: %s'\''%s --data-urlencode "%s=$U" --data-urlencode "%s=$P"%s "$URL") && [ -n "$R" ] && ! printf '\''%%s'\'' "$R" | grep -qE '\''^https?://[^/]+%s'\''\n' \
        "$BROWSER_UA" "$REFERER" "$ORIGIN" "$(emit_hdr_flags)" "$USER_FIELD" "$PASS_FIELD" "$(emit_data_flags)" "$fail_loc_path"
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
    printf 'ORACLE_CURL_SUCCESS_TEST: STATUS=$(curl -s -k -o /dev/null -w '\''%%{http_code}'\'' -X POST -H '\''User-Agent: %s'\'' -H '\''Referer: %s'\'' -H '\''Origin: %s'\''%s --data-urlencode "%s=$U" --data-urlencode "%s=$P"%s "$URL"); [[ "$STATUS" =~ ^3[0-9][0-9]$ ]]\n' \
        "$BROWSER_UA" "$REFERER" "$ORIGIN" "$(emit_hdr_flags)" "$USER_FIELD" "$PASS_FIELD" "$(emit_data_flags)"
}

# emit_oracle_api — API/JSON-class oracles.
# Fail = 4xx JSON. Success = 200 JSON (often with "token" or "success":true).
emit_oracle_api() {
    echo "ORACLE_HYDRA: S=\"token\""
    echo "ORACLE_FFUF: -mc 200"
    printf 'ORACLE_CURL_SUCCESS_TEST: [ "$(curl -s -k -o /dev/null -w '\''%%{http_code}'\'' -X POST -H '\''User-Agent: %s'\'' -H '\''Referer: %s'\'' -H '\''Origin: %s'\''%s --data-urlencode "%s=$U" --data-urlencode "%s=$P"%s "$URL")" = "200" ]\n' \
        "$BROWSER_UA" "$REFERER" "$ORIGIN" "$(emit_hdr_flags)" "$USER_FIELD" "$PASS_FIELD" "$(emit_data_flags)"
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

# emit_run_config — boxed run-config preamble (stdout, emitted first on every
# run incl. bail paths). Makes always-on headers visible (never in invocation)
# and echoes forwarded-state flags as name=value (empty → (none)). Flag-name
# keys mirror the CLI vocabulary so the echo reads like the invocation.
emit_run_config() {
    echo "=============================================================================="
    echo " auth_oracle_probe.sh — run config"
    echo "=============================================================================="
    echo " Target        : ${AUTHORITY}"
    echo " Login path    : ${LOGIN_PATH}   (GET, sampled first)"
    echo " Form action   : ${FORM_ACTION}   (POST, wrong-cred samples)"
    echo " Fields        : ${USER_FIELD} / ${PASS_FIELD}"
    echo " Delay         : ${DELAY_MS} ms"
    echo ""
    echo " Always-on headers (every POST):"
    echo "   User-Agent  : ${BROWSER_UA}"
    echo "   Referer     : ${REFERER}"
    echo "   Origin      : ${ORIGIN}"
    echo ""
    echo " Forwarded state (from Statefulness Probe; passed via flags):"
    echo "   --cookies       : ${COOKIES:-(none)}"
    echo "   --hidden-fields : ${HIDDEN_FIELDS:-(none)}"
    echo "   --extra-headers : ${EXTRA_HEADERS:-(none)}"
    echo ""
    echo " Side-effect     : issues up to 3 wrong-cred POSTs to ${FORM_ACTION}"
    echo "                   → counts toward any per-IP failed-attempt threshold"
    echo "=============================================================================="
    echo ""
}

# emit_coverage_warnings — boxed, informational; always emitted (self-contained
# so an operator entering cold sees every gap without relying on the Statefulness
# Probe preamble upstream). These do not change CLASS or the emitted oracle; they
# are conditions under which the oracle can be silently wrong.
emit_coverage_warnings() {
    echo "=============================================================================="
    echo "COVERAGE WARNINGS (informational — always emitted; may silently invalidate the oracle below)"
    echo "=============================================================================="
    echo "- CAPTCHA / anti-bot on the login page not defeatable shell-side — samples hit the challenge, oracle is garbage; if visible, escalate to Burp + manual browser."
    echo "- JS-computed POST fields (client-side nonce/HMAC/signature) not detectable — samples and attack both fail for the wrong reason; inspect form JS in browser dev tools if oracle underperforms."
    echo "- Multi-step / gated success (email-verify, MFA after first factor) not detectable — success and fail may both redirect; if login is multi-step, verify a real success manually first."
    echo "- POST-gated WAF not detectable (Statefulness Probe is GET-only) — may 403 (loud BAIL) or return a 200 interstitial (silent garbage oracle); if hits are implausible, inspect a raw sample in Burp."
    echo "=============================================================================="
    echo ""
}

main() {
    parse_args "$@"
    AUTHORITY="$(authority)"
    REFERER="${AUTHORITY}${LOGIN_PATH}"
    ORIGIN="${AUTHORITY}"
    emit_run_config
    emit_coverage_warnings
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
