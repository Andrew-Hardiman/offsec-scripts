#!/bin/bash
# web_auth_probe.sh
#
# Probe target HTTP interface for form-based auth surfaces via common-path
# probing with redirect resolution and tiered detection.
#
# Discovers login, register, and forgot-password forms. Emits routing markers
# consumed by Web Attack Checksheet sub-blocks 1.6, 1.7, 1.8.
#
# Usage:
#   web_auth_probe.sh <host> <port> --mode=<login|register|forgot> \
#                     [--scheme=<http|https>] [--verbose]
#
# Marker output contract:
#
#   Per-path markers (per-probe, one per path):
#     {LOGIN|REGISTER|FORGOT}_FORM_FOUND: [<orig> → ]<final>
#         Classic pattern matched — walk mode's technique file against final URL.
#     {LOGIN|REGISTER|FORGOT}_CANDIDATE: [<orig> → ]<final> (<detail>)
#         Form present, unusual shape — eyeball to confirm before walking.
#     AUTH_CHALLENGE: [<orig> → ]<final> (code=401 scheme=<scheme>)
#         HTTP-level auth (Basic, Bearer, Digest, etc.) — different attack path.
#         Informational: WAC has no dedicated Basic Auth sub-block currently.
#     RESTRICTED: [<orig> → ]<final> (code=403)
#         Path exists but forbidden — note for gobuster correlation.
#     METHOD_MISMATCH: <orig> (code=405)
#         Path exists but rejects GET — may be POST-only auth endpoint.
#     SERVER_ERROR: <orig> (code=<c>)
#         5xx response — transient or real-path-with-issue. Note for later.
#     NO_FORM: [<orig> → ]<final> (code=200)
#         Live path with 200 response, no <form> element found.
#     DEAD: <orig> (code=<c>)
#         404 or other clearly-non-existent (400, 410, unexpected codes).
#         SUPPRESSED BY DEFAULT — use --verbose to include in output.
#         Summary counter (dead=N) always accurate regardless of flag.
#     UNREACHABLE: <orig> (curl_exit=<n>)
#         curl failed (connection refused, timeout, DNS fail, etc.).
#
#   Summary marker (always emitted last):
#     AUTH_PROBE_SUMMARY: mode=<mode> found=<n> candidates=<n> \
#                        challenges=<n> restricted=<n> method_mismatch=<n> \
#                        server_error=<n> no_form=<n> dead=<n> unreachable=<n>
#
# Redirect handling:
#   All probes use `curl -L` (follow redirects). Final URL is authoritative.
#   If the final URL's path differs from the original probe path, the marker
#   shows "<orig> → <final_path>". Downstream <login_path>/<signup_path>/
#   <reset_path> variable in WAC = the final URL's path.
#
# Detection heuristics per mode:
#   LOGIN:
#     FOUND     = <form> present AND exactly one type=password input
#     CANDIDATE = <form> present AND no password AND (text|email|untyped) input
#                 (identifier-first / two-step login page 1)
#   REGISTER:
#     FOUND     = <form> present AND >=2 password inputs AND >=1 email input
#     CANDIDATE = <form> present AND >=2 password inputs AND no email
#                 (multi-password without email — rare register variant)
#                 OR <form> present AND 1 password AND >=1 email
#                 (single-password register variant)
#   FORGOT:
#     FOUND     = <form> present AND no password AND >=1 email input
#     CANDIDATE = <form> present AND no password AND >=1 text-like input
#                 (username-based forgot flow)
#
# Deferred (not v1):
#   - Homepage anchor-tag scraping for custom auth paths not in probe list
#   - Case-variant probing (/Login, /LOGIN — for IIS case-insensitive paths)
#   - Cookie persistence across probes (some apps require session)
#   - JSON API auth detection (separate concern; different marker family)

set -u

# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------

TIMEOUT_SEC=10   # Per-probe curl timeout
MAX_REDIRS=10    # curl max redirect chain depth

# ⚠️ DESIGN GAP — READ BEFORE ADDING MORE HARDCODED PATHS ⚠️
#
# Applies to LOGIN_PATHS, REGISTER_PATHS, FORGOT_PATHS.
#
# The hardcoded arrays cover common conventions (/login, /wp-login.php,
# /admin, /user/login, etc.) and that coverage is valuable and must be
# preserved. The gap is what they CANNOT cover: the infinite space of
# app-specific auth-path locations at any depth, of any shape:
#   - Nested with standard endpoint: /customer/login.php, /shop/signin
#   - Custom path AS the endpoint: /customer, /portal, /admin-panel
#   - Custom single-segment name: /mystore, /goto-auth, /enterprise
#   - Nested with custom endpoint: /portal/access, /site/gateway
#   - Anything else a developer typed
#
# Each addition to the arrays closes ONE location; the underlying gap
# persists.
#
# If you are here for the SECOND OR SUBSEQUENT time to add a path after
# a real-target miss, STOP. Adding more entries does not converge. Run the
# canonical playbook audit procedure from Vault_Strategy.md against this
# script — first-principles derivation, steelman every decision, enumerate
# failure axes, adversarially try to break it, bidirectional diff against
# the current script. The audit's job is to design ADDITIONAL complementary
# discovery mechanisms alongside the hardcoded arrays, not to replace them.
# Existing convention coverage must be preserved. Do NOT skip to a
# pre-baked fix; the audit exists precisely to prevent that.
#
# Coupled WAC-side defect: WAC's unauth_paths_<host>.txt sub-routine
# dispatches auth-shape paths to "4.1 / 4.2 / 4.3 Per-path processing",
# but 4.1/4.2/4.3 are host-level discovery flows that probe hardcoded
# arrays — they have no per-path mode to probe under a known base path
# (e.g. discover /mystore, then probe /mystore/login, /mystore/signin).
# The script needs a --base-path flag; WAC's sub-routine dispatch needs
# an actual Per-path processing section to call. Separate defect from the
# finite-list gap above; noted here because a comprehensive audit of the
# discovery flow must address both.
#
# Same warning in Scripts_Index.md.
#
# History: /customers/login, /customer/login added Sep 2026 (THM Walking
# An Application room miss). Warning added same session.

# LOGIN paths: extensionless (modern framework routing), .php/.aspx/.jsp
# variants (legacy stack), CMS-specific. Ordered for readability of output,
# not detection priority (all paths probed regardless of order).
LOGIN_PATHS=(
    /
    # Extensionless
    /login /signin /log-in /sign-in
    /admin
    /user/login /users/sign_in
    /auth /account/login /account/signin
    /portal /portal/login
    /customer/login /customers/login
    # PHP variants (very common in OSCP+ / CTF / legacy apps)
    /login.php /signin.php /admin.php
    # ASP.NET variants
    /login.aspx /admin.aspx /Account/Login
    # JSP / Java variants
    /login.jsp
    # HTML (static-only sites, rare)
    /login.html
    # CMS-specific
    /wp-login.php /wp-admin/
    /administrator          # Joomla admin
    /manager/html           # Tomcat manager
)

# REGISTER paths: register / signup / create-account variants.
REGISTER_PATHS=(
    /
    /register /signup /sign-up
    /create-account /create_account
    /join /account/create /account/signup
    /users/new /user/register
    /register.php /signup.php /register.aspx /register.jsp
    /wp-signup.php
    /customers/signup /customer/create
)

# FORGOT paths: forgot-password / reset / recover variants.
FORGOT_PATHS=(
    /
    /forgot-password /reset-password
    /forgot /recover /recovery
    /password-reset /password/reset
    /user/forgot /account/reset /account/forgot
    /forgot.php /reset.php
    /wp-login.php   # WordPress forgot flow: /wp-login.php?action=lostpassword
)

# ------------------------------------------------------------------------------
# Globals populated by parse_args and select_paths
# ------------------------------------------------------------------------------

HOST=""
PORT=""
MODE=""
SCHEME="http"
VERBOSE=no
PATHS=()
MODE_UPPER=""

# Counters — must be initialized (set -u) — updated per probe.
N_FOUND=0
N_CANDIDATE=0
N_CHALLENGE=0
N_RESTRICTED=0
N_METHOD_MISMATCH=0
N_SERVER_ERROR=0
N_NO_FORM=0
N_DEAD=0
N_UNREACHABLE=0

# Signal globals populated by extract_form_signals — read by classify_* funcs.
G_HAS_FORM=0
G_PW_COUNT=0
G_TEXT_COUNT=0
G_EMAIL_COUNT=0
G_ALL_INPUT_COUNT=0
G_NO_TYPE_INPUT_COUNT=0
G_CAND_DETAIL=""

# ------------------------------------------------------------------------------
# Usage / help
# ------------------------------------------------------------------------------

usage() {
    cat >&2 <<'EOF'
Usage: web_auth_probe.sh <host> <port> --mode=<login|register|forgot> [--scheme=<http|https>] [--verbose]

Positional arguments:
  <host>              Target hostname or IP
  <port>              Target HTTP/HTTPS port

Required flags:
  --mode=<mode>       Probe mode: 'login', 'register', or 'forgot'

Optional flags:
  --scheme=<scheme>   URL scheme: 'http' (default) or 'https'
  --verbose           Include DEAD markers (404s and unexpected codes) in output.
                      Default: DEAD suppressed; summary count still accurate.
  --help, -h          Show this help

See top-of-script comment for marker output contract and detection heuristics.
EOF
    exit 1
}

# ------------------------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------------------------

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --mode=*)    MODE="${1#--mode=}"; shift ;;
            --scheme=*)  SCHEME="${1#--scheme=}"; shift ;;
            --verbose)   VERBOSE=yes; shift ;;
            --help|-h)   usage ;;
            --*)         echo "ERROR: unknown flag: $1" >&2; usage ;;
            *)
                if [ -z "$HOST" ]; then HOST="$1"
                elif [ -z "$PORT" ]; then PORT="$1"
                else echo "ERROR: unexpected positional argument: $1" >&2; usage
                fi
                shift
                ;;
        esac
    done

    [ -z "$HOST" ] && { echo "ERROR: host required" >&2; usage; }
    [ -z "$PORT" ] && { echo "ERROR: port required" >&2; usage; }
    [ -z "$MODE" ] && { echo "ERROR: --mode required" >&2; usage; }

    case "$MODE" in
        login|register|forgot) ;;
        *) echo "ERROR: invalid mode '$MODE' (must be login|register|forgot)" >&2; usage ;;
    esac

    case "$SCHEME" in
        http|https) ;;
        *) echo "ERROR: invalid scheme '$SCHEME' (must be http|https)" >&2; usage ;;
    esac
}

# ------------------------------------------------------------------------------
# Select path list for mode
# ------------------------------------------------------------------------------

select_paths() {
    case "$MODE" in
        login)    PATHS=("${LOGIN_PATHS[@]}") ;;
        register) PATHS=("${REGISTER_PATHS[@]}") ;;
        forgot)   PATHS=("${FORGOT_PATHS[@]}") ;;
    esac
    MODE_UPPER="$(echo "$MODE" | tr '[:lower:]' '[:upper:]')"
}

# ------------------------------------------------------------------------------
# Signal extraction from HTML body
# ------------------------------------------------------------------------------

# count_matches <body> <pcre_regex> - count PCRE regex matches in body.
count_matches() {
    local body="$1"
    local regex="$2"
    printf '%s' "$body" | grep -Poi "$regex" 2>/dev/null | wc -l
}

# extract_form_signals <body> - populate G_* globals from body.
extract_form_signals() {
    local body="$1"

    G_HAS_FORM=$(count_matches "$body" '<form\b[^>]*>')
    G_PW_COUNT=$(count_matches "$body" "type=[\"']?password\b")
    G_TEXT_COUNT=$(count_matches "$body" "type=[\"']?(text|search|tel|url)\b")
    G_EMAIL_COUNT=$(count_matches "$body" "type=[\"']?email\b")
    G_ALL_INPUT_COUNT=$(count_matches "$body" '<input\b[^>]*>')

    # Inputs with any explicit type attribute
    local typed
    typed=$(count_matches "$body" '<input\b[^>]*type\s*=')
    G_NO_TYPE_INPUT_COUNT=$((G_ALL_INPUT_COUNT - typed))
    [ "$G_NO_TYPE_INPUT_COUNT" -lt 0 ] && G_NO_TYPE_INPUT_COUNT=0
}

# ------------------------------------------------------------------------------
# Mode-specific classifiers
# ------------------------------------------------------------------------------

# Each classify_* function:
#   Input: body (via extract_form_signals side effects on G_*)
#   Output: echoes "FORM_FOUND" | "CANDIDATE" | "NO_FORM"
#   Side effect: sets G_CAND_DETAIL when returning CANDIDATE

classify_login() {
    local body="$1"
    extract_form_signals "$body"
    G_CAND_DETAIL=""

    if [ "$G_HAS_FORM" -eq 0 ]; then
        echo "NO_FORM"
        return
    fi

    # Classic login: exactly one password input in the page
    if [ "$G_PW_COUNT" -eq 1 ]; then
        echo "FORM_FOUND"
        return
    fi

    # Identifier-first candidate: no password, but has a text/email-like input
    local username_like=$((G_TEXT_COUNT + G_EMAIL_COUNT + G_NO_TYPE_INPUT_COUNT))
    if [ "$G_PW_COUNT" -eq 0 ] && [ "$username_like" -ge 1 ]; then
        G_CAND_DETAIL="identifier-first? pw=0 text=$G_TEXT_COUNT email=$G_EMAIL_COUNT notype=$G_NO_TYPE_INPUT_COUNT"
        echo "CANDIDATE"
        return
    fi

    # Multi-password territory belongs to register mode; not our concern here.
    echo "NO_FORM"
}

classify_register() {
    local body="$1"
    extract_form_signals "$body"
    G_CAND_DETAIL=""

    if [ "$G_HAS_FORM" -eq 0 ]; then
        echo "NO_FORM"
        return
    fi

    # Classic register: password + confirm + email
    if [ "$G_PW_COUNT" -ge 2 ] && [ "$G_EMAIL_COUNT" -ge 1 ]; then
        echo "FORM_FOUND"
        return
    fi

    # Candidate 1: multi-password without email (rare no-confirm-email variant)
    if [ "$G_PW_COUNT" -ge 2 ] && [ "$G_EMAIL_COUNT" -eq 0 ]; then
        G_CAND_DETAIL="multi-pw-no-email pw=$G_PW_COUNT text=$G_TEXT_COUNT"
        echo "CANDIDATE"
        return
    fi

    # Candidate 2: single password with email (single-password register variant)
    if [ "$G_PW_COUNT" -eq 1 ] && [ "$G_EMAIL_COUNT" -ge 1 ]; then
        G_CAND_DETAIL="single-pw-with-email pw=1 email=$G_EMAIL_COUNT"
        echo "CANDIDATE"
        return
    fi

    echo "NO_FORM"
}

classify_forgot() {
    local body="$1"
    extract_form_signals "$body"
    G_CAND_DETAIL=""

    if [ "$G_HAS_FORM" -eq 0 ]; then
        echo "NO_FORM"
        return
    fi

    # Classic forgot: no password + email
    if [ "$G_PW_COUNT" -eq 0 ] && [ "$G_EMAIL_COUNT" -ge 1 ]; then
        echo "FORM_FOUND"
        return
    fi

    # Candidate: no password + username-like input (username-based forgot)
    if [ "$G_PW_COUNT" -eq 0 ] && [ "$G_TEXT_COUNT" -ge 1 ]; then
        G_CAND_DETAIL="username-based? pw=0 text=$G_TEXT_COUNT email=0"
        echo "CANDIDATE"
        return
    fi

    # Any password field on a probed forgot path is not a forgot form
    echo "NO_FORM"
}

classify_body() {
    local body="$1"
    case "$MODE" in
        login)    classify_login "$body" ;;
        register) classify_register "$body" ;;
        forgot)   classify_forgot "$body" ;;
    esac
}

# ------------------------------------------------------------------------------
# Format redirect chain
# ------------------------------------------------------------------------------

# fmt_path <orig_path> <final_url> - returns "<orig>" or "<orig> → <final_path>"
fmt_path() {
    local orig="$1"
    local final_url="$2"
    # Extract path portion of final URL (strip scheme://host[:port])
    local final_path
    final_path=$(printf '%s' "$final_url" | sed -E 's|^https?://[^/]+||')
    [ -z "$final_path" ] && final_path="/"

    if [ "$orig" = "$final_path" ]; then
        printf '%s' "$orig"
    else
        printf '%s → %s' "$orig" "$final_path"
    fi
}

# ------------------------------------------------------------------------------
# Header parsing for 401 WWW-Authenticate scheme
# ------------------------------------------------------------------------------

# extract_final_auth_scheme <header_file> - print WWW-Authenticate scheme name
# from the FINAL response's headers (last "HTTP/..." block).
# curl -D dumps headers for every response in redirect chain; we want the last.
extract_final_auth_scheme() {
    local header_file="$1"
    # Find line number of last "HTTP/" line, slice to end, grep WWW-Authenticate.
    local last_http_line
    last_http_line=$(grep -nE '^HTTP/' "$header_file" | tail -1 | cut -d: -f1)
    [ -z "$last_http_line" ] && { echo "unknown"; return; }

    local scheme
    scheme=$(sed -n "${last_http_line},\$p" "$header_file" \
        | grep -iE '^WWW-Authenticate:' | head -1 \
        | sed -E 's/^[^:]*:[[:space:]]*([A-Za-z]+).*/\1/' | tr -d '\r\n')
    [ -z "$scheme" ] && scheme="unknown"
    printf '%s' "$scheme"
}

# ------------------------------------------------------------------------------
# Probe a single path
# ------------------------------------------------------------------------------

probe_path() {
    local p="$1"
    local url="${SCHEME}://${HOST}:${PORT}${p}"

    local body_file header_file
    body_file=$(mktemp) || { echo "ERROR: mktemp failed" >&2; exit 1; }
    header_file=$(mktemp) || { echo "ERROR: mktemp failed" >&2; exit 1; }

    local final_url
    final_url=$(curl -sL -k \
        -o "$body_file" \
        -D "$header_file" \
        --max-time "$TIMEOUT_SEC" \
        --max-redirs "$MAX_REDIRS" \
        -w '%{url_effective}' \
        "$url" 2>/dev/null)
    local curl_exit=$?

    if [ $curl_exit -ne 0 ]; then
        rm -f "$body_file" "$header_file"
        echo "UNREACHABLE: $p (curl_exit=$curl_exit)"
        N_UNREACHABLE=$((N_UNREACHABLE + 1))
        return
    fi

    # Extract final HTTP code from last HTTP status line in header file
    local code
    code=$(grep -oiE '^HTTP/[0-9.]+ [0-9]+' "$header_file" | tail -1 | awk '{print $2}')

    if [ -z "$code" ]; then
        rm -f "$body_file" "$header_file"
        echo "UNREACHABLE: $p (no-http-code)"
        N_UNREACHABLE=$((N_UNREACHABLE + 1))
        return
    fi

    local body
    body=$(cat "$body_file")

    # Dispatch by HTTP code
    case "$code" in
        200)
            local classification
            classification=$(classify_body "$body")
            case "$classification" in
                FORM_FOUND)
                    echo "${MODE_UPPER}_FORM_FOUND: $(fmt_path "$p" "$final_url")"
                    N_FOUND=$((N_FOUND + 1))
                    ;;
                CANDIDATE)
                    echo "${MODE_UPPER}_CANDIDATE: $(fmt_path "$p" "$final_url") ($G_CAND_DETAIL)"
                    N_CANDIDATE=$((N_CANDIDATE + 1))
                    ;;
                NO_FORM)
                    echo "NO_FORM: $(fmt_path "$p" "$final_url") (code=200)"
                    N_NO_FORM=$((N_NO_FORM + 1))
                    ;;
            esac
            ;;
        401)
            local scheme
            scheme=$(extract_final_auth_scheme "$header_file")
            echo "AUTH_CHALLENGE: $(fmt_path "$p" "$final_url") (code=401 scheme=$scheme)"
            N_CHALLENGE=$((N_CHALLENGE + 1))
            ;;
        403)
            echo "RESTRICTED: $(fmt_path "$p" "$final_url") (code=403)"
            N_RESTRICTED=$((N_RESTRICTED + 1))
            ;;
        404)
            [ "$VERBOSE" = "yes" ] && echo "DEAD: $p (code=404)"
            N_DEAD=$((N_DEAD + 1))
            ;;
        405)
            echo "METHOD_MISMATCH: $p (code=405)"
            N_METHOD_MISMATCH=$((N_METHOD_MISMATCH + 1))
            ;;
        5*)
            echo "SERVER_ERROR: $p (code=$code)"
            N_SERVER_ERROR=$((N_SERVER_ERROR + 1))
            ;;
        *)
            # Unexpected: e.g., 3xx if -L broken, other 4xx (400, 410, 429...)
            [ "$VERBOSE" = "yes" ] && echo "DEAD: $p (code=$code)"
            N_DEAD=$((N_DEAD + 1))
            ;;
    esac

    rm -f "$body_file" "$header_file"
}

# ------------------------------------------------------------------------------
# Main loop
# ------------------------------------------------------------------------------

run_probes() {
    local p
    for p in "${PATHS[@]}"; do
        probe_path "$p"
    done

    echo "AUTH_PROBE_SUMMARY: mode=$MODE found=$N_FOUND candidates=$N_CANDIDATE challenges=$N_CHALLENGE restricted=$N_RESTRICTED method_mismatch=$N_METHOD_MISMATCH server_error=$N_SERVER_ERROR no_form=$N_NO_FORM dead=$N_DEAD unreachable=$N_UNREACHABLE"
}

main() {
    parse_args "$@"
    select_paths
    run_probes
}

# ------------------------------------------------------------------------------
# Source guard: only run main if executed, not sourced (for tests)
# ------------------------------------------------------------------------------

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
