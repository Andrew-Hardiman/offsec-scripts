# loose_creds_triage.sh
# Content-triage a candidate credential file for structured credential shapes.
# Designed to be pasted ONCE into target shell to define the `triage` function,
# then invoked per candidate file: `triage <path>`.
#
# NOT a standalone executable. File contains a shell function definition only —
# source it OR paste its contents at the target shell prompt. No shebang.
#
# Consumed by:
#   [[Loose Creds]] Step 2 — operator pastes to define `triage`, then calls
#   `triage <file>` for each LOOSE_CRED_FILE marker from Step 1.
#
# Usage (on target, after pasting the function definition):
#   triage <file>
#   → emits zero or more LOOSE_CRED_<SHAPE>[<file>]: <line>:<content> markers
#
# Output markers (one per detected match, grep-style <line>:<content> body):
#   LOOSE_CRED_PEM[<file>]: <line>:<content>       PEM PRIVATE KEY header
#   LOOSE_CRED_HASH[<file>]: <line>:<content>      user:hash or bare $-prefixed hash
#   LOOSE_CRED_URL[<file>]: <line>:<content>       scheme://user:pass@ URL-embedded
#   LOOSE_CRED_KV[<file>]: <line>:<content>        keyword=value / keyword: value / env-shape VAR=value
#   LOOSE_CRED_USERPASS[<file>]: <line>:<content>  <word>:<plaintext-value> catch-all (broadest)
#
# Silence when a file was read but no shape matched is intentional: a file
# named cred-suggestively but with genuinely no cred content deserves no
# operator attention. Playbook Step 2 catches residual bare-password /
# unstructured FN risk via manual `cat` fallback.
#
# DETECTOR PRIORITY & DEDUP:
#   Detectors run in order PEM → HASH → URL → KV → USERPASS (most specific
#   first). If the SAME LINE matches multiple detectors, only the first
#   emits — prevents duplicate markers on lines like `password:$6$salt$hash`
#   (would otherwise emit under HASH and KV both). USERPASS acts as catch-all.
#
# BINARY FILES:
#   grep -I skips files detected as binary. Hits inside compiled objects
#   (.so/.o/.a) are outside scope — operator can `strings` manually if needed.
#
# FN AWARENESS (operator: know what triage does NOT catch):
#   - Bare passwords with NO structural markers ("just PDLrCVl1pLD91U0JMmCz"
#     alone on a line, no user prefix, no keyword) — undetectable
#     structurally. Files with zero triage markers may still contain such a
#     password; fall back to manual `cat` per Step 2.
#   - Bare hex hashes without $-prefix (raw MD5/SHA1/SHA256/SHA512). Too many
#     FPs (UUIDs, git SHAs, checksums) to detect structurally.
#   - Multi-line creds (except PEM which detects on the BEGIN line only —
#     operator cats surrounding lines to get the full block).
#
# ARG VALIDATION (verbose to stderr — under exam pressure, silent failure
# on missing/unreadable arg is worse than an obvious error line):
#   No arg              → usage to stderr, return 1
#   File not found      → error to stderr, return 1
#   Not a regular file  → error to stderr, return 1
#   Not readable        → error to stderr, return 1
#
# Cleanup after Step 2: `unset -f triage` removes the function from the session.

triage() {
    local file="$1"

    if [ -z "$file" ]; then
        echo "usage: triage <file>" >&2
        return 1
    fi
    if [ ! -e "$file" ]; then
        echo "triage: $file: not found" >&2
        return 1
    fi
    if [ ! -f "$file" ]; then
        echo "triage: $file: not a regular file" >&2
        return 1
    fi
    if [ ! -r "$file" ]; then
        echo "triage: $file: not readable" >&2
        return 1
    fi

    local PEM_RE='-----BEGIN [A-Z ]*PRIVATE KEY-----'
    local HASH_RE='^[[:space:]]*[a-zA-Z_][a-zA-Z0-9_.-]*:(\$[a-z0-9]+\$|\{S?[A-Z]+\})|^[[:space:]]*(\$[125]\$|\$6\$|\$2[axy]?\$|\$apr1\$|\$argon2[id]{0,2}\$|\{S?SHA\}|\{S?MD5\})'
    local URL_RE='[a-z][a-z0-9+.-]*://[^:/@[:space:]]+:[^:/@[:space:]]+@'
    local KV_RE='(password|passwd|pwd|secret|token|credential|api[_-]?key|access[_-]?key|auth[_-]?token)[[:space:]]*[=:][[:space:]]*[^[:space:]]|^[[:space:]]*(export[[:space:]]+)?[a-zA-Z0-9_]*(pass(word|wd)?|pwd|secret|token|api[_-]?key|cred|auth[_-]?token)[a-zA-Z0-9_]*='
    local USERPASS_RE='^[a-zA-Z_][a-zA-Z0-9_.-]*:[^$\{[:space:]]'
    # PASSWD_FORMAT_RE: signature of /etc/passwd (and /etc/shadow with `!`/`*`/empty
    # in the password slot) — `name:<placeholder>:UID:GID:...`. USERPASS regex
    # matches these lines because the placeholder byte (`x`, `!`, `*`, empty) is
    # not a hash prefix; without a filter, a passwd-format file surfaced by enum
    # (e.g. /etc/passwd.org, /etc/passwd.bak) explodes into dozens of USERPASS
    # markers. Detector filter (below) suppresses USERPASS emission on any line
    # matching this shape. Precise: requires TWO consecutive digit fields
    # (UID:GID:) which is passwd-specific — legitimate multi-colon creds with a
    # single numeric field (e.g. `admin:pw:12345:extra`) don't match and still
    # emit. Shadow-format lines with a real hash (`root:$6$...`) are caught by
    # HASH before this filter runs.
    local PASSWD_FORMAT_RE='^[^:]+:[^:]*:[0-9]+:[0-9]+:'

    local SEEN_LINES=""
    local detector re match line_num

    for detector in PEM HASH URL KV USERPASS; do
        case "$detector" in
            PEM)      re="$PEM_RE" ;;
            HASH)     re="$HASH_RE" ;;
            URL)      re="$URL_RE" ;;
            KV)       re="$KV_RE" ;;
            USERPASS) re="$USERPASS_RE" ;;
        esac
        while IFS= read -r match; do
            line_num="${match%%:*}"
            case "$SEEN_LINES" in
                *"|$line_num|"*) continue ;;
            esac
            # USERPASS-only pre-filter: skip passwd-format lines
            # (name:x:UID:GID:...). Placeholder value `x`/`!`/`*`/empty
            # matches USERPASS_RE but never carries a plaintext cred.
            if [ "$detector" = "USERPASS" ]; then
                local content="${match#*:}"
                if [[ "$content" =~ $PASSWD_FORMAT_RE ]]; then
                    continue
                fi
            fi
            printf 'LOOSE_CRED_%s[%s]: %s\n' "$detector" "$file" "$match"
            SEEN_LINES="$SEEN_LINES|$line_num|"
        done < <(grep -aniEI -- "$re" "$file" 2>/dev/null)
    done
}
