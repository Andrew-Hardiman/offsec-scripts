#!/bin/bash
# config_enum.sh
# Enumerate readable config files across system trees and scan for credential patterns.
# Outputs explicit markers consumed by:
#   Linux Privilege Escalation Checksheet 'Credential Harvesting' -> Config Files (pre-root)
#   Linux Credential Extraction Checksheet -> Config Files (post-root, future)
#
# Privilege-agnostic via conditional -readable filter. find -readable calls access(2)
# which checks RUID, not EUID — so in a SUID drop-and-launch post-root context
# (RUID=unprivileged, EUID=0), naive -readable would underreport. We detect this
# context and skip the -readable filter so grep's open() (which uses EUID) covers
# the full root-accessible set.
#
# Workflow handling:
#   Pre-root (EUID=RUID=user):       keep -readable; filters to what user can read.
#   Sudo/su post-root (EUID=RUID=0): keep -readable; RUID=0 passes everything.
#   SUID post-root (EUID=0,RUID!=0): SKIP -readable; find returns all files, grep
#                                     opens via EUID=0. Full root view.
#
# Output markers:
#   CONFIG_CRED[<file>]: <line>   - credential pattern hit (one per matched line,
#                                    grep-prefixed with line number)
#   CONFIG_FOUND: <file>          - readable file with no regex match
#                                   (informational only; not an action trigger.
#                                    If a real engagement surfaces a missed pattern,
#                                    update PATTERN below + add regression test in
#                                    config_enum_tests.sh, then commit.)
#   CONFIG_EMPTY                  - no readable config files found
#
# KNOWN LIMITATIONS (revisit if engagement surfaces a miss):
#   - Multi-line YAML values (key on one line, value on next with indent) NOT matched.
#     grep is line-oriented; multi-line YAML would need pcregrep -M or awk state machine.
#     Most common multi-line YAML cred form is inline PEM keys, caught by PEM-BEGIN header.
#   - XML namespaced elements (e.g. <ns:password>secret</ns:password>) NOT matched.
#     Bare-element form <password> works. Fix is regex prefix `<([a-zA-Z][a-zA-Z0-9_]*:)?`.
#   - Symlinks NOT followed (-L deferred). Shared-hosting layouts where /var/www/<site>
#     symlinks into /home/<user>/public_html will miss the symlinked content.
#   - BusyBox/Alpine targets: \b is a GNU grep extension. Requires regex rewrite using
#     explicit boundary char classes (e.g. (^|[^a-zA-Z0-9_]) ... ($|[^a-zA-Z0-9_])).
#   - .netrc empty values (`password ` with no value) intentionally NOT matched; netrc
#     keyword without value is unusable as a credential.

# ============================================================
# CREDENTIAL ALLOW-LIST (cred-bearing key names; bounded growth)
# ============================================================
# Maintenance: append new compounds + add regression test when
# engagements surface misses. Direct script edit, not Vault_Strategy.
#
# Compound prefix: (db|admin|root|user|mysql|postgres|mongo|redis)
# Compound base:   (pass|password|passwd|pwd) via _(pass(word|wd)?|pwd)
# Standalones:     password, passwd, pwd, secret, token, api_key, etc.
K='((db|admin|root|user|mysql|postgres|mongo|redis)_(pass(word|wd)?|pwd)|pgpassword|password|password_hash|passwd|pwd|secret|secret_key|jwt_secret|app_secret|token|auth|api[_-]?key|api[_-]?token|api[_-]?secret|client[_-]?secret|access[_-]?key|aws_secret_access_key|aws_access_key_id|private_key)'

# ============================================================
# MASTER PATTERN — per-syntax alternations sharing the allow-list above
# ============================================================
# Each alternation anchored to one config-file syntax form.
# \b uses GNU grep -E extension; portable across Kali/Debian/Ubuntu/CentOS/RHEL.
# For BusyBox/Alpine targets \b would need replacement with explicit boundary chars.
# Empty values are matched (key with no value is itself a finding — e.g. blank-password auth).
#
# INI/YAML ANCHORING (Fix D, June 2026): the INI/properties/YAML alternation is anchored
# to start-of-line with optional whitespace + optional comment + optional dot-namespace
# prefix. Without anchoring, mid-line allow-list keyword occurrences inside template values
# (e.g. exim's `#  server_prompts = <| Username: | Password:`) matched as if Password: was
# a config key. Anchoring requires the keyword to be at the *start* of a statement.
#
#   Optional dot-prefix: covers Java/Spring-style `spring.datasource.db_password=...`
#                        (one or more identifier chars ending in `.`)
#   Optional [#;]?:      preserves T31 (commented-out credential still flagged)
#
# XML ATTRIBUTE ALTERNATION (Fix D companion): the anchored INI alternation no longer
# catches XML attribute syntax like `<user password="secret" />` (T10). Added a separate
# unanchored alternation requiring the literal `="` sequence — XML-attribute syntax
# (also matches shell `KEY="val"` line-start, which is fine; that's a real cred form).
#
# KNOWN FALSE-NEGATIVE: multi-statement config lines like `setting=foo; password=bar`
# in non-.sh config files (.conf/.ini/.yml/etc.) no longer match the second assignment.
# This is rare in real config files (one-statement-per-line is the convention).
# Shell scripts retain mid-line matching via SH_VAR_PATTERN added to the .sh dispatch.
PATTERN="^[[:space:]]*[#;]?[[:space:]]*([a-zA-Z_][a-zA-Z0-9_.-]*\\.)?\\b${K}\\b[[:space:]]*[=:]"  # anchored INI/properties/.env, YAML
PATTERN="${PATTERN}|\\b${K}\\b=\""                                  # XML attribute (mid-line, requires =")
PATTERN="${PATTERN}|\"${K}\"[[:space:]]*:"                          # JSON
PATTERN="${PATTERN}|\\\$${K}\\b[[:space:]]*="                       # PHP variable
PATTERN="${PATTERN}|define[[:space:]]*\\([[:space:]]*['\"]${K}['\"]" # PHP define()
PATTERN="${PATTERN}|<${K}\\b[^>]*>"                                  # XML element
PATTERN="${PATTERN}|-----BEGIN[ A-Z]+PRIVATE KEY-----"               # PEM private key header (operator cats file for body)
PATTERN="${PATTERN}|://[^/[:space:]:]+:[^@[:space:]]*@"              # URL-embedded creds (empty password permitted)
PATTERN="${PATTERN}|(gh[psuor]_|xox[bpas]-|sk_live_|sk_test_|Bearer )"  # service tokens (GitHub, Slack, Stripe, generic Bearer)

# Format-specific patterns for files where the master regex doesn't apply.
# .netrc/.ldaprc: space-delimited keyword + value (no prose context within these files)
NETRC_PATTERN='\b(password|account|bindpw)\b[[:space:]]+[^[:space:]]+'

# .sh deployment scripts: CLI-flag credential syntax (mysql -p<val>, --password=, sshpass, etc.)
# Reused from history_enum.sh's CLI alternations — these forms don't appear in config files
# but are dominant in bespoke shell deployment scripts (backup.sh, deploy.sh, etc.).
SH_CLI_PATTERN='(mysql|mysqldump|mariadb|psql|pg_dump|mongo|mongosh|redis-cli)[^|;]*-p[^- ]|--password|--pwd|--pass=|--secret=|--api[_-]?key|--token=|sshpass'

# .sh variable assignment — unanchored allow-list keyword + `=`. Matches shell mid-line
# assignment forms that the anchored master PATTERN (Fix D) no longer catches:
#   export DB_PASS=secret      let password=foo         declare -x SECRET=foo
#   set_x; password=foo        cmd1 && password=oops || cmd2
# Restricted to .sh dispatch only (shell convention permits multi-statement per line; the
# anchored config-file PATTERN deliberately doesn't, to kill template/embedded FPs).
SH_VAR_PATTERN="\\b${K}\\b[[:space:]]*="

# .ovpn OpenVPN configs: space-delimited directive + file path. Master regex doesn't apply
# (OpenVPN uses neither = nor : separators — just directive whitespace path).
# Only credential-bearing directives included; ca/cert/crl-verify reference public material
# (not credentials) and are deliberately excluded.
#   auth-user-pass <file>   user/password file (line1=user, line2=password)
#   key <file>              client private key file
#   secret <file>           static key file (used in --secret mode)
#   tls-auth <file>         TLS HMAC auth key file
#   tls-crypt <file>        TLS encrypt key file
#   tls-crypt-v2 <file>     TLSv2 encrypt key file
#   pkcs12 <file>           PKCS#12 archive (contains private key + cert)
# Anchored to start-of-line with optional comment char (consistent with master PATTERN
# T31 behavior: commented-out directives may reference old-but-still-active credential files).
# Trailing [[:space:]]+[^[:space:]] requires at least one space + non-space arg (excludes
# bare directives that would prompt interactively, but those have no file to read anyway).
OVPN_PATTERN='^[[:space:]]*[#;]?[[:space:]]*(auth-user-pass|key|secret|tls-auth|tls-crypt|tls-crypt-v2|pkcs12)[[:space:]]+[^[:space:]]'

# /etc/fstab: CIFS/SMB mount lines carrying creds inline in the comma-separated
# options column (column 4) or pointing to a cred file via credentials=. Master
# PATTERN doesn't apply — fstab is whitespace-column + comma-option syntax,
# neither = nor : separated at line-start. Cred-bearing CIFS option keys per
# mount.cifs(8): username, user, password, credentials. Anchor: start-of-line OR
# comma/whitespace boundary, so embedded substrings (e.g. `mypassword` inside a
# longer token) don't match. Empty values are matched (consistent with rest of
# script — key with empty value is itself a finding).
FSTAB_PATTERN='(^|[,[:space:]])(username|user|password|credentials)='

# ============================================================
# PRIVILEGE-CONTEXT DETECTION (sets $READABLE array used in each find call below)
# ============================================================
# id -u returns EUID; id -ru returns RUID. When EUID=0 but RUID!=0 we're in a SUID
# drop-and-launch context where -readable (RUID-based via access(2)) would filter
# too aggressively. In that one case we skip the filter; grep's open() uses EUID
# and covers the full root-accessible set.
if [ "$(id -u)" = "0" ] && [ "$(id -ru)" != "0" ]; then
    READABLE=()
else
    READABLE=(-readable)
fi

# ============================================================
# FILE ENUMERATION (three tree-classes)
# ============================================================
# All find blocks: "${READABLE[@]}" -type f -size -1048576c
# IMPORTANT on -size: use -1048576c (bytes) not -1M. find rounds size up to next unit,
# so -size -1M only matches empty files (any non-empty file rounds up to 1M, failing
# <1M). -1048576c is precise: matches files strictly under 1 MiB.
# Symlinks NOT followed (-L deferred; revisit if engagement surfaces shared-hosting
# layout miss).

FILES=()

# --- Tree-class 1: System config trees ---
# /etc/, /usr/local/etc/ — extension glob + format-specific named files, maxdepth 4
#
# INFRASTRUCTURE-CONFIG EXCLUSIONS: well-known files in /etc whose purpose is
# structurally non-credential — these are pure system infrastructure config
# (name-service, PAM, network registries, linker). Their keyword vocabulary
# overlaps with credential keywords (passwd: in NSS, auth in PAM, etc.) but the
# values are never usable credentials. Path-based exclusion (not name-based) so
# a custom file in /opt/myapp/nsswitch.conf is still scanned.
# The */etc/ glob prefix is intentional: matches both real /etc/ and test
# fixtures at $TESTDIR/etc/. Grows additively as new infra-FP classes surface.
while IFS= read -r f; do
    FILES+=("$f")
done < <(find /etc /usr/local/etc -maxdepth 4 "${READABLE[@]}" -type f -size -1048576c \
    -not \( -path '*/etc/nsswitch.conf' \
            -o -path '*/etc/pam.conf' -o -path '*/etc/pam.d/*' \
            -o -path '*/etc/services' -o -path '*/etc/protocols' \
            -o -path '*/etc/hosts.allow' -o -path '*/etc/hosts.deny' \
            -o -path '*/etc/ld.so.conf' -o -path '*/etc/ld.so.conf.d/*' \) \
    \( -name '*.conf' -o -name '*.cnf' -o -name '*.cfg' -o -name '*.ini' \
       -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' -o -name '*.env' \
       -o -name '*.toml' -o -name '*.properties' -o -name '*.xml' \
       -o -name '*.ovpn' \
       -o -name 'fstab' \
       -o -name '.htpasswd' -o -name '.pgpass' \
       -o -name '.netrc' -o -name '.ldaprc' \) 2>/dev/null)

# --- Tree-class 2: User homes ---
# /root, /home/* (derived from /etc/passwd interactive users) — named-file allow-list, maxdepth 3
# Interactive users: UID 0 or >= 1000, real shell (excludes nologin/false/sync/halt/shutdown)
HOMES=$(awk -F: '($3 == 0 || $3 >= 1000) && $7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $6}' /etc/passwd | sort -u)
while IFS= read -r h; do
    [ -d "$h" ] || continue
    while IFS= read -r f; do
        FILES+=("$f")
    done < <(find "$h" -maxdepth 3 "${READABLE[@]}" -type f -size -1048576c \
        \( -name '.my.cnf' -o -name '.pgpass' -o -name '.netrc' -o -name '.ldaprc' \
           -o -name '.git-credentials' -o -name '.npmrc' -o -name '.env' \
           -o -name '.htpasswd' \
           -o -name '*.ovpn' \
           -o -path '*/.aws/credentials' -o -path '*/.aws/config' \
           -o -path '*/.docker/config.json' -o -path '*/.kube/config' \) 2>/dev/null)
done <<< "$HOMES"

# --- Tree-class 3a: App roots (web) — /var/www/, /srv/ ---
# Both named-file allow-list + extension glob; includes .sh for bespoke deployment scripts.
# Unbounded depth — apps nest (e.g. /var/www/html/<site>/wp-content/plugins/<plugin>/...).
for tree in /var/www /srv; do
    [ -d "$tree" ] || continue
    while IFS= read -r f; do
        FILES+=("$f")
    done < <(find "$tree" "${READABLE[@]}" -type f -size -1048576c \
        \( -name 'wp-config.php' -o -name 'configuration.php' \
           -o -name 'settings.py' -o -name 'database.yml' -o -name 'secrets.yml' \
           -o -name 'application.yml' -o -name 'application.properties' \
           -o -name 'config.inc.php' -o -name 'LocalSettings.php' -o -name 'web.config' \
           -o -name '.htpasswd' -o -name '.pgpass' \
           -o -name '.netrc' -o -name '.ldaprc' \
           -o -name '*.env' -o -name '*.yml' -o -name '*.yaml' \
           -o -name '*.json' -o -name '*.properties' -o -name '*.sh' \
           -o -name '*.ovpn' \) 2>/dev/null)
done

# --- Tree-class 3b: App roots (third-party) — /opt/ ---
# Same patterns as 3a MINUS .sh — packaged-app launcher dirs (elasticsearch/jira/gitlab)
# can explode .sh count without commensurate cred yield.
[ -d /opt ] && while IFS= read -r f; do
    FILES+=("$f")
done < <(find /opt "${READABLE[@]}" -type f -size -1048576c \
    \( -name 'wp-config.php' -o -name 'configuration.php' \
       -o -name 'settings.py' -o -name 'database.yml' -o -name 'secrets.yml' \
       -o -name 'application.yml' -o -name 'application.properties' \
       -o -name 'config.inc.php' -o -name 'LocalSettings.php' -o -name 'web.config' \
       -o -name '.htpasswd' -o -name '.pgpass' \
       -o -name '.netrc' -o -name '.ldaprc' \
       -o -name '*.env' -o -name '*.yml' -o -name '*.yaml' \
       -o -name '*.json' -o -name '*.properties' \
       -o -name '*.ovpn' \) 2>/dev/null)

# Deduplicate across tree-classes (defensive)
if [ ${#FILES[@]} -gt 0 ]; then
    mapfile -t FILES < <(printf '%s\n' "${FILES[@]}" | sort -u)
fi

# ============================================================
# OUTPUT
# ============================================================
if [ ${#FILES[@]} -eq 0 ]; then
    echo "CONFIG_EMPTY"
    exit 0
fi

for f in "${FILES[@]}"; do
    bname=$(basename "$f")
    case "$bname" in
        '.netrc'|'.ldaprc')
            # Format-specific: space-delimited keyword + value, no prose context in these files
            matches=$(grep -aniE "$NETRC_PATTERN" "$f" 2>/dev/null)
            ;;
        '.htpasswd'|'.pgpass')
            # Whole-file cred storage: format is bytewise-deterministic, every non-blank line is cred material
            matches=$(grep -aniE '[^[:space:]]' "$f" 2>/dev/null)
            ;;
        *.sh)
            # Shell scripts: master pattern (anchored) PLUS SH_VAR_PATTERN (unanchored mid-line
            # assignment, for export/let/declare/multi-statement forms) PLUS SH_CLI_PATTERN
            # (mysql -p<val>, --password=, sshpass, etc.).
            matches=$(grep -aniE "${PATTERN}|${SH_VAR_PATTERN}|${SH_CLI_PATTERN}" "$f" 2>/dev/null)
            ;;
        *.ovpn)
            # OpenVPN configs: directive-specific pattern (space-delim, not = or :)
            matches=$(grep -aniE "$OVPN_PATTERN" "$f" 2>/dev/null)
            ;;
        'fstab')
            # /etc/fstab CIFS/SMB mount creds in column 4 (comma-separated options)
            matches=$(grep -aniE "$FSTAB_PATTERN" "$f" 2>/dev/null)
            ;;
        *)
            matches=$(grep -aniE "$PATTERN" "$f" 2>/dev/null)
            ;;
    esac

    if [ -n "$matches" ]; then
        while IFS= read -r line; do
            echo "CONFIG_CRED[$f]: $line"
        done <<< "$matches"
    else
        echo "CONFIG_FOUND: $f"
    fi
done
