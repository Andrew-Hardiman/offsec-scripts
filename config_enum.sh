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
#   - Double-suffix backup files (e.g. apache.conf.bak.old) — suffix-strip pre-dispatch
#     handles one suffix only; falls to default master PATTERN after first removal.

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
# /etc/, /usr/local/etc/ — extension glob + format-specific named files, maxdepth 4.
# D2: each canonical pattern is followed by its 13 backup variants
# (7 generic: .bak/.old/.orig/.backup/.sav/.save/~ + 6 pkg-mgr: .dpkg-old/.dpkg-new/
# .dpkg-dist/.rpmsave/.rpmnew/.rpmorig — pkg-mgr T-1-specific). Hand-enumerated.
#
# INFRASTRUCTURE-CONFIG EXCLUSIONS: well-known files in /etc whose purpose is
# structurally non-credential — these are pure system infrastructure config
# (name-service, PAM, network registries, linker). Their keyword vocabulary
# overlaps with credential keywords (passwd: in NSS, auth in PAM, etc.) but the
# values are never usable credentials. Path-based exclusion (not name-based) so
# a custom file in /opt/myapp/nsswitch.conf is still scanned.
# The */etc/ glob prefix is intentional: matches both real /etc/ and test
# fixtures at $TESTDIR/etc/. Trailing * (D2) extends exclusion to backup variants.
# Grows additively as new infra-FP classes surface.
while IFS= read -r f; do
    FILES+=("$f")
done < <(find /etc /usr/local/etc -maxdepth 4 "${READABLE[@]}" -type f -size -1048576c \
    -not \( -path '*/etc/nsswitch.conf*' \
            -o -path '*/etc/pam.conf*' -o -path '*/etc/pam.d/*' \
            -o -path '*/etc/services*' -o -path '*/etc/protocols*' \
            -o -path '*/etc/hosts.allow*' -o -path '*/etc/hosts.deny*' \
            -o -path '*/etc/ld.so.conf*' -o -path '*/etc/ld.so.conf.d/*' \) \
    \( -name '*.conf' \
       -o -name '*.conf.bak' -o -name '*.conf.old' -o -name '*.conf.orig' -o -name '*.conf.backup' \
       -o -name '*.conf.sav' -o -name '*.conf.save' -o -name '*.conf~' \
       -o -name '*.conf.dpkg-old' -o -name '*.conf.dpkg-new' -o -name '*.conf.dpkg-dist' \
       -o -name '*.conf.rpmsave' -o -name '*.conf.rpmnew' -o -name '*.conf.rpmorig' \
       -o -name '*.cnf' \
       -o -name '*.cnf.bak' -o -name '*.cnf.old' -o -name '*.cnf.orig' -o -name '*.cnf.backup' \
       -o -name '*.cnf.sav' -o -name '*.cnf.save' -o -name '*.cnf~' \
       -o -name '*.cnf.dpkg-old' -o -name '*.cnf.dpkg-new' -o -name '*.cnf.dpkg-dist' \
       -o -name '*.cnf.rpmsave' -o -name '*.cnf.rpmnew' -o -name '*.cnf.rpmorig' \
       -o -name '*.cfg' \
       -o -name '*.cfg.bak' -o -name '*.cfg.old' -o -name '*.cfg.orig' -o -name '*.cfg.backup' \
       -o -name '*.cfg.sav' -o -name '*.cfg.save' -o -name '*.cfg~' \
       -o -name '*.cfg.dpkg-old' -o -name '*.cfg.dpkg-new' -o -name '*.cfg.dpkg-dist' \
       -o -name '*.cfg.rpmsave' -o -name '*.cfg.rpmnew' -o -name '*.cfg.rpmorig' \
       -o -name '*.ini' \
       -o -name '*.ini.bak' -o -name '*.ini.old' -o -name '*.ini.orig' -o -name '*.ini.backup' \
       -o -name '*.ini.sav' -o -name '*.ini.save' -o -name '*.ini~' \
       -o -name '*.ini.dpkg-old' -o -name '*.ini.dpkg-new' -o -name '*.ini.dpkg-dist' \
       -o -name '*.ini.rpmsave' -o -name '*.ini.rpmnew' -o -name '*.ini.rpmorig' \
       -o -name '*.yml' \
       -o -name '*.yml.bak' -o -name '*.yml.old' -o -name '*.yml.orig' -o -name '*.yml.backup' \
       -o -name '*.yml.sav' -o -name '*.yml.save' -o -name '*.yml~' \
       -o -name '*.yml.dpkg-old' -o -name '*.yml.dpkg-new' -o -name '*.yml.dpkg-dist' \
       -o -name '*.yml.rpmsave' -o -name '*.yml.rpmnew' -o -name '*.yml.rpmorig' \
       -o -name '*.yaml' \
       -o -name '*.yaml.bak' -o -name '*.yaml.old' -o -name '*.yaml.orig' -o -name '*.yaml.backup' \
       -o -name '*.yaml.sav' -o -name '*.yaml.save' -o -name '*.yaml~' \
       -o -name '*.yaml.dpkg-old' -o -name '*.yaml.dpkg-new' -o -name '*.yaml.dpkg-dist' \
       -o -name '*.yaml.rpmsave' -o -name '*.yaml.rpmnew' -o -name '*.yaml.rpmorig' \
       -o -name '*.json' \
       -o -name '*.json.bak' -o -name '*.json.old' -o -name '*.json.orig' -o -name '*.json.backup' \
       -o -name '*.json.sav' -o -name '*.json.save' -o -name '*.json~' \
       -o -name '*.json.dpkg-old' -o -name '*.json.dpkg-new' -o -name '*.json.dpkg-dist' \
       -o -name '*.json.rpmsave' -o -name '*.json.rpmnew' -o -name '*.json.rpmorig' \
       -o -name '*.env' \
       -o -name '*.env.bak' -o -name '*.env.old' -o -name '*.env.orig' -o -name '*.env.backup' \
       -o -name '*.env.sav' -o -name '*.env.save' -o -name '*.env~' \
       -o -name '*.env.dpkg-old' -o -name '*.env.dpkg-new' -o -name '*.env.dpkg-dist' \
       -o -name '*.env.rpmsave' -o -name '*.env.rpmnew' -o -name '*.env.rpmorig' \
       -o -name '*.toml' \
       -o -name '*.toml.bak' -o -name '*.toml.old' -o -name '*.toml.orig' -o -name '*.toml.backup' \
       -o -name '*.toml.sav' -o -name '*.toml.save' -o -name '*.toml~' \
       -o -name '*.toml.dpkg-old' -o -name '*.toml.dpkg-new' -o -name '*.toml.dpkg-dist' \
       -o -name '*.toml.rpmsave' -o -name '*.toml.rpmnew' -o -name '*.toml.rpmorig' \
       -o -name '*.properties' \
       -o -name '*.properties.bak' -o -name '*.properties.old' -o -name '*.properties.orig' -o -name '*.properties.backup' \
       -o -name '*.properties.sav' -o -name '*.properties.save' -o -name '*.properties~' \
       -o -name '*.properties.dpkg-old' -o -name '*.properties.dpkg-new' -o -name '*.properties.dpkg-dist' \
       -o -name '*.properties.rpmsave' -o -name '*.properties.rpmnew' -o -name '*.properties.rpmorig' \
       -o -name '*.xml' \
       -o -name '*.xml.bak' -o -name '*.xml.old' -o -name '*.xml.orig' -o -name '*.xml.backup' \
       -o -name '*.xml.sav' -o -name '*.xml.save' -o -name '*.xml~' \
       -o -name '*.xml.dpkg-old' -o -name '*.xml.dpkg-new' -o -name '*.xml.dpkg-dist' \
       -o -name '*.xml.rpmsave' -o -name '*.xml.rpmnew' -o -name '*.xml.rpmorig' \
       -o -name '*.ovpn' \
       -o -name '*.ovpn.bak' -o -name '*.ovpn.old' -o -name '*.ovpn.orig' -o -name '*.ovpn.backup' \
       -o -name '*.ovpn.sav' -o -name '*.ovpn.save' -o -name '*.ovpn~' \
       -o -name '*.ovpn.dpkg-old' -o -name '*.ovpn.dpkg-new' -o -name '*.ovpn.dpkg-dist' \
       -o -name '*.ovpn.rpmsave' -o -name '*.ovpn.rpmnew' -o -name '*.ovpn.rpmorig' \
       -o -name 'fstab' \
       -o -name 'fstab.bak' -o -name 'fstab.old' -o -name 'fstab.orig' -o -name 'fstab.backup' \
       -o -name 'fstab.sav' -o -name 'fstab.save' -o -name 'fstab~' \
       -o -name 'fstab.dpkg-old' -o -name 'fstab.dpkg-new' -o -name 'fstab.dpkg-dist' \
       -o -name 'fstab.rpmsave' -o -name 'fstab.rpmnew' -o -name 'fstab.rpmorig' \
       -o -name '.htpasswd' \
       -o -name '.htpasswd.bak' -o -name '.htpasswd.old' -o -name '.htpasswd.orig' -o -name '.htpasswd.backup' \
       -o -name '.htpasswd.sav' -o -name '.htpasswd.save' -o -name '.htpasswd~' \
       -o -name '.htpasswd.dpkg-old' -o -name '.htpasswd.dpkg-new' -o -name '.htpasswd.dpkg-dist' \
       -o -name '.htpasswd.rpmsave' -o -name '.htpasswd.rpmnew' -o -name '.htpasswd.rpmorig' \
       -o -name '.pgpass' \
       -o -name '.pgpass.bak' -o -name '.pgpass.old' -o -name '.pgpass.orig' -o -name '.pgpass.backup' \
       -o -name '.pgpass.sav' -o -name '.pgpass.save' -o -name '.pgpass~' \
       -o -name '.pgpass.dpkg-old' -o -name '.pgpass.dpkg-new' -o -name '.pgpass.dpkg-dist' \
       -o -name '.pgpass.rpmsave' -o -name '.pgpass.rpmnew' -o -name '.pgpass.rpmorig' \
       -o -name '.netrc' \
       -o -name '.netrc.bak' -o -name '.netrc.old' -o -name '.netrc.orig' -o -name '.netrc.backup' \
       -o -name '.netrc.sav' -o -name '.netrc.save' -o -name '.netrc~' \
       -o -name '.netrc.dpkg-old' -o -name '.netrc.dpkg-new' -o -name '.netrc.dpkg-dist' \
       -o -name '.netrc.rpmsave' -o -name '.netrc.rpmnew' -o -name '.netrc.rpmorig' \
       -o -name '.ldaprc' \
       -o -name '.ldaprc.bak' -o -name '.ldaprc.old' -o -name '.ldaprc.orig' -o -name '.ldaprc.backup' \
       -o -name '.ldaprc.sav' -o -name '.ldaprc.save' -o -name '.ldaprc~' \
       -o -name '.ldaprc.dpkg-old' -o -name '.ldaprc.dpkg-new' -o -name '.ldaprc.dpkg-dist' \
       -o -name '.ldaprc.rpmsave' -o -name '.ldaprc.rpmnew' -o -name '.ldaprc.rpmorig' \
    \) 2>/dev/null)

# --- Tree-class 2: User homes ---
# /root, /home/* (derived from /etc/passwd interactive users) — named-file allow-list, maxdepth 3
# Interactive users: UID 0 or >= 1000, real shell (excludes nologin/false/sync/halt/shutdown)
# D2: each canonical pattern (named + path-scoped) is followed by its 7 backup
# variants (.bak/.old/.orig/.backup/.sav/.save/~). No pkg-mgr suffixes — those are
# T-1-specific (pkg managers don't write to user homes). Hand-enumerated.
HOMES=$(awk -F: '($3 == 0 || $3 >= 1000) && $7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $6}' /etc/passwd | sort -u)
while IFS= read -r h; do
    [ -d "$h" ] || continue
    while IFS= read -r f; do
        FILES+=("$f")
    done < <(find "$h" -maxdepth 3 "${READABLE[@]}" -type f -size -1048576c \
        \( -name '.my.cnf' \
           -o -name '.my.cnf.bak' -o -name '.my.cnf.old' -o -name '.my.cnf.orig' -o -name '.my.cnf.backup' \
           -o -name '.my.cnf.sav' -o -name '.my.cnf.save' -o -name '.my.cnf~' \
           -o -name '.pgpass' \
           -o -name '.pgpass.bak' -o -name '.pgpass.old' -o -name '.pgpass.orig' -o -name '.pgpass.backup' \
           -o -name '.pgpass.sav' -o -name '.pgpass.save' -o -name '.pgpass~' \
           -o -name '.netrc' \
           -o -name '.netrc.bak' -o -name '.netrc.old' -o -name '.netrc.orig' -o -name '.netrc.backup' \
           -o -name '.netrc.sav' -o -name '.netrc.save' -o -name '.netrc~' \
           -o -name '.ldaprc' \
           -o -name '.ldaprc.bak' -o -name '.ldaprc.old' -o -name '.ldaprc.orig' -o -name '.ldaprc.backup' \
           -o -name '.ldaprc.sav' -o -name '.ldaprc.save' -o -name '.ldaprc~' \
           -o -name '.git-credentials' \
           -o -name '.git-credentials.bak' -o -name '.git-credentials.old' -o -name '.git-credentials.orig' -o -name '.git-credentials.backup' \
           -o -name '.git-credentials.sav' -o -name '.git-credentials.save' -o -name '.git-credentials~' \
           -o -name '.npmrc' \
           -o -name '.npmrc.bak' -o -name '.npmrc.old' -o -name '.npmrc.orig' -o -name '.npmrc.backup' \
           -o -name '.npmrc.sav' -o -name '.npmrc.save' -o -name '.npmrc~' \
           -o -name '.env' \
           -o -name '.env.bak' -o -name '.env.old' -o -name '.env.orig' -o -name '.env.backup' \
           -o -name '.env.sav' -o -name '.env.save' -o -name '.env~' \
           -o -name '.htpasswd' \
           -o -name '.htpasswd.bak' -o -name '.htpasswd.old' -o -name '.htpasswd.orig' -o -name '.htpasswd.backup' \
           -o -name '.htpasswd.sav' -o -name '.htpasswd.save' -o -name '.htpasswd~' \
           -o -name '*.ovpn' \
           -o -name '*.ovpn.bak' -o -name '*.ovpn.old' -o -name '*.ovpn.orig' -o -name '*.ovpn.backup' \
           -o -name '*.ovpn.sav' -o -name '*.ovpn.save' -o -name '*.ovpn~' \
           -o -path '*/.aws/credentials' \
           -o -path '*/.aws/credentials.bak' -o -path '*/.aws/credentials.old' -o -path '*/.aws/credentials.orig' -o -path '*/.aws/credentials.backup' \
           -o -path '*/.aws/credentials.sav' -o -path '*/.aws/credentials.save' -o -path '*/.aws/credentials~' \
           -o -path '*/.aws/config' \
           -o -path '*/.aws/config.bak' -o -path '*/.aws/config.old' -o -path '*/.aws/config.orig' -o -path '*/.aws/config.backup' \
           -o -path '*/.aws/config.sav' -o -path '*/.aws/config.save' -o -path '*/.aws/config~' \
           -o -path '*/.docker/config.json' \
           -o -path '*/.docker/config.json.bak' -o -path '*/.docker/config.json.old' -o -path '*/.docker/config.json.orig' -o -path '*/.docker/config.json.backup' \
           -o -path '*/.docker/config.json.sav' -o -path '*/.docker/config.json.save' -o -path '*/.docker/config.json~' \
           -o -path '*/.kube/config' \
           -o -path '*/.kube/config.bak' -o -path '*/.kube/config.old' -o -path '*/.kube/config.orig' -o -path '*/.kube/config.backup' \
           -o -path '*/.kube/config.sav' -o -path '*/.kube/config.save' -o -path '*/.kube/config~' \
        \) 2>/dev/null)
done <<< "$HOMES"

# --- Tree-class 3a: App roots (web) — /var/www/, /srv/ ---
# Both named-file allow-list + extension glob; includes .sh for bespoke deployment scripts.
# Unbounded depth — apps nest (e.g. /var/www/html/<site>/wp-content/plugins/<plugin>/...).
# D2: each canonical pattern is followed by its 7 backup variants
# (.bak/.old/.orig/.backup/.sav/.save/~). No pkg-mgr suffixes — T-1-specific.
for tree in /var/www /srv; do
    [ -d "$tree" ] || continue
    while IFS= read -r f; do
        FILES+=("$f")
    done < <(find "$tree" "${READABLE[@]}" -type f -size -1048576c \
        \( -name 'wp-config.php' \
           -o -name 'wp-config.php.bak' -o -name 'wp-config.php.old' -o -name 'wp-config.php.orig' -o -name 'wp-config.php.backup' \
           -o -name 'wp-config.php.sav' -o -name 'wp-config.php.save' -o -name 'wp-config.php~' \
           -o -name 'configuration.php' \
           -o -name 'configuration.php.bak' -o -name 'configuration.php.old' -o -name 'configuration.php.orig' -o -name 'configuration.php.backup' \
           -o -name 'configuration.php.sav' -o -name 'configuration.php.save' -o -name 'configuration.php~' \
           -o -name 'settings.py' \
           -o -name 'settings.py.bak' -o -name 'settings.py.old' -o -name 'settings.py.orig' -o -name 'settings.py.backup' \
           -o -name 'settings.py.sav' -o -name 'settings.py.save' -o -name 'settings.py~' \
           -o -name 'database.yml' \
           -o -name 'database.yml.bak' -o -name 'database.yml.old' -o -name 'database.yml.orig' -o -name 'database.yml.backup' \
           -o -name 'database.yml.sav' -o -name 'database.yml.save' -o -name 'database.yml~' \
           -o -name 'secrets.yml' \
           -o -name 'secrets.yml.bak' -o -name 'secrets.yml.old' -o -name 'secrets.yml.orig' -o -name 'secrets.yml.backup' \
           -o -name 'secrets.yml.sav' -o -name 'secrets.yml.save' -o -name 'secrets.yml~' \
           -o -name 'application.yml' \
           -o -name 'application.yml.bak' -o -name 'application.yml.old' -o -name 'application.yml.orig' -o -name 'application.yml.backup' \
           -o -name 'application.yml.sav' -o -name 'application.yml.save' -o -name 'application.yml~' \
           -o -name 'application.properties' \
           -o -name 'application.properties.bak' -o -name 'application.properties.old' -o -name 'application.properties.orig' -o -name 'application.properties.backup' \
           -o -name 'application.properties.sav' -o -name 'application.properties.save' -o -name 'application.properties~' \
           -o -name 'config.inc.php' \
           -o -name 'config.inc.php.bak' -o -name 'config.inc.php.old' -o -name 'config.inc.php.orig' -o -name 'config.inc.php.backup' \
           -o -name 'config.inc.php.sav' -o -name 'config.inc.php.save' -o -name 'config.inc.php~' \
           -o -name 'LocalSettings.php' \
           -o -name 'LocalSettings.php.bak' -o -name 'LocalSettings.php.old' -o -name 'LocalSettings.php.orig' -o -name 'LocalSettings.php.backup' \
           -o -name 'LocalSettings.php.sav' -o -name 'LocalSettings.php.save' -o -name 'LocalSettings.php~' \
           -o -name 'web.config' \
           -o -name 'web.config.bak' -o -name 'web.config.old' -o -name 'web.config.orig' -o -name 'web.config.backup' \
           -o -name 'web.config.sav' -o -name 'web.config.save' -o -name 'web.config~' \
           -o -name '.htpasswd' \
           -o -name '.htpasswd.bak' -o -name '.htpasswd.old' -o -name '.htpasswd.orig' -o -name '.htpasswd.backup' \
           -o -name '.htpasswd.sav' -o -name '.htpasswd.save' -o -name '.htpasswd~' \
           -o -name '.pgpass' \
           -o -name '.pgpass.bak' -o -name '.pgpass.old' -o -name '.pgpass.orig' -o -name '.pgpass.backup' \
           -o -name '.pgpass.sav' -o -name '.pgpass.save' -o -name '.pgpass~' \
           -o -name '.netrc' \
           -o -name '.netrc.bak' -o -name '.netrc.old' -o -name '.netrc.orig' -o -name '.netrc.backup' \
           -o -name '.netrc.sav' -o -name '.netrc.save' -o -name '.netrc~' \
           -o -name '.ldaprc' \
           -o -name '.ldaprc.bak' -o -name '.ldaprc.old' -o -name '.ldaprc.orig' -o -name '.ldaprc.backup' \
           -o -name '.ldaprc.sav' -o -name '.ldaprc.save' -o -name '.ldaprc~' \
           -o -name '*.env' \
           -o -name '*.env.bak' -o -name '*.env.old' -o -name '*.env.orig' -o -name '*.env.backup' \
           -o -name '*.env.sav' -o -name '*.env.save' -o -name '*.env~' \
           -o -name '*.yml' \
           -o -name '*.yml.bak' -o -name '*.yml.old' -o -name '*.yml.orig' -o -name '*.yml.backup' \
           -o -name '*.yml.sav' -o -name '*.yml.save' -o -name '*.yml~' \
           -o -name '*.yaml' \
           -o -name '*.yaml.bak' -o -name '*.yaml.old' -o -name '*.yaml.orig' -o -name '*.yaml.backup' \
           -o -name '*.yaml.sav' -o -name '*.yaml.save' -o -name '*.yaml~' \
           -o -name '*.json' \
           -o -name '*.json.bak' -o -name '*.json.old' -o -name '*.json.orig' -o -name '*.json.backup' \
           -o -name '*.json.sav' -o -name '*.json.save' -o -name '*.json~' \
           -o -name '*.properties' \
           -o -name '*.properties.bak' -o -name '*.properties.old' -o -name '*.properties.orig' -o -name '*.properties.backup' \
           -o -name '*.properties.sav' -o -name '*.properties.save' -o -name '*.properties~' \
           -o -name '*.sh' \
           -o -name '*.sh.bak' -o -name '*.sh.old' -o -name '*.sh.orig' -o -name '*.sh.backup' \
           -o -name '*.sh.sav' -o -name '*.sh.save' -o -name '*.sh~' \
           -o -name '*.ovpn' \
           -o -name '*.ovpn.bak' -o -name '*.ovpn.old' -o -name '*.ovpn.orig' -o -name '*.ovpn.backup' \
           -o -name '*.ovpn.sav' -o -name '*.ovpn.save' -o -name '*.ovpn~' \
        \) 2>/dev/null)
done

# --- Tree-class 3b: App roots (third-party) — /opt/ ---
# Same patterns as 3a MINUS .sh — packaged-app launcher dirs (elasticsearch/jira/gitlab)
# can explode .sh count without commensurate cred yield.
# D2: each canonical pattern is followed by its 7 backup variants
# (.bak/.old/.orig/.backup/.sav/.save/~). No pkg-mgr suffixes — T-1-specific.
[ -d /opt ] && while IFS= read -r f; do
    FILES+=("$f")
done < <(find /opt "${READABLE[@]}" -type f -size -1048576c \
    \( -name 'wp-config.php' \
       -o -name 'wp-config.php.bak' -o -name 'wp-config.php.old' -o -name 'wp-config.php.orig' -o -name 'wp-config.php.backup' \
       -o -name 'wp-config.php.sav' -o -name 'wp-config.php.save' -o -name 'wp-config.php~' \
       -o -name 'configuration.php' \
       -o -name 'configuration.php.bak' -o -name 'configuration.php.old' -o -name 'configuration.php.orig' -o -name 'configuration.php.backup' \
       -o -name 'configuration.php.sav' -o -name 'configuration.php.save' -o -name 'configuration.php~' \
       -o -name 'settings.py' \
       -o -name 'settings.py.bak' -o -name 'settings.py.old' -o -name 'settings.py.orig' -o -name 'settings.py.backup' \
       -o -name 'settings.py.sav' -o -name 'settings.py.save' -o -name 'settings.py~' \
       -o -name 'database.yml' \
       -o -name 'database.yml.bak' -o -name 'database.yml.old' -o -name 'database.yml.orig' -o -name 'database.yml.backup' \
       -o -name 'database.yml.sav' -o -name 'database.yml.save' -o -name 'database.yml~' \
       -o -name 'secrets.yml' \
       -o -name 'secrets.yml.bak' -o -name 'secrets.yml.old' -o -name 'secrets.yml.orig' -o -name 'secrets.yml.backup' \
       -o -name 'secrets.yml.sav' -o -name 'secrets.yml.save' -o -name 'secrets.yml~' \
       -o -name 'application.yml' \
       -o -name 'application.yml.bak' -o -name 'application.yml.old' -o -name 'application.yml.orig' -o -name 'application.yml.backup' \
       -o -name 'application.yml.sav' -o -name 'application.yml.save' -o -name 'application.yml~' \
       -o -name 'application.properties' \
       -o -name 'application.properties.bak' -o -name 'application.properties.old' -o -name 'application.properties.orig' -o -name 'application.properties.backup' \
       -o -name 'application.properties.sav' -o -name 'application.properties.save' -o -name 'application.properties~' \
       -o -name 'config.inc.php' \
       -o -name 'config.inc.php.bak' -o -name 'config.inc.php.old' -o -name 'config.inc.php.orig' -o -name 'config.inc.php.backup' \
       -o -name 'config.inc.php.sav' -o -name 'config.inc.php.save' -o -name 'config.inc.php~' \
       -o -name 'LocalSettings.php' \
       -o -name 'LocalSettings.php.bak' -o -name 'LocalSettings.php.old' -o -name 'LocalSettings.php.orig' -o -name 'LocalSettings.php.backup' \
       -o -name 'LocalSettings.php.sav' -o -name 'LocalSettings.php.save' -o -name 'LocalSettings.php~' \
       -o -name 'web.config' \
       -o -name 'web.config.bak' -o -name 'web.config.old' -o -name 'web.config.orig' -o -name 'web.config.backup' \
       -o -name 'web.config.sav' -o -name 'web.config.save' -o -name 'web.config~' \
       -o -name '.htpasswd' \
       -o -name '.htpasswd.bak' -o -name '.htpasswd.old' -o -name '.htpasswd.orig' -o -name '.htpasswd.backup' \
       -o -name '.htpasswd.sav' -o -name '.htpasswd.save' -o -name '.htpasswd~' \
       -o -name '.pgpass' \
       -o -name '.pgpass.bak' -o -name '.pgpass.old' -o -name '.pgpass.orig' -o -name '.pgpass.backup' \
       -o -name '.pgpass.sav' -o -name '.pgpass.save' -o -name '.pgpass~' \
       -o -name '.netrc' \
       -o -name '.netrc.bak' -o -name '.netrc.old' -o -name '.netrc.orig' -o -name '.netrc.backup' \
       -o -name '.netrc.sav' -o -name '.netrc.save' -o -name '.netrc~' \
       -o -name '.ldaprc' \
       -o -name '.ldaprc.bak' -o -name '.ldaprc.old' -o -name '.ldaprc.orig' -o -name '.ldaprc.backup' \
       -o -name '.ldaprc.sav' -o -name '.ldaprc.save' -o -name '.ldaprc~' \
       -o -name '*.env' \
       -o -name '*.env.bak' -o -name '*.env.old' -o -name '*.env.orig' -o -name '*.env.backup' \
       -o -name '*.env.sav' -o -name '*.env.save' -o -name '*.env~' \
       -o -name '*.yml' \
       -o -name '*.yml.bak' -o -name '*.yml.old' -o -name '*.yml.orig' -o -name '*.yml.backup' \
       -o -name '*.yml.sav' -o -name '*.yml.save' -o -name '*.yml~' \
       -o -name '*.yaml' \
       -o -name '*.yaml.bak' -o -name '*.yaml.old' -o -name '*.yaml.orig' -o -name '*.yaml.backup' \
       -o -name '*.yaml.sav' -o -name '*.yaml.save' -o -name '*.yaml~' \
       -o -name '*.json' \
       -o -name '*.json.bak' -o -name '*.json.old' -o -name '*.json.orig' -o -name '*.json.backup' \
       -o -name '*.json.sav' -o -name '*.json.save' -o -name '*.json~' \
       -o -name '*.properties' \
       -o -name '*.properties.bak' -o -name '*.properties.old' -o -name '*.properties.orig' -o -name '*.properties.backup' \
       -o -name '*.properties.sav' -o -name '*.properties.save' -o -name '*.properties~' \
       -o -name '*.ovpn' \
       -o -name '*.ovpn.bak' -o -name '*.ovpn.old' -o -name '*.ovpn.orig' -o -name '*.ovpn.backup' \
       -o -name '*.ovpn.sav' -o -name '*.ovpn.save' -o -name '*.ovpn~' \
    \) 2>/dev/null)

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
    # Suffix-strip pre-dispatch (D2): backup-variant files (e.g. apache.conf.bak,
    # .netrc.old, fstab.dpkg-old) dispatch to their canonical-name handler.
    # Without this, the backup variants added to each tree-class find block fall
    # through to default master PATTERN, losing NETRC/whole-file/OVPN/FSTAB/
    # SH_VAR+SH_CLI dispatches. ssh_enum.sh uses the same mechanism.
    # Documented limitation: one-strip only — double-suffix files
    # (e.g. apache.conf.bak.old) fall to default after the first removal.
    case "$bname" in
        *.bak|*.old|*.orig|*.backup|*.sav|*.save|*.dpkg-old|*.dpkg-new|*.dpkg-dist|*.rpmsave|*.rpmnew|*.rpmorig)
            bn_dispatch="${bname%.*}"
            ;;
        *~)
            bn_dispatch="${bname%\~}"
            ;;
        *)
            bn_dispatch="$bname"
            ;;
    esac
    case "$bn_dispatch" in
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
