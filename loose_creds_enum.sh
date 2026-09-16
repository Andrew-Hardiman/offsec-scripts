#!/bin/bash
# loose_creds_enum.sh
# Enumerate files whose FILENAME suggests they contain credentials, across
# scoped tree-classes. Complements config_enum.sh (shape-based, opens files
# with known config extensions and greps for cred-pattern lines) — this
# script catches the case where the FILE'S NAME is the tell but the content
# is bare/unstructured (e.g. /etc/password.txt containing 'root:hunter2').
#
# Consumed by:
#   Linux Privilege Escalation Checksheet Step 4 Credential Harvesting -> [[Loose Creds]]
#
# Privilege-agnostic via conditional -readable filter (same mechanic as
# config_enum.sh — access(2) uses RUID, so in a SUID drop-and-launch context
# (RUID unprivileged, EUID=0) we skip -readable and let grep's open() cover
# the full root-accessible set via EUID).
#
# Workflow handling:
#   Pre-root (EUID=RUID=user):       keep -readable
#   Sudo/su post-root (EUID=RUID=0): keep -readable (RUID=0 passes everything)
#   SUID post-root (EUID=0,RUID!=0): SKIP -readable
#
# Output markers:
#   LOOSE_CRED_FILE: <path>   - file with suspicious name found (may be zero
#                                or many per run; playbook cats and classifies
#                                each). Backup variants (.bak, .old, etc.) are
#                                caught naturally via the wildcard globs.
#   LOOSE_CRED_EMPTY          - no suspicious filenames found in any tree-class
#                                (technique inapplicable; return to LPEC).
#
# Silence when files exist elsewhere but none matched is intentional: shell
# prompt return signals script completion; no CONFIG_FOUND-style per-scanned
# telemetry (see config_enum.sh Fix E rationale).
#
# KNOWN LIMITATIONS (revisit if engagement surfaces a miss):
#   - Filename-based only. Files with generic names (notes.txt, backup)
#     containing embedded creds are OUT OF SCOPE — that's linpeas territory
#     (LPEC Step 18 max-IOC backstop).
#   - Symlinks not followed (-L deferred; consistent with config_enum).
#   - Size cap: -size -1048576c filters files >= 1 MiB. Consistent with
#     config_enum; multi-MB matched files (large DB dumps renamed to *creds*)
#     are unlikely OSCP+/CTF form. Bump if engagement surfaces a miss.
#   - BusyBox/Alpine untested; -iname is POSIX + widely portable so should work,
#     but not verified against BusyBox find.
#   - Overlap with config_enum for files matching BOTH filename glob AND
#     config-file extension (e.g. /etc/mysql/password.cnf): both scripts emit,
#     playbook operator sees duplicate candidate. Acceptable — playbook Step 2
#     resolves shape-based whether or not config_enum already resolved it.
#
# NAME GLOBS (case-insensitive via -iname).
# Base set from primary sources (HackTricks, PayloadsAllTheThings, OSCP prep):
#   *password* *passwd* *credential* *creds* *secret*
#   *.pwd *.password
# Additions (confidence-1 parallels or clear-signal extensions):
#   *token* *login* *hash* *.pem *.key *.priv *_key
# Deliberately EXCLUDED (FP-heavy relative to yield):
#   *key* bare (matches keyboard, keymap, keyring — /etc/apt/keyrings/*, XKB)
#   *auth* (matches PAM configs, Kerberos configs — config_enum territory)
#   *admin* (matches admin_email.txt, admin_url — not cred-shaped)
#   id_rsa / id_ed25519 patterns (ssh_enum's territory)
#
# Maintenance: additive. When an engagement surfaces a missed glob,
# add it here + add a regression test in loose_creds_enum_tests.sh + commit.

# ============================================================
# PATH EXCLUSIONS
# ============================================================
# Well-known paths whose contents overlap with our globs but are:
#   (a) covered by another enum script (ssh_enum for */.ssh/*, */etc/ssh/*)
#   (b) system infrastructure with cred keywords in policy prose
#       (PAM configs, AppArmor policy, SELinux policy)
#   (c) canonical system files that always match a glob but are not
#       "loose creds" (/etc/passwd always fires against *passwd* — noise;
#       backup variants /etc/passwd.bak/.dpkg-old NOT excluded, they may
#       carry legacy cred structure).
# Path-based (not name-based) so custom files in /opt/myapp/pam.d/ still scanned.
# Trailing '*' on paths extends exclusion to backup variants where wanted
# (pam.conf.bak, ssh_config.old, etc.); exact-path form used for /etc/passwd
# so backups fire through.
# Grows additively as engagements surface new infra-FP classes.

# ============================================================
# PRIVILEGE-CONTEXT DETECTION (identical to config_enum.sh)
# ============================================================
if [ "$(id -u)" = "0" ] && [ "$(id -ru)" != "0" ]; then
    READABLE=()
else
    READABLE=(-readable)
fi

FILES=()

# ============================================================
# FILE ENUMERATION (five tree-classes)
# ============================================================
# All find blocks: "${READABLE[@]}" -type f -size -1048576c
# -size -1048576c matches files strictly under 1 MiB (bytes, precise;
# find rounds -1M up to next unit and only matches empty files).
# Symlinks NOT followed (-L deferred).

# --- Tree-class 1: System config trees ---
# /etc, /usr/local/etc — maxdepth 4 (consistent with config_enum).
while IFS= read -r f; do
    FILES+=("$f")
done < <(find /etc /usr/local/etc -maxdepth 4 "${READABLE[@]}" -type f -size -1048576c \
    -not \( -path '*/etc/pam.d/*' -o -path '*/etc/pam.conf*' \
            -o -path '*/etc/ssh/*' -o -path '*/.ssh/*' \
            -o -path '*/etc/apparmor.d/*' \
            -o -path '*/etc/selinux/*' \
	        -o -path '*/etc/passwd' \
            -o -path '*/etc/passwd-' \) \
    \( -iname '*password*' -o -iname '*passwd*' -o -iname '*credential*' -o -iname '*creds*' \
       -o -iname '*secret*' -o -iname '*token*' -o -iname '*login*' -o -iname '*hash*' \
       -o -iname '*.pwd' -o -iname '*.password' -o -iname '*.pem' -o -iname '*.key' \
       -o -iname '*.priv' -o -iname '*_key' \) \
    2>/dev/null)

# --- Tree-class 2: User home directories ---
# Interactive users (UID 0 or >= 1000, real shell), maxdepth 3.
# Same awk filter as config_enum for consistency.
HOMES=$(awk -F: '($3==0||$3>=1000)&&$7!~/(nologin|false)/{print $6}' /etc/passwd 2>/dev/null | sort -u)
while IFS= read -r home; do
    [ -z "$home" ] && continue
    [ -d "$home" ] || continue
    while IFS= read -r f; do
        FILES+=("$f")
    done < <(find "$home" -maxdepth 3 "${READABLE[@]}" -type f -size -1048576c \
        -not \( -path '*/.ssh/*' \) \
        \( -iname '*password*' -o -iname '*passwd*' -o -iname '*credential*' -o -iname '*creds*' \
           -o -iname '*secret*' -o -iname '*token*' -o -iname '*login*' -o -iname '*hash*' \
           -o -iname '*.pwd' -o -iname '*.password' -o -iname '*.pem' -o -iname '*.key' \
           -o -iname '*.priv' -o -iname '*_key' \) \
        2>/dev/null)
done <<< "$HOMES"

# --- Tree-class 3a: App roots (web) — /var/www, /srv ---
# Unbounded depth (apps nest); .ssh exclusion covers admin's home symlinked or app-embedded.
for tree in /var/www /srv; do
    [ -d "$tree" ] || continue
    while IFS= read -r f; do
        FILES+=("$f")
    done < <(find "$tree" "${READABLE[@]}" -type f -size -1048576c \
        -not \( -path '*/.ssh/*' \) \
        \( -iname '*password*' -o -iname '*passwd*' -o -iname '*credential*' -o -iname '*creds*' \
           -o -iname '*secret*' -o -iname '*token*' -o -iname '*login*' -o -iname '*hash*' \
           -o -iname '*.pwd' -o -iname '*.password' -o -iname '*.pem' -o -iname '*.key' \
           -o -iname '*.priv' -o -iname '*_key' \) \
        2>/dev/null)
done

# --- Tree-class 3b: App roots (third-party) — /opt ---
[ -d /opt ] && while IFS= read -r f; do
    FILES+=("$f")
done < <(find /opt "${READABLE[@]}" -type f -size -1048576c \
    -not \( -path '*/.ssh/*' \) \
    \( -iname '*password*' -o -iname '*passwd*' -o -iname '*credential*' -o -iname '*creds*' \
       -o -iname '*secret*' -o -iname '*token*' -o -iname '*login*' -o -iname '*hash*' \
       -o -iname '*.pwd' -o -iname '*.password' -o -iname '*.pem' -o -iname '*.key' \
       -o -iname '*.priv' -o -iname '*_key' \) \
    2>/dev/null)

# --- Tree-class 4: Loose-cred-specific locations ---
# Locations where sysadmins / CTF authors drop cred files that don't fit
# any of the trees above:
#   /tmp           - scratch space (maxdepth 2 — /tmp/<file> and /tmp/<user>/<file>)
#   /var/backups   - dpkg /passwd.bak, /shadow.bak, custom cred backups
#   /var/mail      - mail spools may contain forgotten cred emails
#   /var/spool     - cron mail, print jobs — occasionally cred-bearing
#   /root          - root's home if we have EUID=0 or ACL grant (usually
#                    unreadable pre-root; check anyway — misconfigured perms fire)
for tree in /var/backups /var/mail /var/spool /root; do
    [ -d "$tree" ] || continue
    while IFS= read -r f; do
        FILES+=("$f")
    done < <(find "$tree" "${READABLE[@]}" -type f -size -1048576c \
        -not \( -path '*/.ssh/*' \) \
        \( -iname '*password*' -o -iname '*passwd*' -o -iname '*credential*' -o -iname '*creds*' \
           -o -iname '*secret*' -o -iname '*token*' -o -iname '*login*' -o -iname '*hash*' \
           -o -iname '*.pwd' -o -iname '*.password' -o -iname '*.pem' -o -iname '*.key' \
           -o -iname '*.priv' -o -iname '*_key' \) \
        2>/dev/null)
done

# /tmp gets its own maxdepth 2 (world-writable, avoid deep-tree wanderings)
[ -d /tmp ] && while IFS= read -r f; do
    FILES+=("$f")
done < <(find /tmp -maxdepth 2 "${READABLE[@]}" -type f -size -1048576c \
    -not \( -path '*/.ssh/*' \) \
    \( -iname '*password*' -o -iname '*passwd*' -o -iname '*credential*' -o -iname '*creds*' \
       -o -iname '*secret*' -o -iname '*token*' -o -iname '*login*' -o -iname '*hash*' \
       -o -iname '*.pwd' -o -iname '*.password' -o -iname '*.pem' -o -iname '*.key' \
       -o -iname '*.priv' -o -iname '*_key' \) \
    2>/dev/null)

# Deduplicate across tree-classes (a file matched by multiple trees
# — rare given non-overlapping paths, but /opt symlinked to /var/www etc.
# could trip it).
if [ ${#FILES[@]} -gt 0 ]; then
    mapfile -t FILES < <(printf '%s\n' "${FILES[@]}" | sort -u)
fi

# ============================================================
# OUTPUT
# ============================================================
if [ ${#FILES[@]} -eq 0 ]; then
    echo "LOOSE_CRED_EMPTY"
    exit 0
fi

for f in "${FILES[@]}"; do
    echo "LOOSE_CRED_FILE: $f"
done
