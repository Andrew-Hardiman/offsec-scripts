#!/bin/bash
# ssh_enum.sh
# Enumerate SSH key material across system trees.
# Outputs explicit markers consumed by:
#   Linux Privilege Escalation Checksheet 'Credential Harvesting' -> SSH Keys (pre-root)
#   Linux Credential Extraction Checksheet -> SSH Keys (post-root, future)
#
# Privilege-agnostic via conditional -readable filter (mirrors config_enum.sh).
# Three execution contexts covered:
#   Pre-root (EUID=RUID=user):       -readable filters find to what user can read.
#   Sudo/su post-root (EUID=RUID=0): -readable passes everything.
#   SUID post-root (EUID=0,RUID!=0): SKIP -readable; access(2) checks RUID and
#                                     would underreport. Per-file readability uses
#                                     a real open() (head -c 1) instead of [ -r ].
#
# Output markers:
#   SSH_PRIVKEY: <file> [plain|encrypted] [<fingerprint>]
#                                 - readable private key (targeted pass, standard locations)
#   SSH_PEM_OUTLIER: <file> [plain|encrypted] [<fingerprint>]
#                                 - readable private key found OUTSIDE standard SSH dirs
#   SSH_PRIVKEY_DENIED: <file>    - file with private-key naming, perm denied (post-root revisit)
#   SSH_AUTHKEYS: <file>          - readable authorized_keys; non-blank/non-comment lines indented below
#   SSH_AUTHKEYS_DENIED: <file>   - exists, perm denied
#   SSH_CONFIG: <file>            - readable ~/.ssh/config; non-blank/non-comment lines indented below
#   SSH_CONFIG_DENIED: <file>     - exists, perm denied
#   SSH_KNOWNHOSTS: <file>        - hostnames extracted (col 1, no pubkey body)
#   SSH_KNOWNHOSTS_DENIED: <file> - exists, perm denied
#   SSH_PUBKEY: <file>            - standalone public key (informational)
#   SSH_DIR_DENIED: <dir>         - .ssh directory exists but not listable
#   SSH_FILE_DENIED: <file>       - file in .ssh dir, perm denied, unrecognized name
#   SSH_AGENT_HIJACKABLE: <sock> (owner=<u>) - agent socket writable by this UID
#   SSH_AGENT_PRESENT: <sock> (owner=<u>)    - agent socket exists, not writable
#   SSH_AGENT_ENV: <sock>         - SSH_AUTH_SOCK is set in current env
#   SSH_WIDE_PASS_STARTING        - marker before filesystem-wide PEM scan (requires --wide)
#   SSH_WIDE_PASS_DONE            - marker after filesystem-wide PEM scan (requires --wide)
#
# KNOWN LIMITATIONS:
#   - Symlinks not followed (-L deferred; mirrors config_enum decision).
#   - Wide PEM scan size-capped at 1 MiB per file; keys embedded in larger files
#     (multi-MiB CI logs, large tarballs, container blobs) won't be flagged.
#   - /run pruned: systemd ephemeral credentials at /run/credentials/<unit>/... missed
#     (on-disk source typically found elsewhere in the scan).
#   - /snap pruned: snap-bundled key files at /snap/<pkg>/.../ missed (rare; mutable
#     snap data at /var/snap/... and ~/snap/... is NOT pruned and still scanned).
#   - On BusyBox/Alpine, ssh-keygen may be missing or limited; fingerprint
#     extraction degrades to "no-fp"; OpenSSH-format encryption detection degrades
#     to legacy PEM only (Proc-Type: 4,ENCRYPTED still works).
#   - awk numeric comparison ($uid >= 1000) uses bash arithmetic test; non-numeric
#     UIDs in /etc/passwd (impossible per spec) would error and be silently skipped.

# ============================================================
# PRIVILEGE-CONTEXT DETECTION
# ============================================================
if [ "$(id -u)" = "0" ] && [ "$(id -ru)" != "0" ]; then
    SUID_MODE=1
    READABLE=()
else
    SUID_MODE=0
    READABLE=(-readable)
fi

# ============================================================
# ARGUMENT PARSING
# ============================================================
# --wide   Enable filesystem-wide PEM scan. Off by default — the scan creates
#          a long-running find / process visible in ps, opens many files which
#          triggers auditd and EDR behavioural rules, and updates atime on
#          every file it reads. Make a conscious OPSEC call before enabling on
#          monitored targets.
WIDE_PASS=0
for _arg in "$@"; do
    case "$_arg" in
        --wide) WIDE_PASS=1 ;;
    esac
done

# ============================================================
# HELPERS
# ============================================================

# is_readable_file <path> — robust to SUID mode (access(2) vs real open)
is_readable_file() {
    if [ "$SUID_MODE" = "1" ]; then
        head -c 1 "$1" >/dev/null 2>&1
    else
        [ -r "$1" ]
    fi
}

# is_listable_dir <path> — needs both r+x on dir to enumerate
is_listable_dir() {
    if [ "$SUID_MODE" = "1" ]; then
        ls -1 "$1" >/dev/null 2>&1
    else
        [ -r "$1" ] && [ -x "$1" ]
    fi
}

# detect_enc <privkey_path> — emit "plain" or "encrypted"
detect_enc() {
    local f="$1"
    # Legacy PEM: explicit Proc-Type header
    if head -n 5 "$f" 2>/dev/null | grep -q "Proc-Type: 4,ENCRYPTED"; then
        echo "encrypted"
        return
    fi
    # PKCS#8 encrypted: header line itself contains ENCRYPTED (no Proc-Type used in this format)
    if head -n 1 "$f" 2>/dev/null | grep -q "BEGIN ENCRYPTED PRIVATE KEY"; then
        echo "encrypted"
        return
    fi
    # OpenSSH format: try to derive pubkey with empty passphrase; failure => encrypted
    if head -n 1 "$f" 2>/dev/null | grep -q "OPENSSH PRIVATE KEY"; then
        if ! ssh-keygen -y -P "" -f "$f" </dev/null >/dev/null 2>&1; then
            echo "encrypted"
            return
        fi
    fi
    echo "plain"
}

# fingerprint <privkey_path> — emit SHA256 fingerprint or "no-fp"
fingerprint() {
    local fp
    fp=$(ssh-keygen -lf "$1" </dev/null 2>/dev/null | awk '$2 ~ /^(SHA[0-9]+:|MD5:)/ {print $2}')
    [ -z "$fp" ] && fp="no-fp"
    echo "$fp"
}

# emit_privkey <path> [marker_name]
emit_privkey() {
    local f="$1"
    local marker="${2:-SSH_PRIVKEY}"
    echo "${marker}: $f [$(detect_enc "$f")] [$(fingerprint "$f")]"
}

# is_in_targeted_dirs <path> — true if path falls under a directory the
# targeted pass already scanned. SSH_DIRS is populated before the wide pass
# runs; the function is only ever called from inside the wide-pass loop.
# Replaces the over-broad */.ssh/* case pattern which incorrectly matched
# /.ssh/ paths (non-standard .ssh dir at filesystem root), causing those files
# to be silently skipped even though the targeted pass never saw them.
is_in_targeted_dirs() {
    local f="$1" d
    for d in "${SSH_DIRS[@]}"; do
        case "$f" in
            "$d"/*) return 0 ;;
        esac
    done
    return 1
}

# ============================================================
# BUILD SSH DIRECTORY LIST
# ============================================================
SSH_DIRS=(/root/.ssh /etc/ssh)
while IFS=: read -r user _ uid _ _ home shell; do
    # Interactive users only: UID 0 or >= 1000, real shell
    if [ "$uid" = "0" ] || { [ "$uid" -ge 1000 ] 2>/dev/null; }; then
        case "$shell" in
            *nologin|*false|*sync|*halt|*shutdown) ;;
            *)
                [ -d "$home/.ssh" ] && SSH_DIRS+=("$home/.ssh")
                ;;
        esac
    fi
done < /etc/passwd

# Dedupe (e.g. /root/.ssh listed both in defaults and from passwd iteration)
mapfile -t SSH_DIRS < <(printf '%s\n' "${SSH_DIRS[@]}" | sort -u)

# ============================================================
# TARGETED PASS — standard SSH directories
# ============================================================
shopt -s nullglob
for dir in "${SSH_DIRS[@]}"; do
    [ -d "$dir" ] || continue
    if ! is_listable_dir "$dir"; then
        echo "SSH_DIR_DENIED: $dir"
        continue
    fi
    for f in "$dir"/*; do
        [ -f "$f" ] || continue
        bn=$(basename "$f")

        if ! is_readable_file "$f"; then
            case "$bn" in
                id_*|*.pem|*.key|*_key)
                    echo "SSH_PRIVKEY_DENIED: $f"
                    ;;
                authorized_keys|authorized_keys2)
                    echo "SSH_AUTHKEYS_DENIED: $f"
                    ;;
                config)
                    echo "SSH_CONFIG_DENIED: $f"
                    ;;
                known_hosts|known_hosts2|known_hosts.old)
                    echo "SSH_KNOWNHOSTS_DENIED: $f"
                    ;;
                *)
                    echo "SSH_FILE_DENIED: $f"
                    ;;
            esac
            continue
        fi

        first=$(head -n 1 "$f" 2>/dev/null)

        if echo "$first" | grep -qE "^-----BEGIN [A-Z ]*PRIVATE KEY-----"; then
            emit_privkey "$f"
        elif [ "$bn" = "authorized_keys" ] || [ "$bn" = "authorized_keys2" ]; then
            echo "SSH_AUTHKEYS: $f"
            while IFS= read -r line; do
                case "$line" in ''|\#*) continue ;; esac
                echo "  $line"
            done < "$f"
        elif [ "$bn" = "config" ]; then
            echo "SSH_CONFIG: $f"
            while IFS= read -r line; do
                case "$line" in ''|\#*) continue ;; esac
                echo "  $line"
            done < "$f"
        elif [ "$bn" = "known_hosts" ] || [ "$bn" = "known_hosts2" ] || [ "$bn" = "known_hosts.old" ]; then
            echo "SSH_KNOWNHOSTS: $f"
            awk '!/^[#|]/ && NF>0 { if ($1 ~ /^@/) { split($2, a, ","); print "  " $1 " " a[1] } else { split($1, a, ","); print "  " a[1] } }' "$f" | sort -u
        elif echo "$first" | grep -qE "^(ssh-(rsa|ed25519|ecdsa|dss)|ecdsa-sha2-)"; then
            echo "SSH_PUBKEY: $f"
        fi
        # else: unrecognized file in .ssh/ — silently ignore
    done
done
shopt -u nullglob

# ============================================================
# AGENT SOCKETS (fast)
# ============================================================
while IFS= read -r sock; do
    [ -n "$sock" ] || continue
    owner=$(stat -c %U "$sock" 2>/dev/null)
    [ -z "$owner" ] && owner="unknown"
    if [ -w "$sock" ]; then
        echo "SSH_AGENT_HIJACKABLE: $sock (owner=$owner)"
    else
        echo "SSH_AGENT_PRESENT: $sock (owner=$owner)"
    fi
done < <(find /tmp -maxdepth 2 -type s -name 'agent.*' 2>/dev/null)

if [ -n "$SSH_AUTH_SOCK" ]; then
    echo "SSH_AGENT_ENV: $SSH_AUTH_SOCK"
fi

# ============================================================
# WIDE PASS — filesystem PEM private-key scan (gated behind --wide)
# ============================================================
# Off by default for OPSEC: a long-running find / process is visible in ps,
# and opening many files triggers auditd and EDR behavioural rules. Enable
# only on unmonitored targets, or when the targeted pass yields nothing and
# you have accepted the noise cost.
# Prune kernel pseudo-fs (/proc, /sys, /dev) — no real files.
# Prune /run (tmpfs) and /snap (squashfs) — edge cases in KNOWN LIMITATIONS.
# Prune /usr/share/doc — package documentation; demo/example keys have no
# operational authority and are pure noise.
# Dev artifacts (.git, node_modules) kept — real yield possible on dev boxes.
# Size cap 1 MiB — typical PEM <5 KiB but credentials leak into larger files.
if [ "$WIDE_PASS" = "1" ]; then
    echo "SSH_WIDE_PASS_STARTING"
    find / -type d \( -name proc -o -name sys -o -name run -o -name dev \
                      -o -name snap -o -path '*/usr/share/doc' \) -prune \
           -o -type f -size -1048576c "${READABLE[@]}" \
           -print0 2>/dev/null \
      | xargs -0 -r grep -lE "^-----BEGIN [A-Z ]*PRIVATE KEY-----" 2>/dev/null \
      | while IFS= read -r f; do
            is_in_targeted_dirs "$f" && continue
            emit_privkey "$f" SSH_PEM_OUTLIER
        done
    echo "SSH_WIDE_PASS_DONE"
fi
