#!/bin/bash
# history_enum.sh
# Enumerate interactive-user history files and scan for credential patterns.
# Outputs explicit markers consumed by:
#   Linux Privilege Escalation Checksheet Step 3 -> History Files (pre-root)
#   Linux Credential Extraction Checksheet -> History Files (post-root, future)
#
# Privilege-agnostic: -readable filter naturally yields different files depending
# on executing process EUID. Same script serves both contexts.
#
# Output markers:
#   HISTORY_CRED[<file>]: <line>   - credential pattern hit (one per matched line)
#   HISTORY_FOUND: <file>          - readable file with no regex match
#                                    (informational only; not an action trigger.
#                                    If a real engagement surfaces a missed pattern,
#                                    update PATTERN below + add regression test in
#                                    history_enum.tests.sh, then commit.)
#   HISTORY_EMPTY                  - no readable history files found

# CREDENTIAL PATTERN regex (grep -aniE; case-insensitive, extended POSIX).
# -p<value> matching is bounded to known DB-client binaries via the leading
# alternation. Bare -p[^- ] would false-positive on every -p<flag> cluster
# in the wider shell ecosystem (gcc -pthread, tar -pcvf, nc -p<port>, etc.).
# [^|;]* allows args between binary and -p but stops at pipe/semicolon
# boundaries so chained commands don't cross-contaminate.
# Allow-list vs deny-list design rationale: see Vault_Strategy.
# Maintenance: if engagement surfaces a missed DB client (cqlsh, influx,
# clickhouse-client, etc.), append to the alternation + add regression test.
PATTERN='((mysql|mysqldump|mariadb|psql|pg_dump|mongo|mongosh|redis-cli)[^|;]*-p[^- ]|--password|--pwd|--pass=|--secret=|--api[-_]?key|--token=|password=|pwd=|MYSQL_PWD=|PGPASSWORD=|sshpass|Bearer |gh[psuor]_|://[^/]*:[^@]*@)'

# Collect interactive user homes from /etc/passwd:
#   $3 == 0          -> root
#   $3 >= 1000       -> regular user (system accounts UID 1-999 excluded)
#   $7 !~ /no-login/ -> real shell (excludes nologin/false/sync/halt/shutdown)
HOMES=$(awk -F: '($3 == 0 || $3 >= 1000) && $7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $6}' /etc/passwd | sort -u)

# Enumerate readable history-format files in each home
FILES=()
while IFS= read -r h; do
    [ -d "$h" ] || continue
    while IFS= read -r f; do
        FILES+=("$f")
    done < <(find "$h" -maxdepth 2 \( -name ".*history" -o -name ".viminfo" -o -name ".lesshst" \) -readable -type f 2>/dev/null)
done <<< "$HOMES"

if [ ${#FILES[@]} -eq 0 ]; then
    echo "HISTORY_EMPTY"
    exit 0
fi

# Scan each readable file for credential patterns; emit per-match or per-file markers
for f in "${FILES[@]}"; do
    matches=$(grep -aniE "$PATTERN" "$f" 2>/dev/null)
    if [ -n "$matches" ]; then
        while IFS= read -r line; do
            echo "HISTORY_CRED[$f]: $line"
        done <<< "$matches"
    else
        echo "HISTORY_FOUND: $f"
    fi
done
