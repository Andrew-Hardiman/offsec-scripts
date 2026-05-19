#!/bin/bash
# cron_enum.sh — Linux cron enumeration for PrivEsc routing
#
# Outputs explicit markers consumed by Linux Privilege Escalation Checksheet Step 3:
#   WRITABLE_SCRIPT: <path>     → route: Cron File Permissions
#   RELATIVE_CMD: <cmd>         → (combined with WRITABLE_PATH_DIR → Cron PATH)
#   WRITABLE_PATH_DIR: <dir>    → (combined with RELATIVE_CMD → Cron PATH)
#   WILDCARD: <file:line:body>  → route: Cron Wildcards (verify dir writable)
#
# Sources enumerated:
#   /etc/crontab
#   /etc/cron.d/*
#   /etc/cron.{daily,hourly,weekly,monthly}/*
#   Bodies of all scripts cron invokes (resolved from above)
#
# Not yet covered (add when encountered): user crontabs, /etc/anacrontab, systemd timers.

# --- Extract cron's PATH (fallback to standard if not set in any cron config) ---
cron_path=$(grep -h '^PATH=' /etc/crontab /etc/cron.d/* 2>/dev/null | head -1 | cut -d= -f2)
[ -z "$cron_path" ] && cron_path="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"

# --- Collect all cron-invoked script paths (shared between WRITABLE_SCRIPT and WILDCARD) ---
cron_scripts=$(
  {
    # Absolute-path tokens in /etc/crontab and /etc/cron.d/* command fields
    awk '/^[^#]/ && NF>=7 {for(i=7;i<=NF;i++)if($i~/^\//)print $i}' /etc/crontab /etc/cron.d/* 2>/dev/null

    # Relative-path commands resolved via cron's PATH
    awk '/^[^#]/ && NF>=7 && $7!~/^\// && $7!~/^[A-Z_]+=/ {print $7}' /etc/crontab /etc/cron.d/* 2>/dev/null \
      | sort -u | while read -r c; do
        PATH="$cron_path" command -v "$c" 2>/dev/null
      done

    # Scripts in run-parts directories
    find /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -maxdepth 1 -type f 2>/dev/null
  } | sort -u
)

# --- WRITABLE_SCRIPT: writable cron-invoked scripts ---
echo "$cron_scripts" | while read -r f; do
  [ -f "$f" ] && [ -w "$f" ] && echo "WRITABLE_SCRIPT: $f"
done

# --- RELATIVE_CMD: PATH-routable relative-path commands in cron entries ---
# Excludes shell builtins/aliases/functions (command -v returns non-absolute string).
awk '/^[^#]/ && NF>=7 && $7!~/^\// && $7!~/^[A-Z_]+=/ {print $7}' /etc/crontab /etc/cron.d/* 2>/dev/null \
  | sort -u | while read -r c; do
    case "$(PATH="$cron_path" command -v "$c" 2>/dev/null)" in
      /*|"") echo "RELATIVE_CMD: $c" ;;
    esac
  done

# --- WRITABLE_PATH_DIR: writable directories in cron's PATH ---
echo "$cron_path" | tr ':' '\n' | while read -r d; do
  [ -w "$d" ] && echo "WRITABLE_PATH_DIR: $d"
done

# --- WILDCARD: privileged binary + wildcard glob in cron-reachable files ---
# Scans cron entry files (inline commands) AND bodies of all cron-invoked scripts.
{
  grep -nHE '\b(tar|rsync|chown|chmod|gzip)\b.*\*' \
    /etc/crontab /etc/cron.d/* 2>/dev/null

  echo "$cron_scripts" | while read -r f; do
    [ -f "$f" ] && grep -nHE '\b(tar|rsync|chown|chmod|gzip)\b.*\*' "$f" 2>/dev/null
  done
} | sed 's/^/WILDCARD: /'
