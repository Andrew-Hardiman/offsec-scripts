#!/bin/bash
# cron_enum.sh — Linux cron enumeration for PrivEsc routing
#
# Outputs explicit markers consumed by Linux Privilege Escalation Checksheet Step 3:
#   WRITABLE_SCRIPT[root]: <path>     → route: Cron File Permissions
#   RELATIVE_CMD[root]: <cmd>         → (combined with WRITABLE_PATH_DIR → Cron PATH)
#   WRITABLE_PATH_DIR: <dir>          → (combined with RELATIVE_CMD → Cron PATH)
#   WILDCARD[root]: <file:line:body>  → route: Cron Wildcards (verify dir writable)
#
# Sources enumerated:
#   /etc/crontab
#   /etc/cron.d/*
#   /etc/cron.{daily,hourly,weekly,monthly}/*  (always run as root by crond)
#   Bodies of all scripts cron invokes as root (resolved from above)
#
# Only cron entries running as root are considered (user field == "root" or "0";
# user field is 6 for numeric schedules, 2 for @-string schedules like @hourly/@reboot).
# A cron job running as www-data escalates to www-data, not root — not PrivEsc.
#
# Not yet covered (add when encountered): user crontabs, /etc/anacrontab, systemd timers.

# --- Extract cron's PATH (fallback to standard if not set in any cron config) ---
# !!! LIMITATION: uses the FIRST PATH= found across cron files. cron applies PATH
# !!! per-file — each crontab/cron.d file may set its own. If a cron.d file sets a
# !!! divergent PATH, relative-cmd resolution AND WRITABLE_PATH_DIR can be wrong for
# !!! that file's entries. Proper fix = per-file PATH tracking. Revisit if a target
# !!! is seen setting a divergent PATH in cron.d.
cron_path=$(grep -h '^PATH=' /etc/crontab /etc/cron.d/* 2>/dev/null | head -1 | cut -d= -f2)
[ -z "$cron_path" ] && cron_path="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"

# --- Existing cron entry files (guards mawk abort when /etc/crontab is absent, cron.d-only) ---
cron_files=""
for _f in /etc/crontab /etc/cron.d/*; do [ -f "$_f" ] && cron_files="$cron_files $_f"; done

# --- Collect all root-run cron-invoked script paths (shared between WRITABLE_SCRIPT and WILDCARD) ---
cron_scripts=$(
  {
    # Absolute-path tokens from root-run entries in /etc/crontab and /etc/cron.d/*
    [ -n "$cron_files" ] && awk '/^[^#]/ { if ($1~/^@/) { if (NF<3) next; u=$2; s=3 } else { if (NF<7) next; u=$6; s=7 } if (u!="root" && u!="0") next; for(i=s;i<=NF;i++) if ($i~/^\//) print $i }' $cron_files 2>/dev/null

    # Relative-path commands from root-run entries, resolved via cron's PATH
    [ -n "$cron_files" ] && awk '/^[^#]/ { if ($1~/^@/) { if (NF<3) next; u=$2; c=$3 } else { if (NF<7) next; u=$6; c=$7 } if ((u=="root" || u=="0") && c!~/\// && c!~/^[A-Z_]+=/) print c }' $cron_files 2>/dev/null \
      | sort -u | while read -r c; do
        PATH="$cron_path" command -v "$c" 2>/dev/null
      done

    # Scripts in run-parts directories (always executed as root by crond)
    find /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -maxdepth 1 -type f 2>/dev/null
  } | sort -u
)

# --- WRITABLE_SCRIPT: writable root-run cron-invoked scripts ---
echo "$cron_scripts" | while read -r f; do
  [ -f "$f" ] && [ -w "$f" ] && echo "WRITABLE_SCRIPT[root]: $f"
done

# --- RELATIVE_CMD: PATH-routable relative-path commands in root-run cron entries ---
# Excludes shell builtins/aliases/functions (command -v returns non-absolute string).
[ -n "$cron_files" ] && awk '/^[^#]/ { if ($1~/^@/) { if (NF<3) next; u=$2; c=$3 } else { if (NF<7) next; u=$6; c=$7 } if ((u=="root" || u=="0") && c!~/\// && c!~/^[A-Z_]+=/) print c }' $cron_files 2>/dev/null \
  | sort -u | while read -r c; do
    case "$(PATH="$cron_path" command -v "$c" 2>/dev/null)" in
      /*|"") echo "RELATIVE_CMD[root]: $c" ;;
    esac
  done

# --- WRITABLE_PATH_DIR: writable directories in cron's PATH ---
echo "$cron_path" | tr ':' '\n' | while read -r d; do
  [ -w "$d" ] && echo "WRITABLE_PATH_DIR: $d"
done

# --- WILDCARD: privileged binary + wildcard glob in root-run cron-reachable files ---
# Inline entries in crontab/cron.d: use awk to filter on user field (field 6).
# Script bodies: cron_scripts already contains only root-run scripts.
{
  for _f in /etc/crontab /etc/cron.d/*; do
    [ -f "$_f" ] || continue
    awk -v f="$_f" '/^[^#]/ { if ($1~/^@/) { if (NF<3) next; u=$2 } else { if (NF<7) next; u=$6 } if (u=="root" || u=="0") print f ":" NR ":" $0 }' "$_f"
  done | grep -E '\b(tar|rsync|chown|chmod|gzip)\b.*\*'

  echo "$cron_scripts" | while read -r f; do
    [ -f "$f" ] && grep -nHE '\b(tar|rsync|chown|chmod|gzip)\b.*\*' "$f" 2>/dev/null
  done
} | sed 's/^/WILDCARD[root]: /'
