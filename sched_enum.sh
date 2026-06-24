#!/bin/bash
# sched_enum.sh — Linux scheduled-execution enumeration for PrivEsc routing
#
# Emits scheduler-tagged markers consumed by Linux Privilege Escalation Checksheet 'Scheduled execution'.
#
# Cron-family (cron daemon + root user crontab) → Cron walkthroughs:
#   WRITABLE_SCRIPT[root,cron]: <path>          → Cron File Permissions
#   RELATIVE_CMD[root,cron]: <cmd>              → (+ WRITABLE_PATH_DIR[cron]: → Cron PATH)
#   WRITABLE_PATH_DIR[cron]: <dir>              → (+ RELATIVE_CMD[root,cron]: → Cron PATH)
#   WILDCARD[root,cron]: <dir>:<file>:<line>:<body>  → Cron Wildcards
#
# Anacron (/etc/anacrontab) → Anacron walkthroughs (stubs):
#   WRITABLE_SCRIPT[root,anacron]: <path>       → Anacron File Permissions
#   RELATIVE_CMD[root,anacron]: <cmd>           → (+ WRITABLE_PATH_DIR[anacron]: → Anacron PATH)
#   WRITABLE_PATH_DIR[anacron]: <dir>           → (+ RELATIVE_CMD[root,anacron]: → Anacron PATH)
#   WILDCARD[root,anacron]: <dir>:<file>:<line>:<body>  → Anacron Wildcards
#
# At-jobs (atd queue) → At-job walkthroughs (stubs):
#   WRITABLE_SCRIPT[root,at]: <path>            → At-job File Permissions
#   RELATIVE_CMD[root,at]: <cmd>                → (+ WRITABLE_PATH_DIR[at]: → At-job PATH)
#   WRITABLE_PATH_DIR[at]: <dir>                → (+ RELATIVE_CMD[root,at]: → At-job PATH)
#   WILDCARD[root,at]: <dir>:<file>:<line>:<body>  → At-job Wildcards
#   AT_SPOOL_DENIED: <dir>                      → informational; spool exists but
#                                                  not enumerable from current user
#                                                  (typical default: 0700 daemon:daemon
#                                                  on the dir, 0700 owner=submitter on
#                                                  job files). No routing — log only.
#
# Sources enumerated:
#   /etc/crontab, /etc/cron.d/*                                  (cron daemon, 6-field with user)
#   /etc/cron.{daily,hourly,weekly,monthly}/*                    (run-parts dirs, always root)
#   /var/spool/cron/crontabs/root                                (root's user crontab, 5-field no user)
#   /etc/anacrontab                                              (anacron, period delay jobid cmd, always root)
#   /var/spool/cron/atjobs/, /var/spool/at/                      (at-job queue, root-owned files only)
#   Bodies of all scripts cron + anacron + at invoke as root
#
# Pre-root by design — operationally never run as root. Unlike history_enum /
# config_enum / ssh_enum, sched_enum has no post-root analog: scheduled-job
# writability has no Credential Extraction Checksheet hook (scheduled jobs are
# a PrivEsc vector, not a credential source). Under root, [ -w ] checks become
# meaningless via CAP_DAC_OVERRIDE — the script will run but emit operationally
# useless markers. Tests T4/T12/T20 SKIP under root for this reason.
#
# PrivEsc-only filter: only root-run entries surface markers.
# Non-root user crontabs not scanned (lateral, not PrivEsc).
# Non-root at-jobs not scanned (lateral).
# Systemd unit enumeration moved out — see systemd_enum.sh (separate Checksheet step).

# --- Source presence ---
cron_files=""
for _f in /etc/crontab /etc/cron.d/*; do [ -f "$_f" ] && cron_files="$cron_files $_f"; done

user_crontab=""
[ -r /var/spool/cron/crontabs/root ] && user_crontab="/var/spool/cron/crontabs/root"

anacrontab=""
[ -r /etc/anacrontab ] && anacrontab="/etc/anacrontab"

# --- PATH extraction per scheduler family ---
# !!! LIMITATION: uses the FIRST PATH= found per scheduler. cron applies PATH per-file;
# !!! we collapse to one PATH per scheduler family. If a cron.d file or user crontab
# !!! sets a divergent PATH, relative-cmd resolution can be wrong for that file's entries.
# !!! Same limitation applies to anacron and at-jobs.
cron_path=$(grep -h '^PATH=' /etc/crontab /etc/cron.d/* $user_crontab 2>/dev/null | head -1 | cut -d= -f2)
[ -z "$cron_path" ] && cron_path="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"

anacron_path=""
if [ -n "$anacrontab" ]; then
  anacron_path=$(grep -h '^PATH=' "$anacrontab" 2>/dev/null | head -1 | cut -d= -f2)
  [ -z "$anacron_path" ] && anacron_path="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"
fi

# ============================================================================
# CRON-FAMILY: WRITABLE_SCRIPT[root,cron] + RELATIVE_CMD[root,cron] + WRITABLE_PATH_DIR[cron]
# Includes /etc/crontab + /etc/cron.d/* (6-field with user) + run-parts dirs (always root)
# + /var/spool/cron/crontabs/root (5-field no user, implicit root)
# ============================================================================

# --- Collect all root-run cron-invoked script paths ---
cron_scripts=$(
  {
    # /etc/crontab + /etc/cron.d/*: absolute-path tokens from root-run entries (6-field)
    [ -n "$cron_files" ] && awk '/^[^#]/ { if ($1~/^@/) { if (NF<3) next; u=$2; s=3 } else { if (NF<7) next; u=$6; s=7 } if (u!="root" && u!="0") next; for(i=s;i<=NF;i++) if ($i~/^\//) print $i }' $cron_files 2>/dev/null

    # /etc/crontab + /etc/cron.d/*: relative-path commands resolved via cron_path
    [ -n "$cron_files" ] && awk '/^[^#]/ { if ($1~/^@/) { if (NF<3) next; u=$2; c=$3 } else { if (NF<7) next; u=$6; c=$7 } if ((u=="root" || u=="0") && c!~/\// && c!~/^[A-Z_]+=/) print c }' $cron_files 2>/dev/null \
      | sort -u | while read -r c; do
        PATH="$cron_path" command -v "$c" 2>/dev/null
      done

    # /var/spool/cron/crontabs/root: absolute-path tokens (5-field, no user)
    [ -n "$user_crontab" ] && awk '/^[^#]/ { if ($1~/^@/) { if (NF<2) next; s=2 } else { if (NF<6) next; s=6 } for(i=s;i<=NF;i++) if ($i~/^\//) print $i }' "$user_crontab" 2>/dev/null

    # /var/spool/cron/crontabs/root: relative-path commands resolved via cron_path
    [ -n "$user_crontab" ] && awk '/^[^#]/ { if ($1~/^@/) { if (NF<2) next; c=$2 } else { if (NF<6) next; c=$6 } if (c!~/\// && c!~/^[A-Z_]+=/) print c }' "$user_crontab" 2>/dev/null \
      | sort -u | while read -r c; do
        PATH="$cron_path" command -v "$c" 2>/dev/null
      done

    # Scripts in run-parts directories (always executed as root by crond)
    find /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -maxdepth 1 -type f 2>/dev/null
  } | sort -u
)

# --- WRITABLE_SCRIPT[root,cron]: writable cron-invoked scripts ---
echo "$cron_scripts" | while read -r f; do
  [ -f "$f" ] && [ -w "$f" ] && echo "WRITABLE_SCRIPT[root,cron]: $f"
done

# --- RELATIVE_CMD[root,cron]: PATH-routable relative commands in cron-family entries ---
{
  [ -n "$cron_files" ] && awk '/^[^#]/ { if ($1~/^@/) { if (NF<3) next; u=$2; c=$3 } else { if (NF<7) next; u=$6; c=$7 } if ((u=="root" || u=="0") && c!~/\// && c!~/^[A-Z_]+=/) print c }' $cron_files 2>/dev/null
  [ -n "$user_crontab" ] && awk '/^[^#]/ { if ($1~/^@/) { if (NF<2) next; c=$2 } else { if (NF<6) next; c=$6 } if (c!~/\// && c!~/^[A-Z_]+=/) print c }' "$user_crontab" 2>/dev/null
} | sort -u | while read -r c; do
  case "$(PATH="$cron_path" command -v "$c" 2>/dev/null)" in
    /*|"") echo "RELATIVE_CMD[root,cron]: $c" ;;
  esac
done

# --- WRITABLE_PATH_DIR[cron]: writable directories in cron's PATH ---
echo "$cron_path" | tr ':' '\n' | while read -r d; do
  [ -w "$d" ] && echo "WRITABLE_PATH_DIR[cron]: $d"
done

# ============================================================================
# ANACRON: WRITABLE_SCRIPT[root,anacron] + RELATIVE_CMD[root,anacron] + WRITABLE_PATH_DIR[anacron]
# /etc/anacrontab format: "period delay job-identifier command [args...]"
# All entries run as root by default. Variable-assignment lines (PATH=, etc.) excluded.
# ============================================================================

if [ -n "$anacrontab" ]; then
  # --- Collect anacron-invoked script paths ---
  anacron_scripts=$(
    {
      # Absolute-path tokens in command position (field 4 onward)
      awk '/^[^#]/ && $1 !~ /=/ && NF>=4 { for(i=4;i<=NF;i++) if ($i~/^\//) print $i }' "$anacrontab" 2>/dev/null

      # Relative-path commands (field 4 only) resolved via anacron_path
      awk '/^[^#]/ && $1 !~ /=/ && NF>=4 { c=$4; if (c!~/\// && c!~/^[A-Z_]+=/) print c }' "$anacrontab" 2>/dev/null \
        | sort -u | while read -r c; do
          PATH="$anacron_path" command -v "$c" 2>/dev/null
        done
    } | sort -u
  )

  # --- WRITABLE_SCRIPT[root,anacron]: writable anacron-invoked scripts ---
  echo "$anacron_scripts" | while read -r f; do
    [ -f "$f" ] && [ -w "$f" ] && echo "WRITABLE_SCRIPT[root,anacron]: $f"
  done

  # --- RELATIVE_CMD[root,anacron]: relative commands in anacrontab ---
  awk '/^[^#]/ && $1 !~ /=/ && NF>=4 { c=$4; if (c!~/\// && c!~/^[A-Z_]+=/) print c }' "$anacrontab" 2>/dev/null \
    | sort -u | while read -r c; do
      case "$(PATH="$anacron_path" command -v "$c" 2>/dev/null)" in
        /*|"") echo "RELATIVE_CMD[root,anacron]: $c" ;;
      esac
    done

  # --- WRITABLE_PATH_DIR[anacron]: writable directories in anacron's PATH ---
  echo "$anacron_path" | tr ':' '\n' | while read -r d; do
    [ -w "$d" ] && echo "WRITABLE_PATH_DIR[anacron]: $d"
  done
fi

# ============================================================================
# AT-JOBS: WRITABLE_SCRIPT[root,at] + RELATIVE_CMD[root,at] + WRITABLE_PATH_DIR[at]
# Spool: /var/spool/cron/atjobs/ (Debian/Ubuntu) or /var/spool/at/ (RHEL/CentOS).
# Default perms (0700 daemon:daemon on the dir, 0700 owner=submitter on job files)
# typically block foothold enumeration. AT_SPOOL_DENIED emitted when spool present
# but inaccessible — informational only, no routing (per V_S "no silent false
# negatives" rule). Routing markers fire on the rare permissions-misconfig case.
#
# Each readable root-owned at-job file IS treated as its own script body:
#   - The file itself is the executable script (no /etc/crontab-style declaration layer).
#   - PATH= is embedded by atd at submission time; parsed from job content.
#   - WRITABLE_SCRIPT tracks both the at-job file itself + abs-path references inside.
# ============================================================================

at_spool=""
for _d in /var/spool/cron/atjobs /var/spool/at; do
  [ -d "$_d" ] && at_spool="$_d" && break
done

at_path=""
at_jobs=""

if [ -n "$at_spool" ]; then
  if [ -r "$at_spool" ] && [ -x "$at_spool" ]; then
    # Spool listable. Enumerate root-owned readable job files.
    at_jobs=$(find "$at_spool" -maxdepth 1 -type f -uid 0 -readable 2>/dev/null)

    # AT_SPOOL_DENIED fires only when spool contains files that are NOT readable
    # to us (e.g. 0600 owner=root from foothold). Non-root jobs that we CAN read
    # don't count as "denied" — they're just filtered out by the PrivEsc-only rule.
    _total=$(find "$at_spool" -maxdepth 1 -type f 2>/dev/null | wc -l)
    _readable=$(find "$at_spool" -maxdepth 1 -type f -readable 2>/dev/null | wc -l)
    if [ "$_total" -gt 0 ] && [ "$_readable" -eq 0 ]; then
      echo "AT_SPOOL_DENIED: $at_spool"
    fi

    if [ -n "$at_jobs" ]; then
      # Extract PATH from first readable root at-job (atd embeds submitter's PATH).
      # Form: PATH=/usr/local/sbin:...; export PATH
      _first_job=$(echo "$at_jobs" | head -1)
      at_path=$(grep -h '^PATH=' "$_first_job" 2>/dev/null | head -1 \
        | sed -e 's/^PATH=//' -e 's/;.*$//' -e "s/^['\"]//" -e "s/['\"]\$//")
      [ -z "$at_path" ] && at_path="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"
    fi
  else
    echo "AT_SPOOL_DENIED: $at_spool"
  fi
fi

# --- Collect at-invoked script paths (the job file itself + refs inside) ---
at_scripts=""
if [ -n "$at_jobs" ]; then
  at_scripts=$(
    {
      # The at-job file itself IS a script — track for writability
      echo "$at_jobs"

      # Absolute-path tokens inside job bodies (skip atd bookkeeping/env lines)
      for _j in $at_jobs; do
        grep -vE '^#|^PATH=|^umask|^export |^[A-Z_]+=' "$_j" 2>/dev/null \
          | awk '{ for(i=1;i<=NF;i++) if ($i~/^\//) print $i }'
      done

      # Relative-path commands (first token of each non-env line) resolved via at_path
      for _j in $at_jobs; do
        grep -vE '^#|^PATH=|^umask|^export |^[A-Z_]+=' "$_j" 2>/dev/null \
          | awk 'NF>=1 && $1 !~ /^\// && $1 ~ /^[a-zA-Z_]/ && $1 !~ /=/ { print $1 }'
      done | sort -u | while read -r _c; do
        PATH="$at_path" command -v "$_c" 2>/dev/null
      done
    } | sort -u
  )
fi

# --- WRITABLE_SCRIPT[root,at]: writable at-invoked scripts (incl. job file itself) ---
if [ -n "$at_scripts" ]; then
  echo "$at_scripts" | while read -r _f; do
    [ -f "$_f" ] && [ -w "$_f" ] && echo "WRITABLE_SCRIPT[root,at]: $_f"
  done
fi

# --- RELATIVE_CMD[root,at]: PATH-routable relative commands in at-job bodies ---
if [ -n "$at_jobs" ]; then
  for _j in $at_jobs; do
    grep -vE '^#|^PATH=|^umask|^export |^[A-Z_]+=' "$_j" 2>/dev/null \
      | awk 'NF>=1 && $1 !~ /^\// && $1 ~ /^[a-zA-Z_]/ && $1 !~ /=/ { print $1 }'
  done | sort -u | while read -r _c; do
    case "$(PATH="$at_path" command -v "$_c" 2>/dev/null)" in
      /*|"") echo "RELATIVE_CMD[root,at]: $_c" ;;
    esac
  done
fi

# --- WRITABLE_PATH_DIR[at]: writable directories in at-job PATH ---
if [ -n "$at_path" ]; then
  echo "$at_path" | tr ':' '\n' | while read -r _d; do
    [ -w "$_d" ] && echo "WRITABLE_PATH_DIR[at]: $_d"
  done
fi

# ============================================================================
# WILDCARD expansion-dir resolution helpers (shared cron + anacron + at)
# Resolves the dir the bare * expands against = the cwd when the binary runs, by
# replaying the job's governing `cd`s in order from its initial cwd.
# Emits an absolute path, or UNRESOLVED when the cwd can't be determined statically.
# Initial cwd:
#   cron direct job:   root's HOME (standard cron chdir($HOME))
#   cron run-parts:    UNRESOLVED (wrapper-dependent)
#   user crontab:      root's HOME (same as cron direct)
#   anacron entry:     /  (anacron jobs start at /)
#   anacron script:    /
#   at-job:            root's HOME (atd chdirs to submitter HOME before exec)
# LIMITATION: assumes linear top-to-bottom execution; cd inside conditional/loop/
# function control flow is replayed as if always run.
# ============================================================================

_WC_BINS='tar|rsync|chown|chmod|gzip'   # keep in sync with WILDCARD grep below

# _wc_norm <abs_path>: lexical normalisation (resolve . and ..; no filesystem touch).
_wc_norm() {
  awk -v p="$1" 'BEGIN{
    n=split(p,a,"/"); m=0;
    for(i=1;i<=n;i++){ c=a[i];
      if(c=="" || c==".") continue;
      if(c==".."){ if(m>0) m--; continue; }
      st[++m]=c; }
    o=""; for(i=1;i<=m;i++) o=o "/" st[i];
    print (o==""?"/":o); }'
}

# _wc_strip_prefix <source_kind> <line>: drop schedule/user/jobid prefix, echo command portion.
# source_kind: "cron6"  = /etc/crontab or /etc/cron.d/* (6-field with user)
#              "cron5"  = /var/spool/cron/crontabs/root (5-field no user)
#              "anac"   = /etc/anacrontab (period delay jobid cmd...)
#              "at"     = at-job body line (no scheduler prefix; pass-through)
_wc_strip_prefix() {
  case "$1" in
    cron6) awk '{ s=($1~/^@/)?3:7; for(i=s;i<=NF;i++) printf "%s%s",$i,(i<NF?" ":""); print "" }' <<<"$2" ;;
    cron5) awk '{ s=($1~/^@/)?2:6; for(i=s;i<=NF;i++) printf "%s%s",$i,(i<NF?" ":""); print "" }' <<<"$2" ;;
    anac)  awk '{ for(i=4;i<=NF;i++) printf "%s%s",$i,(i<NF?" ":""); print "" }' <<<"$2" ;;
    at)    printf '%s\n' "$2" ;;
  esac
}

# _wc_resolve_dir <source_kind> <file> <line> <body>: emit expansion dir or UNRESOLVED.
_wc_resolve_dir() {
  _sk="$1"; _f="$2"; _ln="$3"; _bd="$4"
  _rh=$(awk -F: '$1=="root"{print $6; exit}' /etc/passwd); _rh="${_rh:-/root}"

  # initial cwd by source kind + file shape
  case "$_sk" in
    cron6|cron5)
      case "$_f" in
        */cron.daily/*|*/cron.hourly/*|*/cron.weekly/*|*/cron.monthly/*) _cwd="" ;;
        *) _cwd="$_rh" ;;
      esac
      ;;
    anac)
      _cwd="/"
      ;;
    at)
      _cwd="$_rh"
      ;;
  esac

  # governing text: inline entry (crontab/anacrontab) → command portion of the line;
  # script body → lines 1..hit
  case "$_f" in
    /etc/crontab|/etc/cron.d/*) _gov=$(_wc_strip_prefix cron6 "$_bd") ;;
    /var/spool/cron/crontabs/*) _gov=$(_wc_strip_prefix cron5 "$_bd") ;;
    /etc/anacrontab)            _gov=$(_wc_strip_prefix anac "$_bd") ;;
    *) if [ -f "$_f" ]; then _gov=$(awk -v n="$_ln" 'NR<=n' "$_f"); else _gov="$_bd"; fi ;;
  esac

  # replay commands in order (split on newline, &&, ||, ;); stop at the wildcard binary
  while IFS= read -r _cmd; do
    _cmd="${_cmd#"${_cmd%%[![:space:]]*}"}"; _cmd="${_cmd%"${_cmd##*[![:space:]]}"}"  # trim
    [ -z "$_cmd" ] && continue
    _w1="${_cmd%%[[:space:]]*}"
    case "$_w1" in
      tar|rsync|chown|chmod|gzip) break ;;
      cd)
        _op="${_cmd#cd}"; _op="${_op#"${_op%%[![:space:]]*}"}"; _op="${_op%%[[:space:]]*}"
        _op="${_op%\"}"; _op="${_op#\"}"; _op="${_op%\'}"; _op="${_op#\'}"
        if [ -z "$_op" ]; then _cwd="$_rh"
        else case "$_op" in
          /*)            _cwd=$(_wc_norm "$_op") ;;
          "~")           _cwd="$_rh" ;;
          *'$'*|*'`'*|'-'|'~'*) _cwd="" ;;
          *)             [ -n "$_cwd" ] && _cwd=$(_wc_norm "$_cwd/$_op") ;;
        esac; fi
        ;;
      *) : ;;
    esac
  done <<<"$(printf '%s\n' "$_gov" | sed 's/&&/\n/g; s/||/\n/g; s/;/\n/g')"
  [ -n "$_cwd" ] && echo "$_cwd" || echo "UNRESOLVED"
}

# --- WILDCARD[root,cron]: cron-family inline entries + cron-invoked script bodies ---
{
  # Inline entries in /etc/crontab + /etc/cron.d/* (6-field, user filter)
  for _f in /etc/crontab /etc/cron.d/*; do
    [ -f "$_f" ] || continue
    awk -v f="$_f" '/^[^#]/ { if ($1~/^@/) { if (NF<3) next; u=$2 } else { if (NF<7) next; u=$6 } if (u=="root" || u=="0") print f ":" NR ":" $0 }' "$_f"
  done | grep -E '\b(tar|rsync|chown|chmod|gzip)\b.*\*' | while IFS= read -r _rec; do
    _wf=${_rec%%:*}; _wr=${_rec#*:}; _wl=${_wr%%:*}; _wb=${_wr#*:}
    _wd=$(_wc_resolve_dir cron6 "$_wf" "$_wl" "$_wb")
    echo "WILDCARD[root,cron]: $_wd:$_wf:$_wl:$_wb"
  done

  # Inline entries in /var/spool/cron/crontabs/root (5-field, no user filter — file = root)
  if [ -n "$user_crontab" ]; then
    awk -v f="$user_crontab" '/^[^#]/ { if ($1~/^@/) { if (NF<2) next } else { if (NF<6) next } print f ":" NR ":" $0 }' "$user_crontab" \
      | grep -E '\b(tar|rsync|chown|chmod|gzip)\b.*\*' | while IFS= read -r _rec; do
        _wf=${_rec%%:*}; _wr=${_rec#*:}; _wl=${_wr%%:*}; _wb=${_wr#*:}
        _wd=$(_wc_resolve_dir cron5 "$_wf" "$_wl" "$_wb")
        echo "WILDCARD[root,cron]: $_wd:$_wf:$_wl:$_wb"
      done
  fi

  # Script bodies invoked by cron-family (cron_scripts already filtered to root-run)
  echo "$cron_scripts" | while read -r f; do
    [ -f "$f" ] && grep -nHE '\b(tar|rsync|chown|chmod|gzip)\b.*\*' "$f" 2>/dev/null
  done | while IFS= read -r _rec; do
    [ -z "$_rec" ] && continue
    _wf=${_rec%%:*}; _wr=${_rec#*:}; _wl=${_wr%%:*}; _wb=${_wr#*:}
    _wd=$(_wc_resolve_dir cron6 "$_wf" "$_wl" "$_wb")
    echo "WILDCARD[root,cron]: $_wd:$_wf:$_wl:$_wb"
  done
}

# --- WILDCARD[root,anacron]: anacrontab inline entries + anacron-invoked script bodies ---
if [ -n "$anacrontab" ]; then
  {
    # Inline entries in /etc/anacrontab (always root, skip variable-assignment lines)
    awk -v f="$anacrontab" '/^[^#]/ && $1 !~ /=/ && NF>=4 { print f ":" NR ":" $0 }' "$anacrontab" \
      | grep -E '\b(tar|rsync|chown|chmod|gzip)\b.*\*' | while IFS= read -r _rec; do
        _wf=${_rec%%:*}; _wr=${_rec#*:}; _wl=${_wr%%:*}; _wb=${_wr#*:}
        _wd=$(_wc_resolve_dir anac "$_wf" "$_wl" "$_wb")
        echo "WILDCARD[root,anacron]: $_wd:$_wf:$_wl:$_wb"
      done

    # Script bodies invoked by anacron (anacron_scripts already filtered to root-run)
    echo "$anacron_scripts" | while read -r f; do
      [ -f "$f" ] && grep -nHE '\b(tar|rsync|chown|chmod|gzip)\b.*\*' "$f" 2>/dev/null
    done | while IFS= read -r _rec; do
      [ -z "$_rec" ] && continue
      _wf=${_rec%%:*}; _wr=${_rec#*:}; _wl=${_wr%%:*}; _wb=${_wr#*:}
      _wd=$(_wc_resolve_dir anac "$_wf" "$_wl" "$_wb")
      echo "WILDCARD[root,anacron]: $_wd:$_wf:$_wl:$_wb"
    done
  }
fi

# --- WILDCARD[root,at]: at-job script body wildcards ---
if [ -n "$at_jobs" ]; then
  {
    echo "$at_jobs" | while read -r f; do
      [ -f "$f" ] && grep -nHE '\b(tar|rsync|chown|chmod|gzip)\b.*\*' "$f" 2>/dev/null
    done | while IFS= read -r _rec; do
      [ -z "$_rec" ] && continue
      _wf=${_rec%%:*}; _wr=${_rec#*:}; _wl=${_wr%%:*}; _wb=${_wr#*:}
      _wd=$(_wc_resolve_dir at "$_wf" "$_wl" "$_wb")
      echo "WILDCARD[root,at]: $_wd:$_wf:$_wl:$_wb"
    done
  }
fi
