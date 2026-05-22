#!/bin/bash
# cron_enum.sh — Linux cron enumeration for PrivEsc routing
#
# Outputs explicit markers consumed by Linux Privilege Escalation Checksheet Step 3:
#   WRITABLE_SCRIPT[root]: <path>     → route: Cron File Permissions
#   RELATIVE_CMD[root]: <cmd>         → (combined with WRITABLE_PATH_DIR → Cron PATH)
#   WRITABLE_PATH_DIR: <dir>          → (combined with RELATIVE_CMD → Cron PATH)
#   WILDCARD[root]: <dir>:<file>:<line>:<body>  → route: Cron Wildcards
#       <dir> = resolved absolute glob expansion directory (cwd when the binary runs),
#       or UNRESOLVED when not statically determinable (variable/computed cd, relative
#       cd with no resolvable base, or a run-parts job lacking an absolute cd).
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

# --- Expansion-directory resolution for WILDCARD hits ---
# Resolves the dir the bare * expands against = the cwd when the binary runs, by
# replaying the job's governing `cd`s in order from its initial cwd.
# Emits an absolute path, or UNRESOLVED when the cwd can't be determined statically
# (variable/computed cd; relative cd with no resolvable base; run-parts job lacking
# an absolute cd). WILDCARD hits are root-only by construction (privesc-to-root), so
# the initial cwd of a non-run-parts job is root's HOME (standard cron chdir($HOME)).
# LIMITATION: assumes linear top-to-bottom execution; a cd inside conditional/loop/
# function control flow is replayed as if it always runs.
_WC_BINS='tar|rsync|chown|chmod|gzip'   # keep in sync with the WILDCARD grep below

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

# _wc_strip_cron_prefix <cron_line>: drop schedule+user fields, echo the command portion
# (@-string: fields 1-2; numeric: fields 1-6).
_wc_strip_cron_prefix() {
  awk '{ s=($1~/^@/)?3:7; for(i=s;i<=NF;i++) printf "%s%s",$i,(i<NF?" ":""); print "" }' <<<"$1"
}

# _wc_resolve_dir <file> <line> <body>: emit the expansion dir or UNRESOLVED.
_wc_resolve_dir() {
  _f="$1"; _ln="$2"; _bd="$3"
  _rh=$(awk -F: '$1=="root"{print $6; exit}' /etc/passwd); _rh="${_rh:-/root}"
  # initial cwd: root's HOME for a direct job; unknown for a run-parts script
  case "$_f" in
    */cron.daily/*|*/cron.hourly/*|*/cron.weekly/*|*/cron.monthly/*) _cwd="" ;;
    *) _cwd="$_rh" ;;
  esac
  # governing text: inline entry → command portion of the line; script → lines 1..hit
  case "$_f" in
    /etc/crontab|/etc/cron.d/*) _gov=$(_wc_strip_cron_prefix "$_bd") ;;
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
} | while IFS= read -r _rec; do
  [ -z "$_rec" ] && continue
  _wf=${_rec%%:*}; _wr=${_rec#*:}; _wl=${_wr%%:*}; _wb=${_wr#*:}
  _wd=$(_wc_resolve_dir "$_wf" "$_wl" "$_wb")
  echo "WILDCARD[root]: $_wd:$_wf:$_wl:$_wb"
done
