#!/bin/bash
# af_unix_sock_enum.sh — writable AF_UNIX domain socket enumeration for PrivEsc routing.
#
# Emits daemon-tagged markers consumed by Linux Privilege Escalation Checksheet
# 'AF_UNIX Socket Hijacking'. Scope: /var/run /run /tmp /var/lib /var/snap.
#
# Marker contract:
#   WRITABLE_AF_UNIX_SOCK[docker]:     <path>  → Docker Socket Abuse
#   WRITABLE_AF_UNIX_SOCK[lxd]:        <path>  → LXD Socket Abuse
#   WRITABLE_AF_UNIX_SOCK[redis]:      <path>  → Redis Socket Abuse
#   WRITABLE_AF_UNIX_SOCK[memcached]:  <path>  → no canonical chain, take next
#   WRITABLE_AF_UNIX_SOCK[unknown]:    <path>  → Unknown Daemon Socket Abuse
#   AF_UNIX_SOCK_SCANNED                       → check-completion (always emitted)
#
# Selection: -type s (AF_UNIX socket files only), -writable (kernel access(2),
# catches mode bits AND POSIX ACL grants from foothold's real UID),
# -not -user "$(id -u)" (drops foothold-owned tmux/session-bus/screen self-comms).
#
# Allowlist branches: canonical AF_UNIX Socket Hijacking exploit chains
# (documented walkthroughs). Grow when new canonical chain is documented.
#
# Blacklist branches: legit-by-design system daemons that expose sockets to
# any local process by protocol design (dbus, journald, cups, etc.) — silent
# drop prevents noise-domination on stock Linux installs (produces 17 markers
# on baseline Ubuntu without the blacklist). Grow when Unknown Daemon Socket
# Abuse walkthrough identifies a new legit-by-design daemon.
#
# Catch-all: novel writable socket → Unknown Daemon Socket Abuse walkthrough
# performs banner-probe identification + generic-primitive-family exploitation
# attempt, and feeds outcome back into allowlist or blacklist for future runs.
#
# Path patterns use */prefix wildcards to match standard system paths and
# non-standard mounted paths (chroot, container bind-mounts).
#
# IOC: local file reads only. No network, no writes, no privileged operations.
# Bounded to five scope directories; no filesystem traversal.

find /var/run /run /tmp /var/lib /var/snap -type s -writable -not -user "$(id -u)" 2>/dev/null | while read s; do
  case "$s" in

    # --- Allowlist: canonical AF_UNIX Socket Hijacking exploit chains ---
    */docker.sock)                                  echo "WRITABLE_AF_UNIX_SOCK[docker]: $s" ;;
    */lxd/unix.socket|*/lxd/*/unix.socket)          echo "WRITABLE_AF_UNIX_SOCK[lxd]: $s" ;;
    */redis*.sock|*/redis-server.sock)              echo "WRITABLE_AF_UNIX_SOCK[redis]: $s" ;;
    */memcached.sock)                               echo "WRITABLE_AF_UNIX_SOCK[memcached]: $s" ;;

    # --- Blacklist: legit-by-design system daemons (silent drop) ---
    #   systemd/*         — systemd-{journald,resolved,oomd,userdb,notify,...}
    #   dbus/*            — session + system message bus
    #   cups/*            — CUPS print spooler
    #   avahi-daemon/*    — mDNS/DNS-SD
    #   uuidd/*           — UUID generation daemon
    #   NetworkManager/*  — NM socket for network config
    #   lvm/*             — LVM (dmeventd, lvmpolld)
    #   tuned/*           — RHEL/CentOS tuning daemon
    #   dmeventd*         — device-mapper event daemon
    #   sepermit/*        — SELinux permit daemon
    #   rpcbind*          — rpcbind portmap (NFS support)
    #   snapd*            — snap package manager
    #   .ICE-unix/*       — X11 Inter-Client Exchange
    #   .X11-unix/*       — X11 display sockets (X protocol; local connect by design)
    #   canonical-livepatch/*  — Ubuntu kernel livepatch daemon
    #   polkit/*          — PolicyKit auth-agent IPC
    #   pcscd/*           — PC/SC smart card daemon
    #   ssh-unix-local/*  — systemd-ssh-generator local SSH endpoint (SSH auth applies)
    #   .iprt-localipc-*  — VirtualBox Guest Additions display IPC (no code exec)
    #   acpid.socket      — ACPI event daemon (world-connectable by design; event-subscription only, no code exec)
    #   mysqld.sock, mysql.sock, mariadb.sock  — MySQL/MariaDB. NOT a writable-socket-primitive vector: default socket perms are 0777 on all distros (writability ubiquitous, not a misconfig signal); MySQL protocol requires authentication regardless of transport; UDF exploit chain is auth-gated and transport-agnostic (socket vs TCP identical). Discriminating condition = "mysqld runs as root" (detected by ps in LPEC Step 10) + "attacker can authenticate with FILE priv" (harvested creds OR auth-bypass paths handled in the MySQL UDF walkthrough Step 1). Canonical route: LPEC Step 10 → [[MySQL UDF]].
    #   .s.PGSQL.*, postgresql/*  — PostgreSQL. Same reasoning as MySQL/MariaDB: default 0777 socket (transport availability, not exploit signal), auth required regardless of transport, COPY FROM PROGRAM exploit is auth-gated and transport-agnostic. Canonical route: LPEC Step 10 → [[Postgres UDF]].
    */systemd/*|*/dbus/*|*/cups/*|*/avahi-daemon/*|*/uuidd/*|*/NetworkManager/*|*/lvm/*|*/tuned/*|*/dmeventd*|*/sepermit/*|*/rpcbind*|*/snapd*|*/.ICE-unix/*|*/.X11-unix/*|*/canonical-livepatch/*|*/polkit/*|*/pcscd/*|*/ssh-unix-local/*|*/.iprt-localipc-*|*/acpid.socket|*/mysqld.sock|*/mysql.sock|*/mariadb.sock|*/.s.PGSQL.*|*/postgresql/*)
      ;;

    # --- Catch-all: novel writable socket, triage via walkthrough ---
    *)                                              echo "WRITABLE_AF_UNIX_SOCK[unknown]: $s" ;;

  esac
done
echo "AF_UNIX_SOCK_SCANNED"
