#!/bin/bash
# searchsploit_ladder.sh — Pass 1 Lookup B automation
#
# Reads services_*.txt in CWD. For each TCP/UDP service row that has both a
# service name and a version field, runs the searchsploit string-variation
# ladder, dedupes hits across queries, classifies each by title keywords,
# parses any version constraint in the title, and compares against the
# target version. Writes searchsploit_<ip>.txt per host.
#
# Every hit is shown and tagged. Operator does final triage:
#   - Open searchsploit_<ip>.txt
#   - Focus on bucket=foothold and bucket=manual
#   - `searchsploit -x <path>` to read source before exploiting
#   - Log foothold-grade candidates to route_<ip>.txt per Step 7
#
# HEURISTIC NOTES (script is starting point, not final answer):
#   - Bucket classification is keyword-based on title only. False positives
#     and negatives both possible. Always read source.
#   - Buckets: foothold (RCE/CmdInj/AuthBypass/etc.) > manual (unclear,
#     read source) > weak (DoS/enum/disclosure/local-privesc/etc.) — every
#     row shown regardless, just sorted and tagged.
#   - Version parser handles: `< X`, `<= X`, `or prior`, `and below`,
#     `X < Y` (range), exact-version. Edge cases yield match=? (kept).
#   - Inner-product fields like `Node.js (Express middleware)` are flagged
#     in output. Run inner ladder manually.
#
# AWAITING VERSION:
#   Rows where field 5 has product but no version run only product-only
#   queries and tag every hit version=? in MATCH column. These need re-firing
#   when a version surfaces (Pass 1 re-fire mechanism — separate task).
#
# GENERIC PRODUCT:
#   Rows where parsed PRODUCT is too generic for service-version-keyed lookup
#   (currently only "Microsoft Windows" — happens when nmap stuffs OS guesses
#   into the version field for OS-bundled services like SMB/MSRPC). Row prints
#   summary block with skip reason and is dropped — no queries fired. OS-keyed
#   exploit hunting belongs in Lookup C / per-service workflow.

set -u
shopt -s nullglob

# --- Classification keyword sets ---
FOOTHOLD_RE='([Rr]emote [Cc]ode [Ee]xecution|[Rr]emote [Cc]ommand [Ee]xecution|\bRCE\b|[Cc]ommand [Ii]njection|[Cc]ommand [Ee]xecution|[Aa]uth(entication)? [Bb]ypass|[Uu]nauthenticated|[Pp]re-?[Aa]uth|[Bb]ackdoor|[Aa]rbitrary [Cc]ode|[Aa]rbitrary [Ff]ile [Uu]pload)'
DISCARD_RE='([Dd]enial of [Ss]ervice|\bDoS\b|[Ee]numeration|[Dd]isclosure|[Ii]nformation [Ll]eak|[Tt]iming [Aa]ttack|[Oo]ff-?by-?one|[Ll]ocal [Pp]rivilege [Ee]scalation)'

classify() {
    local title="$1"
    if [[ "$title" =~ $FOOTHOLD_RE ]]; then echo "foothold"; return; fi
    if [[ "$title" =~ $DISCARD_RE ]]; then echo "weak"; return; fi
    echo "manual"
}

parse_constraint() {
    local title="$1"
    if [[ "$title" =~ ([0-9]+(\.[0-9]+)+[a-z0-9]*)[[:space:]]*\<[[:space:]]*([0-9]+(\.[0-9]+)+[a-z0-9]*) ]]; then
        echo "range:${BASH_REMATCH[1]}:${BASH_REMATCH[3]}"; return
    fi
    if [[ "$title" =~ \<[[:space:]]*([0-9]+(\.[0-9]+)+[a-z0-9]*) ]]; then
        echo "lt:${BASH_REMATCH[1]}"; return
    fi
    if [[ "$title" =~ \<=[[:space:]]*([0-9]+(\.[0-9]+)+[a-z0-9]*) ]]; then
        echo "lte:${BASH_REMATCH[1]}"; return
    fi
    if [[ "$title" =~ ([0-9]+(\.[0-9]+)+[a-z0-9]*)[[:space:]]+(or [Pp]rior|and [Bb]elow) ]]; then
        echo "lte:${BASH_REMATCH[1]}"; return
    fi
    # Wildcard suffix: "N.x" or "N.M.x" → range from prefix to prefix+1
    if [[ "$title" =~ [[:space:]]([0-9]+(\.[0-9]+)*)\.x[[:space:]/-] ]]; then
        local prefix="${BASH_REMATCH[1]}"
        local last="${prefix##*.}"
        local rest="${prefix%.*}"
        local next=$((last + 1))
        if [ "$rest" = "$prefix" ]; then
            echo "range:${prefix}:${next}"
        else
            echo "range:${prefix}:${rest}.${next}"
        fi
        return
    fi
    # Slash-separated alternative versions: "X.Y/Z.W"
    if [[ "$title" =~ ([0-9]+(\.[0-9]+)+[a-z0-9]*)\/([0-9]+(\.[0-9]+)+[a-z0-9]*) ]]; then
        echo "eq_set:${BASH_REMATCH[1]}|${BASH_REMATCH[3]}"; return
    fi
    if [[ "$title" =~ [[:space:]]([0-9]+(\.[0-9]+)+[a-z0-9]*)[[:space:]] ]]; then
        echo "eq:${BASH_REMATCH[1]}"; return
    fi
    echo ""
}

match_constraint() {
    local constraint="$1" target="$2" v rest lo hi versions found has_amb
    [[ -z "$target" || -z "$constraint" ]] && { echo "?"; return; }
    case "$constraint" in
        lt:*)
            v="${constraint#lt:}"
            [ "$(is_partial_ambiguous "$target" "$v")" = "AMBIGUOUS" ] && { echo "?"; return; }
            dpkg --compare-versions "$target" lt "$v" 2>/dev/null && echo YES || echo NO ;;
        lte:*)
            v="${constraint#lte:}"
            [ "$(is_partial_ambiguous "$target" "$v")" = "AMBIGUOUS" ] && { echo "?"; return; }
            dpkg --compare-versions "$target" le "$v" 2>/dev/null && echo YES || echo NO ;;
        eq:*)
            v="${constraint#eq:}"
            [ "$(is_partial_ambiguous "$target" "$v")" = "AMBIGUOUS" ] && { echo "?"; return; }
            dpkg --compare-versions "$target" eq "$v" 2>/dev/null && echo YES || echo NO ;;
        range:*)
            rest="${constraint#range:}"; lo="${rest%:*}"; hi="${rest#*:}"
            if [ "$(is_partial_ambiguous "$target" "$lo")" = "AMBIGUOUS" ] \
               || [ "$(is_partial_ambiguous "$target" "$hi")" = "AMBIGUOUS" ]; then echo "?"; return; fi
            if dpkg --compare-versions "$target" ge "$lo" 2>/dev/null \
               && dpkg --compare-versions "$target" lt "$hi" 2>/dev/null; then echo YES; else echo NO; fi
            ;;
        eq_set:*)
            versions="${constraint#eq_set:}"
            found=0; has_amb=0
            local IFS='|'
            for v in $versions; do
                if [ "$(is_partial_ambiguous "$target" "$v")" = "AMBIGUOUS" ]; then has_amb=1; fi
                if dpkg --compare-versions "$target" eq "$v" 2>/dev/null; then found=1; break; fi
            done
            if [ "$found" = "1" ]; then echo YES
            elif [ "$has_amb" = "1" ]; then echo "?"
            else echo NO; fi
            ;;
        *) echo "?" ;;
    esac
}

# Returns "AMBIGUOUS" if target has fewer dotted components than constraint version
# AND target's components fully match constraint's leading prefix (so unknown
# minor/patch could resolve to either side of the comparison).
is_partial_ambiguous() {
    local target="$1" cv="$2" i
    local -a t_comps c_comps
    IFS='.' read -ra t_comps <<< "$target"
    IFS='.' read -ra c_comps <<< "$cv"
    [ ${#t_comps[@]} -ge ${#c_comps[@]} ] && { echo ""; return; }
    for ((i=0; i<${#t_comps[@]}; i++)); do
        [ "${t_comps[$i]}" != "${c_comps[$i]}" ] && { echo ""; return; }
    done
    echo "AMBIGUOUS"
}

# Returns the bucket for a path+title. Path-based overrides for /local/ and
# /shellcode/, plus title-based override for (Authenticated) + Privilege
# Escalation (post-foothold material). Falls through to classify() for the rest.
bucket_for() {
    local path="$1" title="$2"
    if [[ "$path" =~ /local/ ]]; then echo "local"; return; fi
    if [[ "$path" =~ /shellcode/ ]]; then echo "shellcode"; return; fi
    if [[ "$title" =~ \([Aa]uthenticated\).*[Pp]rivilege[[:space:]][Ee]scalation ]]; then echo "local"; return; fi
    classify "$title"
}

# Returns 0 (true) if title contains PRODUCT / PRODUCT_STRIPPED / PRODUCT_SPACED
# as a whole word (case-insensitive). Drops cross-product false positives like
# 'Sambar Server' surfacing in 'Samba' searches.
title_contains_product() {
    local title="$1" v v_lc
    local title_lc="${title,,}"
    for v in "$PRODUCT" "$PRODUCT_STRIPPED" "$PRODUCT_SPACED"; do
        [ -z "$v" ] && continue
        v_lc="${v,,}"
        if [[ "$title_lc" =~ (^|[^a-z0-9])${v_lc}([^a-z0-9]|$) ]]; then
            return 0
        fi
    done
    return 1
}

# Returns 0 (true) if PRODUCT is too generic for Lookup B (service-version-keyed
# exploit lookup). When nmap stuffs OS guesses into the version field for OS-bundled
# services like SMB ("Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)"),
# the parser extracts PRODUCT="Microsoft Windows" and VFULL="7" — but "7" is just
# the low bound of an OS range, not a service version. Both queries that would run
# fail Lookup B's purpose:
#   1. Product+version query: queries an OS guess as if it were a service version
#   2. Product-only query: matches every Windows exploit ever published
# Skip the row entirely. OS-keyed exploit hunting belongs in Lookup C and
# per-service workflows.
is_generic_product() {
    case "$1" in
        "Microsoft Windows") return 0 ;;
        *) return 1 ;;
    esac
}

# Sets globals: PRODUCT, VFULL, VSTRICT, PRODUCT_SPACED, INNER_PRODUCT
parse_field5() {
    local f5="$1" cleaned
    cleaned="${f5%% (*}"
    cleaned="${cleaned%%(*}"
    cleaned="${cleaned%"${cleaned##*[![:space:]]}"}"
    # Normalise letter-(underscore|slash)-digit to letter-space-digit.
    # Captures SSH banner format (OpenSSH_8.2p1) and HTTP Server headers (Apache/2.4.41).
    cleaned=$(echo "$cleaned" | sed -E 's@([A-Za-z])[/_]([0-9])@\1 \2@g')

    INNER_PRODUCT=0
    if [[ "$f5" =~ \(([^\)]+)\) ]]; then
        local paren="${BASH_REMATCH[1]}"
        if [[ ! "$paren" =~ (\;|Linux|Windows|Ubuntu|Debian|RedHat|RHEL|CentOS|BSD|Solaris|Mac\ OS|FreeBSD|protocol) ]]; then
            INNER_PRODUCT=1
        fi
    fi

    if [[ "$cleaned" =~ ^(.*[A-Za-z])[[:space:]]+([0-9]+(\.[0-9]+)*[a-z0-9]*)([[:space:]].*)?$ ]]; then
        PRODUCT="${BASH_REMATCH[1]}"
        VFULL="${BASH_REMATCH[2]}"
        if [[ "$VFULL" =~ ^([0-9]+(\.[0-9]+)+)[a-z][0-9]+$ ]]; then
            VSTRICT="${BASH_REMATCH[1]}"
        else
            VSTRICT="$VFULL"
        fi
    else
        PRODUCT="$cleaned"
        VFULL=""
        VSTRICT=""
    fi
    PRODUCT="${PRODUCT%"${PRODUCT##*[![:space:]]}"}"

    # Daemon-stripped product (set whenever a strip happens, single- or multi-word)
    PRODUCT_STRIPPED=""
    PRODUCT_SPACED=""
    local stripped="$PRODUCT" did_strip=0
    if [[ "$stripped" =~ ^(.+)[[:space:]]+(httpd|smbd|sshd|server|Server)$ ]]; then
        stripped="${BASH_REMATCH[1]}"
        did_strip=1
    elif [[ "$stripped" =~ ^[^[:space:]]+[dD]$ ]]; then
        stripped="${stripped%[dD]}"
        did_strip=1
    fi
    if [ "$did_strip" = "1" ]; then
        PRODUCT_STRIPPED="$stripped"
        # CamelCase split — only set if it differs from stripped
        local spaced
        spaced=$(echo "$stripped" | sed 's/\([a-z]\)\([A-Z]\)/\1 \2/g')
        if [ "$spaced" != "$stripped" ] && [[ "$spaced" =~ [[:space:]] ]]; then
            PRODUCT_SPACED="$spaced"
        fi
    fi
}

# --- Main loop ---
# Short-circuit if sourced (allows test files to use helpers without running main)
[ "${BASH_SOURCE[0]:-$0}" != "$0" ] && return 0 2>/dev/null

files=(services_*.txt)
[ ${#files[@]} -eq 0 ] && { echo "No services_*.txt in CWD" >&2; exit 1; }

command -v searchsploit >/dev/null || { echo "searchsploit not in PATH" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq not in PATH (apt install jq)" >&2; exit 1; }
command -v dpkg >/dev/null || { echo "dpkg not in PATH" >&2; exit 1; }

for f in "${files[@]}"; do
    ip=$(echo "$f" | grep -oP '\d+\.\d+\.\d+\.\d+')
    out="searchsploit_${ip}.txt"
    : > "$out"
    {
        echo "=== HOST: $ip ==="
        echo "Generated: $(date)"
    } >> "$out"

    # Read each candidate row
    while IFS= read -r line; do
        port=$(echo "$line" | cut -d/ -f1)
        service=$(echo "$line" | cut -d/ -f4)
        version_field=$(echo "$line" | cut -d/ -f5-)

        parse_field5 "$version_field"

        {
            echo
            echo "--- [${port}/${service}] ${version_field} ---"
            echo "  Product:           ${PRODUCT}"
            [ -n "$PRODUCT_STRIPPED" ] && echo "  Product (stripped):${PRODUCT_STRIPPED}"
            [ -n "$PRODUCT_SPACED" ] && echo "  Product (spaced):  ${PRODUCT_SPACED}"
            echo "  Version (full):    ${VFULL:-<none>}"
            echo "  Version (strict):  ${VSTRICT:-<none>}"
            if is_generic_product "$PRODUCT"; then
                echo "  ! Generic product (\"${PRODUCT}\"): Lookup B skipped — field is OS-keyed (e.g. nmap's '7 - 10' range for SMB), not a service-version. OS-keyed exploits route through Lookup C / per-service workflow."
            else
                [ "$INNER_PRODUCT" = "1" ] && echo "  ! Field 5 contains parenthesised inner product. Script does NOT handle. Run inner ladder manually."
                [ -z "$VFULL" ] && echo "  ! Awaiting version: no version present. Version-specific queries skipped. Re-fire required when version surfaces."
                [ -n "$VFULL" ] && [[ ! "$VFULL" =~ \. ]] && echo "  ! Partial version: only major detected (\"${VFULL}\"). Title constraints requiring minor/patch will tag MATCH=? (ambiguous). Re-fire required when minor/patch surfaces."
            fi
        } >> "$out"

        # Skip Lookup B entirely if primary PRODUCT is generic — see is_generic_product
        if is_generic_product "$PRODUCT"; then
            continue
        fi

        # Build query list
        queries=()
        # Full product
        [ -n "$VFULL" ] && queries+=("$PRODUCT $VFULL")
        [ -n "$VSTRICT" ] && [ "$VSTRICT" != "$VFULL" ] && queries+=("$PRODUCT $VSTRICT")
        queries+=("$PRODUCT")
        # Daemon-stripped (also gate on stripped genericness — strip can yield "Microsoft Windows" from "Microsoft Windows Server")
        if [ -n "$PRODUCT_STRIPPED" ] && ! is_generic_product "$PRODUCT_STRIPPED"; then
            [ -n "$VFULL" ] && queries+=("$PRODUCT_STRIPPED $VFULL")
            [ -n "$VSTRICT" ] && [ "$VSTRICT" != "$VFULL" ] && queries+=("$PRODUCT_STRIPPED $VSTRICT")
            queries+=("$PRODUCT_STRIPPED")
        fi
        # CamelCase-spaced (only if differs from stripped)
        if [ -n "$PRODUCT_SPACED" ] && ! is_generic_product "$PRODUCT_SPACED"; then
            [ -n "$VFULL" ] && queries+=("$PRODUCT_SPACED $VFULL")
            queries+=("$PRODUCT_SPACED")
        fi

        echo "  Queries:" >> "$out"
        for q in "${queries[@]}"; do echo "    searchsploit $q" >> "$out"; done

        # Run + dedupe
        declare -A seen=()
        results=()
        for q in "${queries[@]}"; do
            json=$(searchsploit -j --title $q 2>/dev/null) || json=""
            [ -z "$json" ] && continue
            while IFS=$'\t' read -r path title; do
                [ -z "$path" ] && continue
                if [ -z "${seen[$path]+x}" ]; then
                    seen[$path]=1
                    results+=("${path}"$'\t'"${title}")
                fi
            done < <(echo "$json" | jq -r '.RESULTS_EXPLOIT[]? | "\(.Path)\t\(.Title)"' 2>/dev/null)
        done

    echo >> "$out"
        if [ ${#results[@]} -eq 0 ]; then
            echo "  No hits across ${#queries[@]} queries." >> "$out"
        else
            sortable=()
            hidden_no=0
            dropped_dos=0
            hidden_awaiting=0
            dropped_offproduct=0
            for r in "${results[@]}"; do
                path="${r%%$'\t'*}"
                title="${r#*$'\t'}"
                path="${path#/usr/share/exploitdb/exploits}"
                # Drop categorically-irrelevant paths
                if [[ "$path" =~ /dos/ ]]; then
                    dropped_dos=$((dropped_dos + 1)); continue
                fi

                # Drop hits where title doesn't contain any product variant as whole word
                if ! title_contains_product "$title"; then
                    dropped_offproduct=$((dropped_offproduct + 1)); continue
                fi

                bucket=$(bucket_for "$path" "$title")

                constraint=$(parse_constraint "$title")
                match=$(match_constraint "$constraint" "$VFULL")

                # Hide awaiting-version ? rows (no target version = no constraint check possible = pure speculation)
                if [ -z "$VFULL" ] && [ "$match" = "?" ]; then
                    hidden_awaiting=$((hidden_awaiting + 1)); continue
                fi
                # Hide deterministic NOs (prefix-aware ambiguity check ensures NO == genuinely impossible)
                if [ "$match" = "NO" ]; then
                    hidden_no=$((hidden_no + 1)); continue
                fi

                short_title="${title:0:95}"

                case "$bucket" in foothold) bk=1 ;; manual) bk=2 ;; local) bk=3 ;; shellcode) bk=4 ;; weak) bk=5 ;; *) bk=9 ;; esac

                case "$match" in YES) mk=1 ;; "?") mk=2 ;; NO) mk=3 ;; *) mk=9 ;; esac
                row=$(printf "  %-9s %-7s %-18s %-95s %s" "$bucket" "$match" "${constraint:-?}" "$short_title" "$path")
                sortable+=("${bk}${mk}${row}")
            done
            if [ ${#sortable[@]} -eq 0 ]; then
                echo "  No surviving rows after filters (see counts below)." >> "$out"
            else
                printf "  %-9s %-7s %-18s %-95s %s\n" "BUCKET" "MATCH" "CONSTRAINT" "TITLE" "PATH" >> "$out"
                printf "  %-9s %-7s %-18s %-95s %s\n" "------" "-----" "----------" "-----" "----" >> "$out"
                printf "%s\n" "${sortable[@]}" | sort | sed 's/^..//' >> "$out"
            fi

            [ "$hidden_awaiting" -gt 0 ] && echo "  (${hidden_awaiting} awaiting-version row(s) hidden — speculative without target version; re-fire when version surfaces)" >> "$out"
            [ "$hidden_no" -gt 0 ] && echo "  (${hidden_no} MATCH=NO row(s) hidden — version-mismatched; ambiguous cases are tagged MATCH=?)" >> "$out"

            [ "$dropped_dos" -gt 0 ] && echo "  (${dropped_dos} /dos/ row(s) dropped — DoS prohibited)" >> "$out"

            [ "$dropped_offproduct" -gt 0 ] && echo "  (${dropped_offproduct} row(s) dropped — title did not contain product as whole word, likely cross-product false positive)" >> "$out"
        fi

        unset seen
        queries=()
        results=()
    done < <(awk -F/ '($2=="open" || $2=="open|filtered") && $4!="-" && $5!="-"' "$f")

    echo "=== ${out} (${ip}) ==="
    cat "$out"
done
