#!/usr/bin/env bash
# Automated recon for a program.
#
#   recon.sh <program>            subdomains -> DNS -> HTTP probing
#   recon.sh <program> --passive  subdomains only, sends nothing to the target
#
# Each run gets its own folder:  programs/<name>/recon/<date_time>/
# recon/latest always points to the newest finished run, and every run is
# compared with the previous one, so you can see what's NEW.

set -euo pipefail
source "$(dirname "$(readlink -f "$0")")/lib/common.sh"
export LC_ALL=C  # same sort order everywhere, so comm/diff work

usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") <program> [--passive]

  --passive   only collect subdomains from public sources (no traffic to the target)
EOF
    exit 1
}

passive=0
args=()
for a in "$@"; do
    case "$a" in
        --passive) passive=1 ;;
        -h|--help) usage ;;
        -*) die "Unknown option: $a" ;;
        *) args+=("$a") ;;
    esac
done
((${#args[@]} == 1)) || usage

dir="$(program_dir "${args[0]}")"
in_scope="$dir/scope/in-scope.txt"
out_scope="$dir/scope/out-of-scope.txt"

# ---------------------------------------------------------------------------
# Program settings
# ---------------------------------------------------------------------------
[[ -f "$dir/program.conf" ]] || die "Missing $dir/program.conf"
# shellcheck source=/dev/null
source "$dir/program.conf"
RATE_LIMIT="${RATE_LIMIT:-5}"
[[ "$RATE_LIMIT" =~ ^[1-9][0-9]*$ ]] || die "RATE_LIMIT in program.conf must be a positive number"

# Scope rules without comments/blank lines/schemes, lowercase.
rules() {
    sed -E 's/#.*//; s#^[[:space:]]*[A-Za-z][A-Za-z0-9+.-]*://##; s/[[:space:]]+//g' "$1" \
        | tr '[:upper:]' '[:lower:]' | grep . || true
}

[[ -n "$(rules "$in_scope")" ]] \
    || die "No rules in $in_scope. Fill it from the policy page (or run: import-scope.sh $(basename "$dir"))"

# The filter only understands hosts: "vimeo.com/api" would allow all of vimeo.com.
while read -r r; do
    warn "Path-scoped rule is treated as the WHOLE host: $r (fix scope/in-scope.txt)"
done < <(rules "$in_scope" | grep -E '^[^/]+/.+' || true)

require_tools subfinder jq
((passive)) || require_tools dnsx httpx

# ---------------------------------------------------------------------------
# Run folder
# ---------------------------------------------------------------------------
prev=""
[[ -d "$dir/recon/latest" ]] && prev="$(readlink -f "$dir/recon/latest")"
run="$dir/recon/$(date +%F_%H%M%S)"
mkdir -p "$run"/{subdomains,dns,http}
exec 2> >(tee -a "$run/recon.log" >&2)   # keep a copy of all messages
trap 'warn "Run failed. Partial results and log in $run"' ERR

info "Program: ${PROGRAM_NAME:-$(basename "$dir")}"
info "Mode: $( ((passive)) && echo passive || echo full ) | rate limit: $RATE_LIMIT req/s"
info "Output: $run"

# ---------------------------------------------------------------------------
# [1/3] Subdomains (passive)
# ---------------------------------------------------------------------------
# WHY: you can't test what you don't know exists. subfinder asks public
# sources (certificate logs, DNS datasets, search engines) - it sends
# nothing to the target itself.
info "[1/3] Subdomains"

# "*.vimeo.com" -> search subdomains of "vimeo.com"
rules "$in_scope" | grep '^\*\.' | sed 's/^\*\.//' | sort -u > "$run/subdomains/roots.txt" || true
# Exact hosts from the scope are targets too, even if no source lists them.
rules "$in_scope" | grep -v '^\*' > "$run/subdomains/scope-hosts.txt" || true

if [[ -s "$run/subdomains/roots.txt" ]]; then
    subfinder -dL "$run/subdomains/roots.txt" -all -silent > "$run/subdomains/subfinder.txt" \
        || warn "subfinder failed, continuing with what it found"
else
    info "No wildcards in scope, skipping subfinder"
    : > "$run/subdomains/subfinder.txt"
fi

# WHY the filter: sources return lots of out-of-scope names. Testing those
# can get you banned, so nothing passes this point without matching scope.
cat "$run/subdomains/subfinder.txt" "$run/subdomains/scope-hosts.txt" \
    | scope_filter "$in_scope" "$out_scope" | sort -u > "$run/subdomains/all.txt"

n_raw=$(sort -u "$run/subdomains/subfinder.txt" | wc -l)
n_subs=$(wc -l < "$run/subdomains/all.txt")
ok "Subdomains: $n_raw from sources, $n_subs in scope (incl. hosts listed in scope)"

# ---------------------------------------------------------------------------
# [2/3] DNS resolution
# ---------------------------------------------------------------------------
# WHY: many names from old certificates/datasets no longer exist. Resolving
# them removes dead ones. dnsx asks public DNS resolvers, not the target.
# CNAMEs are kept: a CNAME pointing to a deleted cloud resource can mean a
# subdomain takeover.
n_dns=0
if ((!passive)) && [[ -s "$run/subdomains/all.txt" ]]; then
    info "[2/3] DNS resolution"
    dnsx -l "$run/subdomains/all.txt" -silent -a -cname -resp -json -o "$run/dns/dnsx.json" > /dev/null
    jq -r 'select((.a // []) + (.cname // []) | length > 0) | .host' "$run/dns/dnsx.json" \
        | sort -u > "$run/dns/resolved.txt"
    jq -r 'select(.cname) | "\(.host) -> \(.cname | join(", "))"' "$run/dns/dnsx.json" \
        | sort -u > "$run/dns/cnames.txt"
    n_dns=$(wc -l < "$run/dns/resolved.txt")
    ok "Resolving: $n_dns ($(wc -l < "$run/dns/cnames.txt") with CNAME)"
fi

# ---------------------------------------------------------------------------
# [3/3] HTTP probing
# ---------------------------------------------------------------------------
# WHY: a resolving name isn't necessarily a website. httpx finds which hosts
# answer on HTTP(S) and grabs status, title and technologies, so you can
# pick what to look at first. This is the first step that talks to the
# target, so it respects RATE_LIMIT and the required headers.
n_live=0
if ((!passive)) && [[ -s "${run}/dns/resolved.txt" ]]; then
    info "[3/3] HTTP probing"
    hx=(httpx -l "$run/dns/resolved.txt" -silent -no-color -json -o "$run/http/httpx.json"
        -rl "$RATE_LIMIT" -t 10 -sc -title -td -server -cl -location)
    [[ -n "${CUSTOM_HEADER:-}" ]] && hx+=(-H "$CUSTOM_HEADER")
    [[ -n "${USER_AGENT:-}" ]] && hx+=(-H "User-Agent: $USER_AGENT")
    "${hx[@]}" > /dev/null

    jq -r '.url' "$run/http/httpx.json" | sort -u > "$run/http/live.txt"
    # Human-readable list: status  url  [title]  [tech]
    jq -r '"\(.status_code)\t\(.url)\t[\(.title // "")]\t[\((.tech // []) | join(", "))]"' \
        "$run/http/httpx.json" | sort -t$'\t' -k2 > "$run/http/live-details.txt"
    n_live=$(wc -l < "$run/http/live.txt")
    ok "Live web hosts: $n_live"
fi

# ---------------------------------------------------------------------------
# What's new since the last run
# ---------------------------------------------------------------------------
# WHY: new subdomains and new sites are the least-tested part of a program.
# Compares with the newest earlier run that HAS the file, so a --passive run
# (no HTTP results) doesn't hide new live hosts on the next full run.
new_since() {  # new_since <relative file>  -> lines in this run but not before
    local cur="$run/$1" old="" runs d i
    [[ -f "$cur" ]] || return 0
    runs=("$dir"/recon/20*/)
    for ((i = ${#runs[@]} - 1; i >= 0; i--)); do
        d="${runs[i]%/}"
        [[ "$d" != "$run" && -f "$d/$1" ]] && { old="$d/$1"; break; }
    done
    [[ -n "$old" ]] && comm -13 "$old" "$cur"
    return 0
}
new_since subdomains/all.txt > "$run/subdomains/new.txt"
new_since http/live.txt > "$run/http/new.txt"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
{
    echo "# Recon summary: ${PROGRAM_NAME:-$(basename "$dir")}"
    echo
    echo "- Run: $(basename "$run") ($( ((passive)) && echo passive || echo full ))"
    echo "- Previous run: $([[ -n "$prev" ]] && basename "$prev" || echo none)"
    echo
    echo "| Stage | Count |"
    echo "|---|---|"
    echo "| Subdomains from sources | $n_raw |"
    echo "| In scope (+ hosts listed in scope) | $n_subs |"
    ((passive)) || echo "| Resolving | $n_dns |"
    ((passive)) || echo "| Live web hosts | $n_live |"
    echo
    if [[ -n "$prev" ]]; then
        echo "## New since last run"
        echo
        echo "### Subdomains ($(wc -l < "$run/subdomains/new.txt"))"
        sed 's/^/- /' "$run/subdomains/new.txt"
        echo
        echo "### Live web hosts ($(wc -l < "$run/http/new.txt"))"
        sed 's/^/- /' "$run/http/new.txt"
        echo
    fi
    if [[ -s "$run/http/httpx.json" ]]; then
        echo "## Technologies"
        echo
        jq -r '.tech[]?' "$run/http/httpx.json" | sort | uniq -c | sort -rn | head -25 \
            | awk '{c=$1; $1=""; sub(/^ /,""); printf "- %s (%d)\n", $0, c}'
        echo
        echo "## Live web hosts"
        echo
        echo "| Status | URL | Title | Tech |"
        echo "|---|---|---|---|"
        jq -r '[.status_code, .url, (.title // ""), ((.tech // []) | join(", "))]
               | map(tostring | gsub("\\|"; "/")) | "| " + join(" | ") + " |"' \
            "$run/http/httpx.json" | sort -t'|' -k3
        echo
    fi
    if [[ -s "$run/dns/cnames.txt" ]]; then
        echo "## CNAMEs (check for subdomain takeover)"
        echo
        sed 's/^/- /' "$run/dns/cnames.txt"
    fi
} > "$run/summary.md"

ln -sfn "$(basename "$run")" "$dir/recon/latest"
trap - ERR
ok "Done. Summary: $dir/recon/latest/summary.md"
