#!/usr/bin/env bash
# Automated recon for a program.
#
#   recon.sh <program>            subdomains -> DNS -> HTTP probing
#   recon.sh <program> --passive  subdomains only, sends nothing to the target
#   recon.sh <program> --resume   continue the last unfinished run
#
# Each run gets its own folder:  programs/<name>/recon/<date_time>/
# recon/latest always points to the newest finished run, and every run is
# compared with the previous one, so you can see what's NEW.

set -Eeuo pipefail
source "$(dirname "$(readlink -f "$0")")/lib/common.sh"
export LC_ALL=C  # same sort order everywhere, so comm/diff work

usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") <program> [--passive] [--resume]

  --passive   only collect subdomains from public sources (no traffic to the target)
  --resume    continue the last unfinished run (after Ctrl+C or an error)
EOF
    exit 1
}

passive=0 resume=0
args=()
for a in "$@"; do
    case "$a" in
        --passive) passive=1 ;;
        --resume) resume=1 ;;
        -h|--help) usage ;;
        -*) die "Unknown option: $a" ;;
        *) args+=("$a") ;;
    esac
done
((${#args[@]} == 1)) || usage

dir="$(program_dir "${args[0]}")"
name="$(basename "$dir")"
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
    || die "No rules in $in_scope. Fill it from the policy page (or run: import-scope.sh $name)"

# The filter only understands hosts: "vimeo.com/api" would allow all of vimeo.com.
while read -r r; do
    warn "Path-scoped rule is treated as the WHOLE host: $r (fix scope/in-scope.txt)"
done < <(rules "$in_scope" | grep -E '^[^/]+/.+' || true)

# ---------------------------------------------------------------------------
# Run folder (new, or the last unfinished one with --resume)
# ---------------------------------------------------------------------------
# A run is "finished" when it has summary.md. Each stage writes a .done-*
# marker when it completes, so --resume skips the stages already done.
finished_runs() {  # newest last
    local d
    for d in "$dir"/recon/20*/; do
        [[ -f "$d/summary.md" ]] && echo "${d%/}"
    done
    return 0
}

prev="$(finished_runs | tail -1)"

if ((resume)); then
    runs=("$dir"/recon/20*/)
    [[ -d "${runs[-1]:-}" ]] || die "No run to resume"
    run="${runs[-1]%/}"
    [[ ! -f "$run/summary.md" ]] || die "The last run already finished. Start a new one: recon.sh $name"
    # Keep the mode the run was started with.
    [[ "$(cat "$run/.mode" 2>/dev/null || true)" == passive ]] && passive=1 || passive=0
else
    run="$dir/recon/$(date +%F_%H%M%S)"
fi
mkdir -p "$run"/{subdomains,dns,http}
echo "$( ((passive)) && echo passive || echo full )" > "$run/.mode"

done_stage() { [[ -f "$run/.done-$1" ]]; }
mark_done() { touch "$run/.done-$1"; }

require_tools subfinder jq
((passive)) || require_tools dnsx httpx

exec 2> >(tee -a "$run/recon.log" >&2)   # keep a copy of all messages

# Ctrl+C or an error: say where the partial results are and how to continue.
stopped() {
    trap - ERR INT TERM
    echo >&2
    warn "Stopped. Partial results in $run"
    warn "Continue with: recon.sh $name --resume"
    exit 130
}
failed() {
    local rc=$1
    ((rc == 130)) && stopped   # a tool killed by Ctrl+C
    trap - ERR INT TERM
    warn "Run failed (exit $rc). Log: $run/recon.log"
    warn "Fix the problem, then continue with: recon.sh $name --resume"
    exit "$rc"
}
trap stopped INT TERM
trap 'failed $?' ERR

info "Program: ${PROGRAM_NAME:-$name}"
info "Mode: $(cat "$run/.mode") | rate limit: $RATE_LIMIT req/s$( ((resume)) && echo " | resuming")"
info "Output: $run"

# ---------------------------------------------------------------------------
# [1/3] Subdomains (passive)
# ---------------------------------------------------------------------------
# WHY: you can't test what you don't know exists. subfinder asks public
# sources (certificate logs, DNS datasets, search engines) - it sends
# nothing to the target itself.
if done_stage subdomains; then
    info "[1/3] Subdomains: already done, skipping"
else
    info "[1/3] Subdomains (public sources, can take several minutes)"

    # "*.vimeo.com" -> search subdomains of "vimeo.com"
    rules "$in_scope" | grep '^\*\.' | sed 's/^\*\.//' | sort -u > "$run/subdomains/roots.txt" || true
    # Exact hosts from the scope are targets too, even if no source lists them.
    rules "$in_scope" | grep -v '^\*' | sort -u > "$run/subdomains/scope-hosts.txt" || true

    if [[ -s "$run/subdomains/roots.txt" ]]; then
        subfinder -dL "$run/subdomains/roots.txt" -all -silent < /dev/null > "$run/subdomains/subfinder.txt" \
            || warn "subfinder failed, continuing with what it found"
    else
        info "No wildcards in scope, skipping subfinder"
        : > "$run/subdomains/subfinder.txt"
    fi

    # WHY the filter: sources return lots of out-of-scope names. Testing those
    # can get you banned, so nothing passes this point without matching scope.
    cat "$run/subdomains/subfinder.txt" "$run/subdomains/scope-hosts.txt" \
        | scope_filter "$in_scope" "$out_scope" | sort -u > "$run/subdomains/all.txt"
    mark_done subdomains
fi
n_raw=$(sort -u "$run/subdomains/subfinder.txt" | wc -l)
n_subs=$(wc -l < "$run/subdomains/all.txt")
ok "Subdomains: $n_raw from sources, $n_subs in scope (incl. hosts listed in scope)"

# ---------------------------------------------------------------------------
# [2/3] DNS resolution + wildcard filtering
# ---------------------------------------------------------------------------
# WHY: many names from old certificates/datasets no longer exist. Resolving
# them removes dead ones. dnsx asks public DNS resolvers, not the target.
# CNAMEs are kept: a CNAME pointing to a deleted cloud resource can mean a
# subdomain takeover.
#
# WILDCARD DNS: some domains answer for ANY name (*.vhx.tv resolves
# "anything-you-want.vhx.tv"). Then every junk name from the sources looks
# alive. To detect it, we resolve a few random names per root: if they
# resolve, hosts that get exactly those same answers are dropped as noise.
# They go to dns/wildcard-dropped.txt (some may still be real tenant sites,
# like VHX customer sites - check the program notes before ignoring them).
# Hosts listed explicitly in scope are never dropped.
n_dns=0 n_wild=0
if ((!passive)) && [[ -s "$run/subdomains/all.txt" ]]; then
    if done_stage dns; then
        info "[2/3] DNS: already done, skipping"
    else
        info "[2/3] DNS resolution"
        dnsx -l "$run/subdomains/all.txt" -silent -a -cname -resp -json -o "$run/dns/dnsx.json" < /dev/null > /dev/null

        # Random names per root -> what does the wildcard answer?
        while read -r root; do
            for _ in 1 2 3 4 5; do echo "bbtk${RANDOM}${RANDOM}x.$root"; done
        done < "$run/subdomains/roots.txt" > "$run/dns/wildcard-probes.txt"
        : > "$run/dns/wildcard-probes.json"
        if [[ -s "$run/dns/wildcard-probes.txt" ]]; then
            dnsx -l "$run/dns/wildcard-probes.txt" -silent -a -cname -resp -json \
                -o "$run/dns/wildcard-probes.json" < /dev/null > /dev/null
        fi
        # {"vhx.tv": ["104.18.36.21", ...]} for roots that have a wildcard
        jq -s 'map({root: (.host | sub("^[^.]+\\."; "")),
                    ans: ((.a // []) + (.cname // []))})
               | group_by(.root)
               | map({key: .[0].root, value: (map(.ans[]) | unique)})
               | map(select(.value | length > 0)) | from_entries' \
            "$run/dns/wildcard-probes.json" > "$run/dns/wildcard.json"

        # R = real host, W = only gets the wildcard's answers
        jq -r --slurpfile w "$run/dns/wildcard.json" '
            ((.a // []) + (.cname // [])) as $ans | select($ans | length > 0)
            | .host as $h
            | [$w[0] | to_entries[] | .key as $root | select($h | endswith("." + $root)) | .value] as $sets
            | if any($sets[]; ($ans - .) | length == 0) then "W\t\($h)" else "R\t\($h)" end' \
            "$run/dns/dnsx.json" > "$run/dns/classified.tsv"

        { grep '^R' "$run/dns/classified.tsv" | cut -f2
          grep '^W' "$run/dns/classified.tsv" | cut -f2 | grep -Fxf "$run/subdomains/scope-hosts.txt"
        } | sort -u > "$run/dns/resolved.txt" || true
        grep '^W' "$run/dns/classified.tsv" | cut -f2 | sort -u \
            | comm -23 - "$run/dns/resolved.txt" > "$run/dns/wildcard-dropped.txt" || true

        jq -r 'select(.cname) | "\(.host)\t\(.cname | join(", "))"' "$run/dns/dnsx.json" | sort -u \
            | join -t$'\t' "$run/dns/resolved.txt" - | sed 's/\t/ -> /' > "$run/dns/cnames.txt" || true
        # Human-readable list of real hosts: host  [IPs]  [CNAME]
        jq -r '"\(.host)\t[\((.a // []) | join(", "))]\t[\((.cname // []) | join(", "))]"' \
            "$run/dns/dnsx.json" | sort -u | join -t$'\t' "$run/dns/resolved.txt" - \
            > "$run/dns/dns-details.txt" || true
        mark_done dns
    fi
    while read -r root; do
        warn "Wildcard DNS on *.$root: names that only get its answers are dropped"
    done < <(jq -r 'keys[]' "$run/dns/wildcard.json")
    n_dns=$(wc -l < "$run/dns/resolved.txt")
    n_wild=$(wc -l < "$run/dns/wildcard-dropped.txt")
    ok "Resolving: $n_dns real, $n_wild dropped as wildcard, $(wc -l < "$run/dns/cnames.txt") with CNAME"
fi

# ---------------------------------------------------------------------------
# [3/3] HTTP probing
# ---------------------------------------------------------------------------
# WHY: a resolving name isn't necessarily a website. httpx finds which hosts
# answer on HTTP(S) and grabs status, title and technologies, so you can
# pick what to look at first. This is the first step that talks to the
# target, so it respects RATE_LIMIT and the required headers.
n_live=0
if ((!passive)) && [[ -s "$run/dns/resolved.txt" ]]; then
    if done_stage http; then
        info "[3/3] HTTP probing: already done, skipping"
    else
        # Results from an interrupted attempt are kept; only probe what's left.
        touch "$run/http/httpx.json"
        if [[ -f "$run/http/httpx.part.json" ]]; then
            cat "$run/http/httpx.part.json" >> "$run/http/httpx.json"
            rm "$run/http/httpx.part.json"
        fi
        jq -r '.input' "$run/http/httpx.json" | sort -u \
            | comm -13 - "$run/dns/resolved.txt" > "$run/http/todo.txt"
        n_todo=$(wc -l < "$run/http/todo.txt")
        n_already=$(( $(wc -l < "$run/dns/resolved.txt") - n_todo ))

        if ((n_todo > 0)); then
            eta=$(( (n_todo + RATE_LIMIT * 60 - 1) / (RATE_LIMIT * 60) ))
            info "[3/3] HTTP probing: $n_todo hosts$( ((n_already)) && echo " ($n_already already done)") - at least ~$eta min at $RATE_LIMIT req/s"
            hx=(httpx -l "$run/http/todo.txt" -silent -no-color -json -o "$run/http/httpx.part.json"
                -rl "$RATE_LIMIT" -t 10 -sc -title -td -server -cl -location)
            [[ -n "${CUSTOM_HEADER:-}" ]] && hx+=(-H "$CUSTOM_HEADER")
            [[ -n "${USER_AGENT:-}" ]] && hx+=(-H "User-Agent: $USER_AGENT")
            [[ -t 1 ]] && hx+=(-stats -si 30)   # progress line every 30s
            # Run inside http/: when interrupted, httpx drops a resume.cfg in
            # the current folder. We resume our own way, so it's just litter.
            (cd "$run/http" && "${hx[@]}" < /dev/null > /dev/null)
            rm -f "$run/http/resume.cfg"
            cat "$run/http/httpx.part.json" >> "$run/http/httpx.json"
            rm "$run/http/httpx.part.json"
        else
            info "[3/3] HTTP probing: all $n_already hosts already done"
        fi
        rm -f "$run/http/todo.txt"

        jq -r '.url' "$run/http/httpx.json" | sort -u > "$run/http/live.txt"
        # Human-readable list: status  url  [title]  [tech]
        jq -r '"\(.status_code)\t\(.url)\t[\(.title // "")]\t[\((.tech // []) | join(", "))]"' \
            "$run/http/httpx.json" | sort -t$'\t' -k2 > "$run/http/live-details.txt"
        mark_done http
    fi
    n_live=$(wc -l < "$run/http/live.txt")
    ok "Live web hosts: $n_live"
fi

# ---------------------------------------------------------------------------
# What's new since the last run
# ---------------------------------------------------------------------------
# WHY: new subdomains and new sites are the least-tested part of a program.
# Compares with the newest earlier FINISHED run that has the file, so a
# --passive run (no HTTP results) doesn't hide new live hosts later.
new_since() {  # new_since <relative file>  -> lines in this run but not before
    local cur="$run/$1" old="" d
    [[ -f "$cur" ]] || return 0
    while read -r d; do
        [[ "$d" != "$run" && -f "$d/$1" ]] && old="$d/$1"
    done < <(finished_runs)
    [[ -n "$old" ]] && comm -13 "$old" "$cur"
    return 0
}
new_since subdomains/all.txt > "$run/subdomains/new.txt"
new_since http/live.txt > "$run/http/new.txt"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
{
    echo "# Recon summary: ${PROGRAM_NAME:-$name}"
    echo
    echo "- Run: $(basename "$run") ($(cat "$run/.mode"))"
    echo "- Previous run: $([[ -n "$prev" ]] && basename "$prev" || echo none)"
    echo
    echo "| Stage | Count |"
    echo "|---|---|"
    echo "| Subdomains from sources | $n_raw |"
    echo "| In scope (+ hosts listed in scope) | $n_subs |"
    ((passive)) || echo "| Resolving (real) | $n_dns |"
    ((passive)) || echo "| Dropped as wildcard DNS | $n_wild |"
    ((passive)) || echo "| Live web hosts | $n_live |"
    echo
    if [[ -s "$run/dns/wildcard.json" ]] && [[ "$(jq 'length' "$run/dns/wildcard.json")" -gt 0 ]]; then
        echo "## Wildcard DNS"
        echo
        jq -r 'to_entries[] | "- *.\(.key) answers \(.value | join(", ")) for any name"' "$run/dns/wildcard.json"
        echo
        echo "Names that only got those answers are in \`dns/wildcard-dropped.txt\`."
        echo
    fi
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
trap - ERR INT TERM
ok "Done. Summary: $dir/recon/latest/summary.md"
