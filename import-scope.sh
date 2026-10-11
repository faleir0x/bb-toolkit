#!/usr/bin/env bash
# Fill a program's scope files from HackerOne's public scope data.
#
#   import-scope.sh <program> [hackerone-handle] [--force]
#   import-scope.sh vimeo          handle defaults to the program name
#
# The handle is the last part of the program URL: hackerone.com/<handle>
#
# Data: github.com/arkadiyt/bounty-targets-data (refreshed several times a day).
# It's a shortcut, not the source of truth: ALWAYS compare the result with
# the program's policy page before running recon.

set -euo pipefail
source "$(dirname "$(readlink -f "$0")")/lib/common.sh"

DATA_URL="https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/bb-toolkit/hackerone_data.json"

usage() {
    echo "Usage: $(basename "$0") <program> [hackerone-handle] [--force]" >&2
    exit 1
}

force=0
args=()
for a in "$@"; do
    case "$a" in
        --force) force=1 ;;
        -h|--help) usage ;;
        -*) die "Unknown option: $a" ;;
        *) args+=("$a") ;;
    esac
done
((${#args[@]} >= 1 && ${#args[@]} <= 2)) || usage

dir="$(program_dir "${args[0]}")"
handle="${args[1]:-$(basename "$dir")}"
[[ "$handle" =~ ^[A-Za-z0-9_-]+$ ]] || die "Invalid handle: $handle"
in_scope="$dir/scope/in-scope.txt"
out_scope="$dir/scope/out-of-scope.txt"

require_tools curl jq

# Don't overwrite scope you may have edited by hand.
has_rules() { [[ -f "$1" ]] && sed 's/#.*//' "$1" | grep -q '[^[:space:]]'; }
if ((!force)) && { has_rules "$in_scope" || has_rules "$out_scope"; }; then
    die "Scope files already have rules. Use --force to replace them."
fi

# ---------------------------------------------------------------------------
# Download (cached for 12 hours)
# ---------------------------------------------------------------------------
if [[ ! -s "$CACHE" || -n "$(find "$CACHE" -mmin +720 2>/dev/null)" ]]; then
    info "Downloading HackerOne scope data..."
    mkdir -p "$(dirname "$CACHE")"
    curl -fsSL -o "$CACHE.tmp" "$DATA_URL" || die "Download failed"
    mv "$CACHE.tmp" "$CACHE"
fi

program="$(jq -c --arg h "$handle" '.[] | select(.handle == $h)' "$CACHE")"
[[ -n "$program" ]] || die "No HackerOne program '$handle'. Check hackerone.com/<handle> and pass it: $(basename "$0") ${args[0]} <handle>"

# ---------------------------------------------------------------------------
# Convert
# ---------------------------------------------------------------------------
# Prints "<bounty 1/0>\t<entry>\t<instruction>" for web assets. Some entries
# hold several hosts separated by commas ("magisto.com,www.magisto.com").
# The instruction is the program's free-text note on that asset. It often
# holds exceptions ("EXCEPT community.vhx.tv", "report on the X program"),
# so it's copied as a comment above the rule: read those before testing.
web_assets() {  # web_assets in_scope|out_of_scope
    jq -r --arg k "$1" '.targets[$k][]
        | select(.asset_type == "URL" or .asset_type == "WILDCARD")
        | (if .eligible_for_bounty then 1 else 0 end) as $b
        | ((.instruction // "") | gsub("\\s+"; " ") | gsub("^ | $"; "")
           | if length > 300 then .[:300] + "..." else . end) as $note
        | .asset_identifier | split(",")[] | gsub("^\\s+|\\s+$"; "")
        | select(length > 0) | "\($b)\t\(.)\t\($note)"' <<< "$program"
}
other_assets() {  # mobile apps, source code, etc. - listed for reference only
    jq -r --arg k "$1" '.targets[$k][]
        | select(.asset_type != "URL" and .asset_type != "WILDCARD")
        | "\(.asset_type): \(.asset_identifier | gsub("\\s+"; " "))"' <<< "$program"
}

# The scope filter only understands hosts, so entries limited to a path
# ("vimeo.com/api") or with odd wildcards ("*test*.x.com") are written as
# comments: you handle those by hand.
skipped=0
convert() {  # convert in_scope|out_of_scope  -> scope lines on stdout
    local b raw note e
    while IFS=$'\t' read -r b raw note; do
        [[ -n "$note" ]] && echo "# NOTE: $note"
        e="$(tr '[:upper:]' '[:lower:]' <<< "$raw")"
        e="${e#*://}"; e="${e%/\*}"; e="${e%/}"
        if [[ "$e" == */* ]]; then
            echo "# PATH-SCOPED (only this path, test by hand): $raw"; ((skipped++)) || true
        elif [[ "${e#\*.}" == *\** ]]; then
            echo "# CHECK MANUALLY (unusual wildcard): $raw"; ((skipped++)) || true
        elif [[ "$1" == in_scope && "$b" == 0 ]]; then
            echo "$e  # no bounty"
        else
            echo "$e"
        fi
    done < <(web_assets "$1")
    while read -r line; do
        [[ -n "$line" ]] && echo "# Not web (reference only) - $line"
    done < <(other_assets "$1")
}

header() {  # header <title>
    cat <<EOF
# $1 - imported from HackerOne public data on $(date +%F)
# Source: https://hackerone.com/$handle  <- VERIFY against the policy page
#
# Syntax: *.example.com = subdomains only, example.com = exact host.
# Commented "PATH-SCOPED" / "CHECK MANUALLY" lines are ignored by the scope
# filter on purpose: handle them by hand, within their limits.
# "NOTE" lines are the program's own instructions for the rule below them.
# They often contain exceptions: read them, and move hosts to
# out-of-scope.txt when a note excludes them.

EOF
}

{ header "In-scope assets"; convert in_scope; } > "$in_scope"
{ header "Out-of-scope assets (these always win)"; convert out_of_scope; } > "$out_scope"

# Fill platform/URL in program.conf if still empty.
sed -i -E "s|^PLATFORM=\"\"|PLATFORM=\"hackerone\"|; s|^PROGRAM_URL=\"\"|PROGRAM_URL=\"https://hackerone.com/$handle\"|" \
    "$dir/program.conf"

count() { sed 's/#.*//' "$1" | grep -c '[^[:space:]]' || true; }
ok "In scope: $(count "$in_scope") rules | Out of scope: $(count "$out_scope") rules | Skipped for manual handling: $skipped"
warn "Now compare scope/ with https://hackerone.com/$handle before running recon."
