#!/usr/bin/env bash
# Fill a program's scope files from public scope data (HackerOne, Bugcrowd, Intigriti).
#
#   import-scope.sh <program> [handle] [--platform hackerone|bugcrowd|intigriti] [--force]
#
#   import-scope.sh vimeo                              HackerOne (default)
#   import-scope.sh pexels --platform bugcrowd         bugcrowd.com/engagements/<handle>
#   import-scope.sh tweakers --platform intigriti      intigriti.com/programs/<company>/<handle>/detail
#
# The handle defaults to the program name. The platform defaults to PLATFORM
# in program.conf, or hackerone if that's empty.
# YesWeHack isn't in the dataset: fill scope/ by hand for it.
#
# Data: github.com/arkadiyt/bounty-targets-data (refreshed several times a day).
# It's a shortcut, not the source of truth: ALWAYS compare the result with
# the program's policy page before running recon.

set -euo pipefail
source "$(dirname "$(readlink -f "$0")")/lib/common.sh"

DATA_BASE="https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/bb-toolkit"

usage() {
    echo "Usage: $(basename "$0") <program> [handle] [--platform hackerone|bugcrowd|intigriti] [--force]" >&2
    exit 1
}

force=0 platform=""
args=()
while (($#)); do
    case "$1" in
        --force) force=1 ;;
        --platform) shift; platform="${1:-}" ;;
        --platform=*) platform="${1#*=}" ;;
        -h|--help) usage ;;
        -*) die "Unknown option: $1" ;;
        *) args+=("$1") ;;
    esac
    shift
done
((${#args[@]} >= 1 && ${#args[@]} <= 2)) || usage

dir="$(program_dir "${args[0]}")"
handle="${args[1]:-$(basename "$dir")}"
[[ "$handle" =~ ^[A-Za-z0-9_.-]+$ ]] || die "Invalid handle: $handle"
in_scope="$dir/scope/in-scope.txt"
out_scope="$dir/scope/out-of-scope.txt"

# Platform: --platform, else PLATFORM in program.conf, else hackerone.
if [[ -z "$platform" ]]; then
    platform="$(sed -n 's/^PLATFORM="\([^"]*\)".*/\1/p' "$dir/program.conf" 2>/dev/null)"
fi
platform="$(tr '[:upper:]' '[:lower:]' <<< "${platform:-hackerone}")"
case "$platform" in
    hackerone|bugcrowd|intigriti) ;;
    yeswehack) die "YesWeHack isn't in the public dataset: fill $dir/scope/ by hand" ;;
    *) die "Unknown platform: $platform (hackerone, bugcrowd or intigriti)" ;;
esac

require_tools curl jq

# Don't overwrite scope you may have edited by hand.
has_rules() { [[ -f "$1" ]] && sed 's/#.*//' "$1" | grep -q '[^[:space:]]'; }
if ((!force)) && { has_rules "$in_scope" || has_rules "$out_scope"; }; then
    die "Scope files already have rules. Use --force to replace them."
fi

# ---------------------------------------------------------------------------
# Download (cached for 12 hours, one file per platform)
# ---------------------------------------------------------------------------
cache="$CACHE_DIR/${platform}_data.json"
if [[ ! -s "$cache" || -n "$(find "$cache" -mmin +720 2>/dev/null)" ]]; then
    info "Downloading $platform scope data..."
    mkdir -p "$CACHE_DIR"
    curl -fsSL -o "$cache.tmp" "$DATA_BASE/${platform}_data.json" || die "Download failed"
    mv "$cache.tmp" "$cache"
fi

# ---------------------------------------------------------------------------
# Find the program
# ---------------------------------------------------------------------------
case "$platform" in
    hackerone)
        matches="$(jq -c --arg h "$handle" '[.[] | select(.handle == $h)]' "$cache")" ;;
    bugcrowd)
        # Handle = last part of the URL: bugcrowd.com/engagements/<handle>
        matches="$(jq -c --arg h "$handle" \
            '[.[] | select((.url | rtrimstr("/") | split("/") | last | ascii_downcase) == ($h | ascii_downcase))]' "$cache")" ;;
    intigriti)
        # Program handle first; a company handle only if it has a single program.
        matches="$(jq -c --arg h "$handle" '
            [.[] | select(.handle == $h)] as $p
            | if ($p | length) > 0 then $p else [.[] | select(.company_handle == $h)] end' "$cache")" ;;
esac

n="$(jq 'length' <<< "$matches")"
((n > 0)) || die "No $platform program '$handle'. Pass the handle from its URL: $(basename "$0") ${args[0]} <handle> --platform $platform"
if ((n > 1)); then
    jq -r '.[] | "    \(.handle) (\(.name))"' <<< "$matches" >&2
    die "'$handle' matches several $platform programs, pass one of the handles above"
fi
program="$(jq -c '.[0]' <<< "$matches")"

case "$platform" in
    hackerone) program_url="https://hackerone.com/$handle" ;;
    *) program_url="$(jq -r '.url' <<< "$program")" ;;
esac

# ---------------------------------------------------------------------------
# Convert
# ---------------------------------------------------------------------------
# web_assets prints "<bounty 1/0>\t<entry>\t<note>" for web assets, one per
# entry (some entries hold several hosts separated by commas). The note is
# the program's own text on that asset. It often holds exceptions ("EXCEPT
# community.vhx.tv", "report on the X program"), so it's copied as a comment
# above the rule: read those before testing.
JQ_NOTE='gsub("\\s+"; " ") | gsub("^ | $"; "") | if length > 300 then .[:300] + "..." else . end'
JQ_SPLIT='split(",")[] | gsub("^\\s+|\\s+$"; "") | select(length > 0)'

web_assets() {  # web_assets in_scope|out_of_scope
    case "$platform" in
        hackerone) jq -r --arg k "$1" ".targets[\$k][]
            | select(.asset_type == \"URL\" or .asset_type == \"WILDCARD\")
            | (if .eligible_for_bounty then 1 else 0 end) as \$b
            | ((.instruction // \"\") | $JQ_NOTE) as \$note
            | .asset_identifier | $JQ_SPLIT | \"\(\$b)\t\(.)\t\(\$note)\"" <<< "$program" ;;
        # Bugcrowd has no per-asset bounty flag. Its "name" can differ from the
        # target (target www.pexels.com, name *.pexels.com): kept as a note.
        bugcrowd) jq -r --arg k "$1" ".targets[\$k][]
            | select(.type == \"website\" or .type == \"api\")
            | ((if (.name // \"\") != \"\" and .name != .target then \"Listed as: \" + .name else \"\" end) | $JQ_NOTE) as \$note
            | .target | $JQ_SPLIT | \"1\t\(.)\t\(\$note)\"" <<< "$program" ;;
        intigriti) jq -r --arg k "$1" ".targets[\$k][]
            | select(.type == \"url\" or .type == \"wildcard\")
            | (if .impact == \"No Bounty\" then 0 else 1 end) as \$b
            | (([.impact // empty | select(. != \"Out of scope\")] + [.description // empty] | join(\" - \")) | $JQ_NOTE) as \$note
            | .endpoint | $JQ_SPLIT | \"\(\$b)\t\(.)\t\(\$note)\"" <<< "$program" ;;
    esac
}
other_assets() {  # mobile apps, source code, etc. - listed for reference only
    case "$platform" in
        hackerone) jq -r --arg k "$1" '.targets[$k][]
            | select(.asset_type != "URL" and .asset_type != "WILDCARD")
            | "\(.asset_type): \(.asset_identifier | gsub("\\s+"; " "))"' <<< "$program" ;;
        bugcrowd) jq -r --arg k "$1" '.targets[$k][]
            | select(.type != "website" and .type != "api")
            | "\(.type): \(.target // .name | gsub("\\s+"; " "))"' <<< "$program" ;;
        intigriti) jq -r --arg k "$1" '.targets[$k][]
            | select(.type != "url" and .type != "wildcard")
            | "\(.type // "other"): \(.endpoint // "" | gsub("\\s+"; " "))"' <<< "$program" ;;
    esac
}

# The scope filter only understands hosts, so entries limited to a path
# ("vimeo.com/api"), with odd wildcards ("*test*.x.com" in scope) or that
# aren't hosts at all (sentences, "all") are written as comments: you
# handle those by hand.
skipped=0
convert() {  # convert in_scope|out_of_scope  -> scope lines on stdout
    local b raw note e
    while IFS=$'\t' read -r b raw note; do
        [[ -n "$note" ]] && echo "# NOTE: $note"
        e="$(tr '[:upper:]' '[:lower:]' <<< "$raw")"
        e="${e#*://}"; e="${e%/\*}"; e="${e%/}"
        if [[ "$e" =~ [[:space:]] || "$e" != *.* ]]; then
            echo "# CHECK MANUALLY (not a host): $raw"; ((skipped++)) || true
        elif [[ "$e" == */* ]]; then
            echo "# PATH-SCOPED (only this path, test by hand): $raw"; ((skipped++)) || true
        elif [[ "${e#\*.}" == *\** && "$1" == out_of_scope ]]; then
            # Excluding more is the safe side: keep patterns like *dev*.x.com active.
            echo "$e  # pattern: \"*\" = any characters"
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
# $1 - imported from $platform public data on $(date +%F)
# Source: $program_url  <- VERIFY against the policy page
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
sed -i -E "s|^PLATFORM=\"\"|PLATFORM=\"$platform\"|; s|^PROGRAM_URL=\"\"|PROGRAM_URL=\"$program_url\"|" \
    "$dir/program.conf"

count() { sed 's/#.*//' "$1" | grep -c '[^[:space:]]' || true; }
ok "In scope: $(count "$in_scope") rules | Out of scope: $(count "$out_scope") rules | Skipped for manual handling: $skipped"
warn "Now compare scope/ with $program_url before running recon."
