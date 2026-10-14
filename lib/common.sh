#!/usr/bin/env bash
# Shared helpers for all bug bounty scripts.
# Usage (from a script in the repo root):  source "$(dirname "$0")/lib/common.sh"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# Layout:  BB_HOME/
#            ├── bb-toolkit/  (this repo)
#            ├── programs/    (one workspace per program)
#            └── wordlists/   (SecLists, etc.)
# Any of these can be overridden with an environment variable.
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BB_HOME="${BB_HOME:-$(dirname "$SCRIPTS_DIR")}"
PROGRAMS_DIR="${PROGRAMS_DIR:-$BB_HOME/programs}"
WORDLISTS_DIR="${WORDLISTS_DIR:-$BB_HOME/wordlists}"
SECLISTS="${SECLISTS:-$WORDLISTS_DIR/SecLists}"

# Tools live in ~/go/bin (go install) and ~/.pdtm/go/bin (pdtm).
# ~/.bashrc adds these for interactive terminals, but cron and other
# non-interactive shells don't read .bashrc, so add them here too.
for _p in "$HOME/go/bin" "$HOME/.pdtm/go/bin"; do
    case ":$PATH:" in *":$_p:"*) ;; *) PATH="$PATH:$_p" ;; esac
done
unset _p
export PATH

# ---------------------------------------------------------------------------
# Logging (colors only when printing to a terminal)
# ---------------------------------------------------------------------------
if [[ -t 2 ]]; then
    C_RED=$'\e[31m' C_GREEN=$'\e[32m' C_YELLOW=$'\e[33m' C_BLUE=$'\e[34m' C_RESET=$'\e[0m'
else
    C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_RESET=''
fi

# Logs go to stderr so stdout stays clean for piping results.
info() { printf '%s[*]%s %s\n' "$C_BLUE"   "$C_RESET" "$*" >&2; }
ok()   { printf '%s[+]%s %s\n' "$C_GREEN"  "$C_RESET" "$*" >&2; }
warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# require_tools tool1 tool2 ...  -> exits listing every missing tool.
require_tools() {
    local missing=() t
    for t in "$@"; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    ((${#missing[@]} == 0)) || die "Missing tools: ${missing[*]} (run setup.sh)"
}

# slugify "Varonis Inc." -> "varonis-inc"
# Keeps folder names safe: lowercase letters, digits and single dashes.
slugify() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' \
        | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//'
}

# program_dir <name> -> prints the workspace path, dies if it doesn't exist.
program_dir() {
    local dir
    dir="$PROGRAMS_DIR/$(slugify "$1")"
    [[ -d "$dir" ]] || die "No workspace for '$1' at $dir (run new-program.sh first)"
    printf '%s\n' "$dir"
}

# ---------------------------------------------------------------------------
# Scope filter
# ---------------------------------------------------------------------------
# scope_filter <in-scope.txt> <out-of-scope.txt>  < hosts  > in-scope hosts
#
# The most important function here: every recon stage pipes its results
# through it, because sources like crt.sh, Wayback and crawlers happily
# return hosts the program never authorized you to test.
#
# Rule syntax (one per line, '#' starts a comment):
#   *.example.com   -> any subdomain of example.com (NOT example.com itself)
#   example.com     -> exactly example.com
#   https://app.example.com/path  -> treated as app.example.com
#   *dev*.example.com -> any host matching the pattern ("*" = any characters)
#
# Out-of-scope rules always win over in-scope rules.
# Input lines may be bare hosts or URLs; output is deduplicated bare hosts.
# (IP/CIDR scopes are not handled yet.)
scope_filter() {
    local in_file="$1" out_file="$2"
    [[ -f "$in_file" ]] || die "Scope file not found: $in_file"
    [[ -f "$out_file" ]] || out_file=/dev/null

    awk '
        # Reduce a line to a bare lowercase hostname ("" for blank/comment).
        function norm(s) {
            s = tolower(s)
            sub(/#.*$/, "", s)                       # comments
            sub(/^[ \t\r]+/, "", s)
            sub(/^[a-z][a-z0-9+.-]*:\/\//, "", s)   # scheme://
            sub(/^[^\/@]*@/, "", s)                  # user:pass@
            sub(/[\/:? \t\r].*$/, "", s)             # path, port, spaces
            sub(/\.$/, "", s)                        # trailing dot (DNS)
            return s
        }
        # Other patterns ("*dev*.example.com"): "*" matches any characters.
        function glob_match(host, rule,    re) {
            re = rule
            gsub(/\./, "\\.", re)
            gsub(/\*/, "[a-z0-9.-]*", re)
            return host ~ ("^" re "$")
        }
        function matches(host, rule,    base) {
            if (index(rule, "*") && !(substr(rule, 1, 2) == "*." && !index(substr(rule, 3), "*")))
                return glob_match(host, rule)
            if (substr(rule, 1, 2) == "*.") {
                base = substr(rule, 2)               # ".example.com"
                return length(host) > length(base) &&
                       substr(host, length(host) - length(base) + 1) == base
            }
            return host == rule
        }
        FILENAME == ARGV[1] { r = norm($0); if (r != "") inr[++ni] = r; next }
        FILENAME == ARGV[2] { r = norm($0); if (r != "") outr[++no] = r; next }
        {
            h = norm($0)
            if (h == "" || h in seen) next
            ok = 0
            for (i = 1; i <= ni; i++) if (matches(h, inr[i])) { ok = 1; break }
            if (!ok) next
            for (i = 1; i <= no; i++) if (matches(h, outr[i])) next
            seen[h] = 1
            print h
        }
    ' "$in_file" "$out_file" -
}
