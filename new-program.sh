#!/usr/bin/env bash
# Create a workspace for a new bug bounty program.
#
#   ./new-program.sh <program name>
#   ./new-program.sh "Example Corp"   -> programs/example-corp/
#
# This only creates folders and templates. It sends nothing to any target.
# Next step after running it: fill scope/ and program.conf from the program page.

set -euo pipefail
source "$(dirname "$(readlink -f "$0")")/lib/common.sh"

usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") <program name>

Creates $PROGRAMS_DIR/<slug>/ with folders and templates.
EOF
    exit 1
}

[[ $# -eq 1 && "$1" != "-h" && "$1" != "--help" ]] || usage

name="$1"
# Restrict characters so the name can go into program.conf (a bash file) safely.
[[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9\ ._-]*$ ]] \
    || die "Use only letters, digits, spaces, '.', '_' and '-' in the name"

slug="$(slugify "$name")"
[[ -n "$slug" ]] || die "Name '$name' produces an empty folder name"

dir="$PROGRAMS_DIR/$slug"
[[ ! -e "$dir" ]] || die "Workspace already exists: $dir"

today="$(date +%F)"

info "Program: $name"
info "Workspace: $dir"

# ---------------------------------------------------------------------------
# Folders
# ---------------------------------------------------------------------------
#   scope/     what you're allowed to test (read by every recon stage)
#   recon/     automated recon, one dated folder per run
#   scans/     active scans (nuclei, ffuf...) - only if the policy allows them
#   manual/    your manual testing: Burp exports, screenshots, notes
#   findings/  one folder per candidate bug
#   ai/        summaries and context prepared for the AI
mkdir -p "$dir"/{scope,recon,scans,manual,findings,ai}

# ---------------------------------------------------------------------------
# program.conf - rules from the policy, read by recon.sh
# ---------------------------------------------------------------------------
cat > "$dir/program.conf" <<EOF
# Program settings. Fill these in from the program's policy page.
# This file is sourced by bash, so keep the KEY="value" format.

PROGRAM_NAME="$name"
PLATFORM=""             # hackerone | bugcrowd | intigriti | yeswehack | other
PROGRAM_URL=""          # link to the program's policy page

# --- Rules from the policy -------------------------------------------------
RATE_LIMIT=5            # max requests per second for active tools
CUSTOM_HEADER=""        # e.g. "X-HackerOne: yourusername" if the policy requires one
USER_AGENT=""           # some programs require a specific User-Agent
ALLOW_ACTIVE_SCAN="no"  # "yes" only if the policy allows automated scanners

CREATED="$today"
EOF

# ---------------------------------------------------------------------------
# Scope files
# ---------------------------------------------------------------------------
cat > "$dir/scope/in-scope.txt" <<'EOF'
# In-scope assets, one per line. Copy them from the program page.
#
#   *.example.com    any subdomain of example.com (NOT example.com itself)
#   example.com      exactly example.com
#   app.example.com  exactly that host
#
# If the program lists both "*.example.com" and "example.com", add both lines.
EOF

cat > "$dir/scope/out-of-scope.txt" <<'EOF'
# Out-of-scope assets, same syntax as in-scope.txt.
# These always win: a host matching a line here is never tested.
EOF

# ---------------------------------------------------------------------------
# notes.md - your own understanding of the program
# ---------------------------------------------------------------------------
cat > "$dir/notes.md" <<EOF
# $name

- Platform:
- Program page:
- Started: $today

## What the company does
<!-- Main products and features. What data matters most to them?
     What kind of bug would hurt them the most? -->

## Rules and restrictions
<!-- Key points from the policy: forbidden tests, rate limits, required
     headers, test accounts, what they don't accept. -->

## What they pay for
<!-- Bounty table, severities, bug types they care about. -->

## Disclosed reports
<!-- Public reports on this program (and similar ones). What was found, where? -->

## Attack surface
<!-- Interesting hosts, features, roles, APIs, tech stack. -->

## Ideas to test

## Log
- $today: workspace created
EOF

# ---------------------------------------------------------------------------
# findings/_template.md - copy this into findings/<bug-name>/report.md
# ---------------------------------------------------------------------------
cat > "$dir/findings/_template.md" <<'EOF'
# <Short title: bug type + where + impact>

- Status: candidate   <!-- candidate | reproduced | reported | triaged | resolved | duplicate | n/a -->
- Asset:
- Bug type:
- Estimated severity:
- Date found:

## Summary
<!-- Two or three sentences: what the bug is and why it matters. -->

## Steps to reproduce
1.
2.
3.

## Proof of concept
<!-- Exact requests/responses (from Burp), screenshots, video. -->

## Impact
<!-- What can an attacker actually do? Be concrete, don't exaggerate. -->

## Suggested fix
EOF

# ---------------------------------------------------------------------------
# CLAUDE.md - context and rules for AI assistants working in this folder
# ---------------------------------------------------------------------------
cat > "$dir/CLAUDE.md" <<EOF
# Bug bounty workspace: $name

You are helping a beginner bug bounty hunter on this program. Teach along the
way: explain why something might be vulnerable, not only what to do.

## Scope (read before doing anything)
- In scope: scope/in-scope.txt
- Out of scope: scope/out-of-scope.txt (always wins over in-scope)
- Program rules: program.conf and the "Rules and restrictions" section of notes.md
- If a host or URL is not clearly in scope, treat it as out of scope and ask.

## Hard rules
- Never send requests to a target (curl, scanners, fuzzers, browser) without
  the user's explicit OK for that specific action.
- Respect RATE_LIMIT and send CUSTOM_HEADER / USER_AGENT from program.conf.
- No destructive tests, no denial of service, no touching other users' real
  data beyond the minimum needed to prove impact.
- Never call something a vulnerability until it has been reproduced.
  Call it a "candidate" until then.

## Workspace layout
- recon/<date>/   automated recon runs (recon/latest points to the newest)
- scans/          output of active scans
- manual/         notes and exports from manual testing
- findings/<bug>/ one folder per candidate bug, based on findings/_template.md
- ai/             summaries and context prepared for you
- notes.md        the hunter's notes about the program
EOF

ok "Workspace created"
cat >&2 <<EOF

Next steps:
  1. Fill the scope: import-scope.sh $slug   (HackerOne programs)
     or edit $dir/scope/ by hand
  2. Read the policy, compare it with scope/, fill in program.conf
  3. Run recon: recon.sh $slug
EOF

# Print the path on stdout so it can be used like:  cd "$(./new-program.sh foo)"
printf '%s\n' "$dir"
