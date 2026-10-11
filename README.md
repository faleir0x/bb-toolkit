# bb-toolkit

Automation for setting up programs and running recon.

```
bug-bounty/
├── bb-toolkit/  this repo
├── programs/    one workspace per program (not in git)
└── wordlists/   SecLists and other wordlists (not in git)
```

## Scripts

| Script | What it does |
|---|---|
| `new-program.sh <name>` | Creates `programs/<name>/` with folders, scope files and templates. Sends nothing to the target. |
| `import-scope.sh <name> [handle]` | Fills `scope/` from HackerOne public data. Path-scoped entries are commented out for manual handling. |
| `recon.sh <name> [--passive]` | Subdomains (subfinder) → scope filter → DNS (dnsx) → HTTP probing (httpx). One dated folder per run, `recon/latest` → newest, `summary.md` with what's new since the last run. `--passive` sends nothing to the target. |

## Workflow

```
new-program.sh vimeo
import-scope.sh vimeo      # then compare scope/ with the policy, edit program.conf
recon.sh vimeo             # results: programs/vimeo/recon/latest/summary.md
```

## Scope syntax

```
*.example.com    any subdomain of example.com (not example.com itself)
example.com      exactly example.com
```

Out-of-scope rules always win. Every recon stage filters results through
`scope_filter` in `lib/common.sh`.
