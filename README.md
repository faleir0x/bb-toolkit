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
| `import-scope.sh <name> [handle] [--platform hackerone\|bugcrowd\|intigriti] [--force]` | Fills `scope/` from public scope data (HackerOne, Bugcrowd, Intigriti; YesWeHack is manual). Program notes become `# NOTE` comments, out-of-scope patterns like `*dev*.x.com` stay active, path-scoped and non-host entries are commented out for manual handling. Platform defaults to `PLATFORM` in `program.conf`. |
| `recon.sh <name> [--passive] [--resume]` | Subdomains (subfinder) → scope filter → DNS (dnsx) + wildcard DNS filtering → HTTP probing (httpx, with progress). One dated folder per run, `recon/latest` → newest finished run, `summary.md` with what's new since the last run. `--passive` sends nothing to the target. `--resume` continues a run stopped with Ctrl+C or an error. |

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
