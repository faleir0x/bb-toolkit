# Bug bounty scripts

Automation for setting up programs and running recon.

```
bug-bounty/
├── scripts/     this repo
├── programs/    one workspace per program (not in git)
└── wordlists/   SecLists and other wordlists (not in git)
```

## Scripts

| Script | What it does |
|---|---|
| `new-program.sh <name>` | Creates `programs/<name>/` with folders, scope files and templates. Sends nothing to the target. |

## Workflow

1. `./new-program.sh "Example Corp"`
2. Read the program policy. Fill `scope/in-scope.txt`, `scope/out-of-scope.txt` and `program.conf`.
3. Run recon (coming next).

## Scope syntax

```
*.example.com    any subdomain of example.com (not example.com itself)
example.com      exactly example.com
```

Out-of-scope rules always win. Every recon stage filters results through
`scope_filter` in `lib/common.sh`.
