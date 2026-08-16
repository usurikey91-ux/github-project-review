# Tool Options

## Recommended default: this Skill plus the bundled collector

Use the bundled collector for small or medium batches. It is read-only, uses Python standard library plus public GitHub REST endpoints, and leaves the final interpretation to the agent. It reads selected public text files through the API but does not clone repositories, download release assets, install dependencies, or execute target code.

The collector is unauthenticated by default. Use `--use-token` only after the user explicitly approves using the `GITHUB_TOKEN` environment variable.

## GitHub CLI (`gh`)

GitHub CLI can display a repository description and README with `gh repo view`, and can make authenticated API requests with `gh api`. It is useful when the user already has `gh` installed and has explicitly approved installing or authenticating it. Do not make `gh repo clone`, `gh codespace`, workflow, or run commands part of the default screening path.

Suggested read-only commands after explicit approval to use `gh`:

```powershell
gh repo view OWNER/REPO
gh api repos/OWNER/REPO
gh api repos/OWNER/REPO/git/trees/BRANCH?recursive=1
gh api repos/OWNER/REPO/releases?per_page=5
```

## Static-analysis tools

Linters, CodeQL, SonarQube and similar tools answer code-quality or security questions. They do not by themselves prove that a README's promised user workflow works. Use them only as a second phase after the repository has passed static existence checks and the user has approved installing or running analysis tooling.

## Decision rule

- Need a no-install, cross-platform batch screen: use this Skill and the collector.
- Already have GitHub CLI and want richer metadata: optionally use `gh repo view` and `gh api`.
- Need security or maintainability findings after selecting a project: propose a separate static-analysis phase with an explicit confirmation gate.
