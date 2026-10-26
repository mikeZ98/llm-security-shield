# Contributing to llm-security-shield

## ⛔ Sole-Contributor Invariant (non-negotiable)

Every commit in this repository, on every branch, MUST have **author and committer** set to exactly:

| Field | Value |
|-------|-------|
| Name  | `mikeZ98` |
| Email | `145975972+mikeZ98@users.noreply.github.com` |

- No other name, no machine username, no personal or local email: zero tolerance.
- Commit messages MUST NOT contain AI attribution or co-author metadata. Banned: `Co-Authored-By`,
  `Generated-by`, `Generated with`, `Assisted-by`, `AI-generated`, the 🤖 emoji, and any mention of
  Claude, Anthropic, ChatGPT, OpenAI, GPT-n, Copilot, Gemini or Cursor. The literal file name
  `CLAUDE.md` is the only exception.
- Every GitHub web-UI merge method (merge, squash and rebase) records `GitHub <noreply@github.com>`
  as committer and **will fail** the audit. Land changes with the
  [fast-forward workflow](#landing-changes-on-main) instead.

### How it is enforced

| Layer | Where | Checks |
|-------|-------|--------|
| `pre-commit` | `.githooks/pre-commit` | author/committer identity; blocks `.cache/`, venvs, `.env*`, keys; ruff check and format on staged Python |
| `commit-msg` | `.githooks/commit-msg` | forbidden trailers/terms; Conventional Commit subject; identity re-check (covers `--author` and `--amend`) |
| `pre-push` | `.githooks/pre-push` | full audit of every commit being pushed |
| CI | `scripts/audit-attribution.sh` via the GitHub Actions `attribution-audit` job | server-side audit of the whole branch history |
| Branch protection | GitHub, `main` | all five CI checks required from GitHub Actions, branch up to date, linear history, applies to admins, no force-push or deletion |
| Secret scanning | GitHub | push protection rejects pushes that contain recognized secrets |

The policy (allowed identity and banned patterns) lives in one place: `.githooks/_policy.sh`.
Audit any range by hand with `scripts/audit-attribution.sh [<rev-list args>]` (default: `HEAD`).

Never bypass hooks with `--no-verify`. CI re-runs the same audit and will reject the branch anyway.

## Environment setup (macOS, external SSD)

All caches, the virtualenv, temp files and the Colima VM live under `./.cache/` on
`/Volumes/KINGSTONE_SSD`. Nothing is written to the internal disk.

```bash
brew install uv direnv colima docker
direnv allow          # pins caches and sets core.hooksPath + the local git identity
uv sync               # downloads CPython 3.13 and creates .cache/venv
```

`.envrc` sets `XDG_CACHE_HOME`, `UV_CACHE_DIR`, `UV_PYTHON_INSTALL_DIR`, `UV_PROJECT_ENVIRONMENT`,
`RUFF_CACHE_DIR`, `MYPY_CACHE_DIR`, `COVERAGE_FILE`, `PYTHONPYCACHEPREFIX`, `TMPDIR`, `COLIMA_HOME`,
`LIMA_HOME`, `DOCKER_HOST` and `DOCKER_CONFIG`. Tool config in `pyproject.toml` also points the
pytest, ruff, mypy and coverage caches at `.cache/`, so they stay there even without direnv. Put
personal overrides in `.envrc.local` (gitignored).

## Quality gates

```bash
ruff check . && ruff format --check .
mypy                      # strict, configured in pyproject.toml
bandit -c pyproject.toml -r src
pytest                    # hermetic: sockets disabled, coverage ≥ 90% (branch)
```

## Commit discipline

- [Conventional Commits](https://www.conventionalcommits.org/): `<type>(<scope>): <summary>`, subject
  ≤ 100 characters. Types: `feat fix chore docs test build ci refactor perf style revert`.
- One logical change per commit. Keep commits atomic and green.

## Landing changes on `main`

`main` only accepts a commit after the five CI checks (`attribution-audit`, `lint-and-typecheck`,
`security-audit`, `test-hermetic`, `docker-build`) have passed on that exact commit. History must
stay linear and the rules apply to admins too. Pull request reviews are deliberately not
required: a required review forces a web-UI merge, and every web-UI merge rewrites the committer.
Instead, open a pull request so CI runs, then fast-forward `main` locally to the green branch:

```bash
git switch main && git pull --ff-only
git switch -c docs/my-change                 # one topic per branch
git commit                                   # hooks check identity and message
git push -u origin docs/my-change
gh pr create --fill --base main              # CI runs on the pull request
gh pr checks --watch --fail-fast             # wait until all five checks pass
git switch main
git merge --ff-only docs/my-change           # your commits, unchanged
git push origin main                         # accepted: checks already passed on this commit
git push origin --delete docs/my-change && git branch -d docs/my-change
```

GitHub marks the pull request as merged once its head commit reaches `main`.

- **`main` moved meanwhile?** `--ff-only` refuses. Rebase the branch (`git rebase main`), push it
  with `git push --force-with-lease`, wait for the checks again, then fast-forward.
- **Never click Merge in the web UI.** GitHub would accept it once the checks pass, but the merge
  commit is committed by GitHub, fails the audit on `main`, and cannot be removed without
  lifting branch protection, because force-pushes to `main` are blocked.
- **Never bypass push protection.** If secret scanning blocks a push, remove the secret from the
  history and rotate it.

### Dependency updates

Dependabot alerts are enabled. Dependabot security-update pull requests are disabled on purpose:
their commits are authored by `dependabot[bot]` and would fail the audit. Apply fixes yourself
with `uv lock --upgrade-package <name>`, run the quality gates, and land the change through the
workflow above.
