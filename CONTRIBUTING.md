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
- Merges made in the GitHub web UI record `GitHub <noreply@github.com>` as committer and **will fail**
  the audit. Rebase or merge locally, then push.

### How it is enforced

| Layer | Where | Checks |
|-------|-------|--------|
| `pre-commit` | `.githooks/pre-commit` | author/committer identity; blocks `.cache/`, venvs, `.env*`, keys; ruff check and format on staged Python |
| `commit-msg` | `.githooks/commit-msg` | forbidden trailers/terms; Conventional Commit subject; identity re-check (covers `--author` and `--amend`) |
| `pre-push` | `.githooks/pre-push` | full audit of every commit being pushed |
| CI | `scripts/audit-attribution.sh` via the GitHub Actions `attribution-audit` job (added in the `ci(github)` step) | server-side audit of the whole branch history |

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
