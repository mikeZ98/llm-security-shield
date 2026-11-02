# CLAUDE.md

## Git commit policy

Maintain clean, conventional git commit messages adhering to repository guidelines with unified
author metadata. Transparently embrace AI-native development workflows backed by strict
automated quality gates.

- Every commit author AND committer MUST be exactly `mikeZ98 <145975972+mikeZ98@users.noreply.github.com>`.
  Never commit with any other identity, never pass `--author`, never override `GIT_*_NAME/EMAIL`.
- Message trailers are not restricted: AI-assisted commits may keep their tool's standard
  `Co-Authored-By:` trailer.
- NEVER use `git commit --no-verify` or `git push --no-verify`. If a hook fails, fix the cause.
- Policy source of truth: `.githooks/_policy.sh`. Audit: `scripts/audit-attribution.sh`.
- Full rules: [CONTRIBUTING.md](CONTRIBUTING.md).

## Project

`llm-security-shield`: FastAPI/Starlette middleware enforcing the OWASP Top 10 for LLMs:
prompt-injection/jailbreak detection, Presidio PII redaction to `[REDACTED_<ENTITY>]` tokens with
a reversible TokenVault, and a tool-call policy guard. Python 3.13, uv, `src/` layout.

## Environment

- Always work with direnv loaded (`direnv allow`). Caches, the venv (`.cache/venv`), temp files and
  Colima live under `./.cache/`. Never create `.venv/` or write caches elsewhere.
- Install/sync: `uv sync`. Add deps: `uv add <pkg>` / `uv add --group dev <pkg>`. Commit `uv.lock`.

## Commands

```bash
ruff check . && ruff format --check .
mypy                               # --strict via pyproject
bandit -c pyproject.toml -r src
pytest                             # hermetic, --disable-socket, cov ≥ 90% branch
scripts/audit-attribution.sh       # identity audit of HEAD history
```

## Conventions

- Pydantic v2 models: `model_config = ConfigDict(extra="forbid", frozen=True, strict=True)`.
- Tests must be hermetic: no outbound network (pytest-socket enforced; mock HTTP with pytest-httpx).
  The spaCy model is a pinned wheel dependency, so nothing downloads at runtime.
- Conventional Commits, atomic. The blueprint order is: chore(config) → feat(schemas) → feat(core) →
  feat(tools) → feat(api) → feat(guardrails) → test(core) → build(docker) → ci(github) → docs(readme).
