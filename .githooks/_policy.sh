# shellcheck shell=bash
# Shared attribution policy for git hooks and scripts/audit-attribution.sh.
# Sourced, never executed. Git ignores this file as a hook (not a hook name).

readonly SHIELD_ALLOWED_NAME="mikeZ98"
readonly SHIELD_ALLOWED_EMAIL="145975972+mikeZ98@users.noreply.github.com"

# Case-insensitive ERE matched against commit messages (after stripping
# comments and the literal file name CLAUDE.md, which docs commits may cite).
readonly SHIELD_FORBIDDEN_MSG_RE='co-authored-by|generated-by|generated[ -]with|ai-generated|assisted-by|signed-off-by:.*(noreply@anthropic|openai)|claude|anthropic|chatgpt|openai|gpt-[0-9]|copilot|gemini|cursor\.(sh|com)|🤖'

readonly SHIELD_CONVENTIONAL_RE='^(feat|fix|chore|docs|test|build|ci|refactor|perf|style|revert)(\([a-z0-9._/-]+\))?!?: [^ ].{0,98}$'

shield_err() { printf '\033[31m✖ %s\033[0m\n' "$*" >&2; }
shield_ok() { printf '\033[32m✔ %s\033[0m\n' "$*" >&2; }

# shield_check_identity <role> <name> <email>
shield_check_identity() {
  local role="$1" name="$2" email="$3"
  if [[ "$name" != "$SHIELD_ALLOWED_NAME" || "$email" != "$SHIELD_ALLOWED_EMAIL" ]]; then
    shield_err "$role identity '$name <$email>' violates the sole-contributor invariant."
    shield_err "Expected: '$SHIELD_ALLOWED_NAME <$SHIELD_ALLOWED_EMAIL>'."
    return 1
  fi
}

# shield_parse_ident <git-var-ident>  →  prints "name<TAB>email"
shield_parse_ident() {
  sed -E 's/^(.*) <([^>]*)> [0-9]+ [-+][0-9]{4}$/\1\t\2/' <<<"$1"
}

# shield_clean_message — strip comments and anything below the scissors line.
shield_clean_message() {
  sed -e '/^# ------------------------ >8 ------------------------$/,$d' -e '/^#/d'
}

# shield_check_message <message-text>
shield_check_message() {
  local msg="$1" hits
  hits="$(sed -E 's/CLAUDE\.md//g' <<<"$msg" | grep -inE "$SHIELD_FORBIDDEN_MSG_RE" || true)"
  if [[ -n "$hits" ]]; then
    shield_err "Commit message contains forbidden AI attribution / co-author metadata:"
    printf '    %s\n' "$hits" >&2
    return 1
  fi
}

# shield_check_subject <first-line>
shield_check_subject() {
  local subject="$1"
  case "$subject" in
    Merge\ *|fixup!\ *|squash!\ *|amend!\ *) return 0 ;;
  esac
  if ! grep -qE "$SHIELD_CONVENTIONAL_RE" <<<"$subject"; then
    shield_err "Subject is not a Conventional Commit (max 100 chars): '$subject'"
    shield_err "Format: <type>(<scope>)?: <summary>   types: feat fix chore docs test build ci refactor perf style revert"
    return 1
  fi
}
