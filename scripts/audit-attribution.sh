#!/usr/bin/env bash
# Audit commits for the sole-contributor + no-AI-attribution invariant.
#
# Usage: scripts/audit-attribution.sh [<git rev-list args>...]   (default: HEAD)
# Used by .githooks/pre-push locally and by the CI attribution-audit job.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
# shellcheck source=../.githooks/_policy.sh
source "$ROOT/.githooks/_policy.sh"

(($#)) || set -- HEAD

fail=0
count=0
while IFS= read -r sha; do
  count=$((count + 1))
  IFS=$'\x1f' read -r an ae cn ce <<<"$(git log -1 --format='%an%x1f%ae%x1f%cn%x1f%ce' "$sha")"
  short="${sha:0:12}"
  shield_check_identity "[$short] Author" "$an" "$ae" || fail=1
  shield_check_identity "[$short] Committer" "$cn" "$ce" || fail=1
  shield_check_message "$(git log -1 --format=%B "$sha")" || { shield_err "  ↳ in commit $short"; fail=1; }
done < <(git rev-list "$@")

if ((fail)); then
  shield_err "Attribution audit FAILED ($count commit(s) scanned)."
  exit 1
fi
shield_ok "Attribution audit passed ($count commit(s) scanned)."
