#!/usr/bin/env bash
# Fails when a tracked file (or, with a range argument, a commit message in that range)
# matches a denylisted pattern.
#
#   scripts/denylist.sh              # tracked files
#   scripts/denylist.sh origin/main..HEAD   # tracked files and commit messages in the range
#
# Patterns: denylist.txt (public, generic) and denylist.local.txt (untracked, optional).
# GUIDs other than the all-zero test placeholders (00000000-0000-0000-0000-0000000000xx) and
# email addresses outside example.com, example.org, and GitHub noreply addresses are also
# refused. The test keys under crates/mcpward-testing/keys/ are exempt from the GUID check.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

patterns=$(mktemp)
trap 'rm -f "$patterns"' EXIT
for f in denylist.txt denylist.local.txt; do
  [[ -f "$f" ]] && grep -vE '^\s*(#|$)' "$f" >>"$patterns" || true
done

files=$(git ls-files -co --exclude-standard | grep -vE '^(denylist\.txt|scripts/denylist\.sh)$' || true)
status=0

if [[ -s "$patterns" ]] && [[ -n "$files" ]]; then
  if hits=$(echo "$files" | xargs -d '\n' grep -nIiE -f "$patterns" -- 2>/dev/null); then
    echo "Denylisted patterns found:" >&2
    echo "$hits" >&2
    status=1
  fi
fi

guid='[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
placeholder='00000000-0000-0000-0000-0000000000[0-9a-f]{2}'
guid_files=$(echo "$files" | grep -v '^crates/mcpward-testing/keys/' || true)
if [[ -n "$guid_files" ]]; then
  if hits=$(echo "$guid_files" | xargs -d '\n' grep -noIiE -- "$guid" 2>/dev/null | grep -viE ":$placeholder\$"); then
    echo "Non-placeholder GUIDs found (use 00000000-0000-0000-0000-0000000000xx):" >&2
    echo "$hits" >&2
    status=1
  fi
fi

email='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
allowed_email='@(([A-Za-z0-9-]+\.)*example\.(com|org)|users\.noreply\.github\.com)$'
if [[ -n "$files" ]]; then
  if hits=$(echo "$files" | xargs -d '\n' grep -noIE -- "$email" 2>/dev/null | grep -vE "$allowed_email" | grep -vE '@[0-9]+\.[0-9]+' ); then
    echo "Email addresses outside example domains found:" >&2
    echo "$hits" >&2
    status=1
  fi
fi

if [[ $# -gt 0 ]] && [[ -s "$patterns" ]]; then
  if hits=$(git log --format='%H %B' "$1" | grep -iE -f "$patterns"); then
    echo "Denylisted patterns in commit messages:" >&2
    echo "$hits" >&2
    status=1
  fi
fi

exit $status
