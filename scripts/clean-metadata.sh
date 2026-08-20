#!/usr/bin/env bash
set -euo pipefail

# Neutralize file timestamps to a fixed date.
echo "=== Metadata Cleanup ==="

echo "Checking for files that do not belong in a public tree..."
# The check runs over what git will actually publish - tracked files,
# plus anything untracked that a careless add would sweep in. Scanning
# the working directory instead would judge local tool state that
# never ships, and miss nothing that does.
CANDIDATES=$( { git ls-files; git ls-files --others --exclude-standard; } | sort -u )

# Binary documents never ship.
FOUND=$(printf '%s\n' "$CANDIDATES" | grep -iE '\.(docx|xlsx|pptx|pdf|zip)$' | head -5 || true)
if [ -n "$FOUND" ]; then
    echo "ERROR: Binary documents found:"
    echo "$FOUND"
    exit 1
fi

# Markdown is allowlisted rather than blocklisted: a name pattern only
# catches what it names. Anything outside docs/, .github/ and the
# standard top-level files is a stray working note and stays out.
STRAY=$(printf '%s\n' "$CANDIDATES" | grep -E '\.md$' \
    | grep -vE '^(docs|\.github)/' \
    | grep -vE '(^|/)(README|CHANGELOG|CONTRIBUTING|CODE_OF_CONDUCT|SECURITY)\.md$' \
    | head -5 || true)
if [ -n "$STRAY" ]; then
    echo "ERROR: Markdown outside the documented locations:"
    echo "$STRAY"
    exit 1
fi

echo "Checking for machine paths..."
PATHS=$(grep -ri "C:\\Users\|/home/\|/Users/" \
    --include="*.rs" --include="*.md" --include="*.toml" \
    --include="*.yml" --include="*.yaml" . 2>/dev/null | head -5 || true)
if [ -n "$PATHS" ]; then
    echo "ERROR: Machine paths found:"
    echo "$PATHS"
    exit 1
fi

echo "Neutralizing timestamps..."
find . -not -path './.git/*' -exec touch -t 202601010000 {} \; 2>/dev/null || true

echo "=== Metadata cleanup complete ==="
