#!/usr/bin/env bash
# package.sh — Build a distributable .skill file from this repo
#
# Usage:
#   ./package.sh              # outputs virustotal-api.skill in current directory
#   ./package.sh ./dist       # outputs into ./dist/
#
# The .skill file is a zip archive with contents wrapped in a virustotal-api/
# folder, matching the expected skill folder name. Attach it to a GitHub
# Release so Claude.ai users can install via Settings → Skills → Upload.

set -euo pipefail

SKILL_NAME="virustotal-api"
OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/${SKILL_NAME}.skill"

# Validate SKILL.md exists and has required frontmatter
if [[ ! -f "SKILL.md" ]]; then
  echo "❌ Error: SKILL.md not found. Run this script from the repo root."
  exit 1
fi
if ! grep -q "^name:" SKILL.md; then
  echo "❌ Error: SKILL.md is missing 'name:' in frontmatter."
  exit 1
fi
if ! grep -q "^description:" SKILL.md; then
  echo "❌ Error: SKILL.md is missing 'description:' in frontmatter."
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Stage contents into a named subfolder, then zip
STAGING_DIR=$(mktemp -d)
trap 'rm -rf "$STAGING_DIR"' EXIT

DEST="${STAGING_DIR}/${SKILL_NAME}"
mkdir "$DEST"

# Copy everything except repo/meta files that don't belong in the skill package
while IFS= read -r -d '' file; do
  rel="${file#./}"
  case "$rel" in
    .git/*|.git|.github/*|.github) continue ;;
    .claude-plugin/*|.claude-plugin) continue ;;
    README.md|LICENSE|CHANGELOG.md|.gitignore|package.sh) continue ;;
    *.skill|.DS_Store|__pycache__/*|*.pyc) continue ;;
  esac
  dest_file="${DEST}/${rel}"
  mkdir -p "$(dirname "$dest_file")"
  cp "$file" "$dest_file"
done < <(find . -type f -print0)

# Create the zip from the staging directory
(cd "$STAGING_DIR" && zip -r - "${SKILL_NAME}") > "$OUTPUT_FILE"

echo "✅ Packaged: ${OUTPUT_FILE}"
echo ""
echo "Contents:"
unzip -l "$OUTPUT_FILE"