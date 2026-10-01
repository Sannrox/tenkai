#!/usr/bin/env bash
# Fail when a relative Markdown link or #anchor in tracked documentation does
# not resolve. External URLs are not fetched. Anchors follow GitHub's heading
# slug rules (lowercase, punctuation dropped, spaces to hyphens, -N suffixes
# for repeats) plus explicit <a id> / <a name> targets.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

files="$(mktemp)"
trap 'rm -f "$files"' EXIT
git ls-files > "$files"

# shellcheck disable=SC2016 # awk program, not shell expansion
git ls-files -z '*.md' | xargs -0 awk -v tracked="$files" '
function slug(text,    s) {
  s = tolower(text)
  gsub(/\]\([^)]*\)/, "]", s)
  gsub(/—|–|→|←|↔|…|’|‘|“|”|·|×|§/, "", s)
  gsub(/[!-,.\/:-@[-^`{-~]/, "", s)
  gsub(/ /, "-", s)
  return s
}
function dirname(path,    i) {
  i = match(path, /\/[^\/]*$/)
  return i ? substr(path, 1, i - 1) : ""
}
function normalize(path,    n, parts, out, depth, i) {
  n = split(path, parts, "/")
  depth = 0
  for (i = 1; i <= n; i++) {
    if (parts[i] == "" || parts[i] == ".") continue
    if (parts[i] == "..") { if (depth == 0) return "/outside"; depth--; continue }
    out[++depth] = parts[i]
  }
  path = ""
  for (i = 1; i <= depth; i++) path = path (i > 1 ? "/" : "") out[i]
  return path
}
BEGIN {
  while ((getline line < tracked) > 0) {
    exists[line] = 1
    while ((i = match(line, /\/[^\/]*$/)) > 0) { line = substr(line, 1, i - 1); exists[line] = 1 }
  }
  exists[""] = 1
}
FNR == 1 { fence = "" }
{
  if (fence == "" && match($0, /^ *(```|~~~)/)) { fence = substr($0, RSTART + RLENGTH - 3, 3); next }
  if (fence != "") { if (index($0, fence) && $0 ~ ("^ *" fence)) fence = ""; next }
  if (match($0, /^#+ /) && RLENGTH <= 7) {
    heading = substr($0, RLENGTH + 1)
    sub(/ +#+ *$/, "", heading)
    s = slug(heading)
    key = FILENAME SUBSEP s
    if (key in seen) { anchors[FILENAME SUBSEP s "-" seen[key]] = 1; seen[key]++ }
    else { anchors[key] = 1; seen[key] = 1 }
  }
  rest = $0
  while (match(rest, /<a (id|name)="[^"]+"/)) {
    target = substr(rest, RSTART, RLENGTH); sub(/^<a (id|name)="/, "", target); sub(/"$/, "", target)
    anchors[FILENAME SUBSEP target] = 1
    rest = substr(rest, RSTART + RLENGTH)
  }
  rest = $0
  gsub(/`[^`]*`/, "", rest)
  while (match(rest, /\]\([^) ]+( "[^"]*")?\)/)) {
    target = substr(rest, RSTART + 2, RLENGTH - 3)
    rest = substr(rest, RSTART + RLENGTH)
    sub(/ "[^"]*"$/, "", target)
    sub(/^</, "", target); sub(/>$/, "", target)
    if (target ~ /^[a-zA-Z][a-zA-Z0-9+.-]*:/) continue
    links[++nlinks] = FILENAME "\t" FNR "\t" target
  }
}
END {
  bad = 0
  for (i = 1; i <= nlinks; i++) {
    split(links[i], f, "\t")
    source = f[1]; target = f[3]
    anchor = ""
    if ((h = index(target, "#")) > 0) { anchor = substr(target, h + 1); target = substr(target, 1, h - 1) }
    if (target == "") path = source
    else if (substr(target, 1, 1) == "/") path = normalize(substr(target, 2))
    else path = normalize(dirname(source) "/" target)
    if (!(path in exists)) {
      printf "%s:%s: broken link: %s\n", source, f[2], f[3]; bad++; continue
    }
    if (anchor != "" && path ~ /\.md$/ && anchor !~ /^L[0-9]+(-L[0-9]+)?$/ && !((path SUBSEP tolower(anchor)) in anchors)) {
      printf "%s:%s: missing anchor: %s\n", source, f[2], f[3]; bad++
    }
  }
  if (bad) { printf "docs link check failed: %d broken link(s)\n", bad; exit 1 }
  printf "docs link check passed (%d relative links)\n", nlinks
}
'
