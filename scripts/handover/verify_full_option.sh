#!/usr/bin/env bash
set -euo pipefail

# Verifies the curated full_option handover bundle.
# Bounded output: single PASS/FAIL line with SecCode.

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BASE="$ROOT/full_option"
MANIFEST="$BASE/manifests/FULL_OPTION_MANIFEST.sha256"

fail() {
  echo "FAIL: verify_full_option SEC_$1"
  exit 1
}

[ -d "$BASE" ] || fail "NO_FULL_OPTION"
[ -f "$MANIFEST" ] || fail "MANIFEST_MISSING"

forbidden_regex='(secrets|\.pem$|\.key$|_key|private|artifacts/tmp|target|node_modules)'
while IFS= read -r path; do
  rel="${path#"$BASE"/}"
  [[ "$rel" =~ $forbidden_regex ]] && fail "FORBIDDEN_PATH"
done < <(find "$BASE" -type f)

expected_paths=()
expected_hashes=()
while read -r hash relpath; do
  [[ -z "${hash:-}" || -z "${relpath:-}" ]] && continue
  expected_hashes+=("$hash")
  expected_paths+=("$relpath")
done < "$MANIFEST"

if [ ${#expected_paths[@]} -eq 0 ]; then
  fail "EMPTY_MANIFEST"
fi

tmp_exp=$(mktemp)
tmp_act=$(mktemp)
trap 'rm -f "$tmp_exp" "$tmp_act"' EXIT

printf '%s\n' "${expected_paths[@]}" | LC_ALL=C sort > "$tmp_exp"
(cd "$BASE" && find . -type f -print | sed 's|^./||' | grep -v '^manifests/FULL_OPTION_MANIFEST.sha256$' | LC_ALL=C sort) > "$tmp_act"

missing=$(comm -23 "$tmp_exp" "$tmp_act")
[ -n "$missing" ] && fail "MISSING_FILE"

extra=$(comm -13 "$tmp_exp" "$tmp_act")
[ -n "$extra" ] && fail "EXTRA_FILE"

for i in "${!expected_paths[@]}"; do
  path="${expected_paths[$i]}"
  hash="${expected_hashes[$i]}"
  [ -f "$BASE/$path" ] || fail "MISSING_FILE"
  calc=$(shasum -a 256 "$BASE/$path" | awk '{print $1}')
  [[ "$calc" == "$hash" ]] || fail "HASH_MISMATCH"
done

echo "PASS: verify_full_option SEC_OK"
