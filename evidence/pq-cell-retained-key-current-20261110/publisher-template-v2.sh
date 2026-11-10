#!/bin/sh
set -eu
umask 077
TASK_DIR=__TASK_DIR__
GH=/opt/homebrew/bin/gh
REPO=TrillionniumFoundation/Trillionnium-Chain
BRANCH=fix/chain-pq-cell-reuse-20261109
PARENT=a4c594fc9d5f43d0d2b7ae7e0835d0e1514dc667
EXPECTED_TREE=__EXPECTED_TREE__
EXPECTED_COMMIT=__EXPECTED_COMMIT__
api() { "$GH" api --hostname github.com "$@"; }
test "$(api user --jq .login)" = ProfHepta
test "$(api "repos/$REPO" --jq .id)" = 1323087357
test "$(api "repos/$REPO" --jq .permissions.admin)" = true
test "$(api "repos/$REPO/pulls/851" --jq .state)" = open
test "$(api "repos/$REPO/pulls/851" --jq .draft)" = true
test "$(api "repos/$REPO/pulls/851" --jq .head.ref)" = "$BRANCH"
test "$(api "repos/$REPO/git/ref/heads/$BRANCH" --jq .object.sha)" = "$PARENT"
printf '%s\n' AUTHENTICATED_AND_EXPECTED_HEAD > "$TASK_DIR/phase.txt"
while IFS="$(printf '\t')" read -r filename expected; do
  actual=$(api --method POST "repos/$REPO/git/blobs" --input "$TASK_DIR/payload/blobs/$filename" --jq .sha)
  test "$actual" = "$expected"
done < "$TASK_DIR/payload/blob-map.tsv"
tree=$(api --method POST "repos/$REPO/git/trees" --input "$TASK_DIR/payload/tree.json" --jq .sha)
test "$tree" = "$EXPECTED_TREE"
printf '%s\n' EXACT_TREE_CREATED > "$TASK_DIR/phase.txt"
commit=$(api --method POST "repos/$REPO/git/commits" --input "$TASK_DIR/payload/commit.json" --jq .sha)
case "$commit" in *[!0-9a-f]*|'') exit 31;; esac
test "${#commit}" -eq 40
printf '%s\n' "$commit" > "$TASK_DIR/created-commit.txt"
test "$commit" = "$EXPECTED_COMMIT"
test "$(api "repos/$REPO/git/commits/$commit" --jq .tree.sha)" = "$EXPECTED_TREE"
test "$(api "repos/$REPO/git/commits/$commit" --jq '.parents | length')" = 1
test "$(api "repos/$REPO/git/commits/$commit" --jq '.parents[0].sha')" = "$PARENT"
test "$(api "repos/$REPO/git/ref/heads/$BRANCH" --jq .object.sha)" = "$PARENT"
printf '{"sha":"%s","force":false}\n' "$commit" > "$TASK_DIR/ref.json"
api --method PATCH "repos/$REPO/git/refs/heads/$BRANCH" --input "$TASK_DIR/ref.json" > "$TASK_DIR/ref-response.json"
test "$(api "repos/$REPO/git/ref/heads/$BRANCH" --jq .object.sha)" = "$commit"
printf '%s\n' BRANCH_FAST_FORWARDED > "$TASK_DIR/phase.txt"
sed "s/__EVIDENCE_COMMIT__/$commit/g" "$TASK_DIR/payload/pr-template.json" > "$TASK_DIR/pr.json"
api --method PATCH "repos/$REPO/pulls/851" --input "$TASK_DIR/pr.json" > "$TASK_DIR/pr-response.json"
printf '{"login":"ProfHepta","repository":"%s","branch":"%s","parent":"%s","commit":"%s","tree":"%s","pr":851,"route":"HeptaRuntime mac local gh","production_activation":false}\n' "$REPO" "$BRANCH" "$PARENT" "$commit" "$tree" > "$TASK_DIR/result.json"
printf '%s\n' COMPLETED > "$TASK_DIR/phase.txt"
cat "$TASK_DIR/result.json"
