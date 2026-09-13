#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GUARD="$ROOT/scripts/v2/check_unchecked_gov_usage.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

make_fixture() {
  local dir="$1"
  mkdir -p "$dir/crates/demo/src"
  cat >"$dir/Cargo.toml" <<'TOML'
[workspace]
members = ["crates/demo"]
resolver = "2"
TOML
  cat >"$dir/crates/demo/Cargo.toml" <<'TOML'
[package]
name = "demo"
version = "0.1.0"
edition = "2021"

[dev-dependencies]
trnm-state = { path = "../trnm-state", features = ["test-utils"] }
TOML
  cat >"$dir/crates/demo/src/lib.rs" <<'RS'
pub struct Store;

impl Store {
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn set_gov_param_bootstrap_unchecked(&mut self) {}
}

#[cfg(test)]
mod tests;
RS
  cat >"$dir/crates/demo/src/tests.rs" <<'RS'
#[test]
fn fixture_call() {
    let mut store = crate::Store;
    store.set_gov_param_bootstrap_unchecked();
}
RS
}

allowed="$TMP_DIR/allowed"
make_fixture "$allowed"
TRNM_UNCHECKED_GOV_SCAN_ROOT="$allowed/crates" \
TRNM_UNCHECKED_GOV_CARGO_ROOT="$allowed" \
  "$GUARD" >/dev/null

same_line="$TMP_DIR/same-line-cfg-test"
mkdir -p "$same_line/crates/demo/src"
cat >"$same_line/Cargo.toml" <<'TOML'
[workspace]
members = ["crates/demo"]
resolver = "2"
TOML
cat >"$same_line/crates/demo/Cargo.toml" <<'TOML'
[package]
name = "demo"
version = "0.1.0"
edition = "2021"
TOML
cat >"$same_line/crates/demo/src/lib.rs" <<'RS'
pub struct Store;

impl Store {
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn set_gov_param_bootstrap_unchecked(&mut self) {}
}

#[cfg(test)] mod tests {
    #[test]
    fn same_line_cfg_test_scope_is_recognized() {
        let mut store = super::Store;
        store.set_gov_param_bootstrap_unchecked();
    }
}
RS
TRNM_UNCHECKED_GOV_SCAN_ROOT="$same_line/crates" \
TRNM_UNCHECKED_GOV_CARGO_ROOT="$same_line" \
  "$GUARD" >/dev/null

detached_builtin_test="$TMP_DIR/detached-builtin-test"
make_fixture "$detached_builtin_test"
cat >"$detached_builtin_test/crates/demo/src/detached_builtin_test.rs" <<'RS'
#[test] fn exact_detached_builtin_test_is_test_only() {
    let mut store = crate::Store;
    store.set_gov_param_bootstrap_unchecked();
}
RS
TRNM_UNCHECKED_GOV_SCAN_ROOT="$detached_builtin_test/crates" \
TRNM_UNCHECKED_GOV_CARGO_ROOT="$detached_builtin_test" \
  "$GUARD" >/dev/null

intrinsic_inner_cfg_test="$TMP_DIR/intrinsic-inner-cfg-test"
make_fixture "$intrinsic_inner_cfg_test"
cat >>"$intrinsic_inner_cfg_test/crates/demo/src/lib.rs" <<'RS'

macro_rules! attach_intrinsic_test_module {
    ($name:ident) => {
        mod $name;
    };
}
attach_intrinsic_test_module!(intrinsic_test_helpers);
RS
cat >"$intrinsic_inner_cfg_test/crates/demo/src/intrinsic_test_helpers.rs" <<'RS'
#![cfg(test)]

fn ordinary_helper_is_intrinsically_test_only(store: &mut crate::Store) {
    store.set_gov_param_bootstrap_unchecked();
}
RS
TRNM_UNCHECKED_GOV_SCAN_ROOT="$intrinsic_inner_cfg_test/crates" \
TRNM_UNCHECKED_GOV_CARGO_ROOT="$intrinsic_inner_cfg_test" \
  "$GUARD" >/dev/null

inner_cfg_near_misses="$TMP_DIR/inner-cfg-near-misses"
make_fixture "$inner_cfg_near_misses"
cat >"$inner_cfg_near_misses/crates/demo/src/cfg_attr_near_miss.rs" <<'RS'
#![cfg_attr(test, cfg(test))]

fn cfg_attr_inner_attribute_is_not_intrinsic(store: &mut crate::Store) {
    store.set_gov_param_bootstrap_unchecked(); // cfg_attr_inner_marker
}
RS
cat >"$inner_cfg_near_misses/crates/demo/src/custom_inner_near_miss.rs" <<'RS'
#![foo::cfg(test)]

fn custom_inner_attribute_is_not_intrinsic(store: &mut crate::Store) {
    store.set_gov_param_bootstrap_unchecked(); // custom_inner_marker
}
RS
set +e
inner_cfg_near_misses_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$inner_cfg_near_misses/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$inner_cfg_near_misses" \
    "$GUARD" 2>&1
)"
inner_cfg_near_misses_rc=$?
set -e
if [[ "$inner_cfg_near_misses_rc" -ne 2 ]] \
  || ! grep -Fq "cfg_attr_inner_marker" <<<"$inner_cfg_near_misses_output" \
  || ! grep -Fq "custom_inner_marker" <<<"$inner_cfg_near_misses_output"; then
  echo "[FAIL] near-miss inner attributes were accepted as exact #![cfg(test)]" >&2
  echo "$inner_cfg_near_misses_output" >&2
  exit 1
fi

detached_nonbuiltin_test_attrs="$TMP_DIR/detached-nonbuiltin-test-attrs"
make_fixture "$detached_nonbuiltin_test_attrs"
cat >"$detached_nonbuiltin_test_attrs/crates/demo/src/detached_nonbuiltin.rs" <<'RS'
#[foo::test]
fn namespaced_attribute_is_not_builtin_test() {
    let mut store = crate::Store;
    store.set_gov_param_bootstrap_unchecked(); // namespaced_test_marker
}

#[cfg_attr(test, test)]
fn cfg_attr_is_not_exact_builtin_test() {
    let mut store = crate::Store;
    store.set_gov_param_bootstrap_unchecked(); // cfg_attr_test_marker
}
RS
set +e
detached_nonbuiltin_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$detached_nonbuiltin_test_attrs/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$detached_nonbuiltin_test_attrs" \
    "$GUARD" 2>&1
)"
detached_nonbuiltin_rc=$?
set -e
if [[ "$detached_nonbuiltin_rc" -ne 2 ]] \
  || ! grep -Fq "namespaced_test_marker" <<<"$detached_nonbuiltin_output" \
  || ! grep -Fq "cfg_attr_test_marker" <<<"$detached_nonbuiltin_output"; then
  echo "[FAIL] non-built-in test-like attributes were accepted as exact #[test]" >&2
  echo "$detached_nonbuiltin_output" >&2
  exit 1
fi

detached_test_with_helper="$TMP_DIR/detached-test-with-helper"
make_fixture "$detached_test_with_helper"
cat >"$detached_test_with_helper/crates/demo/src/detached_mixed.rs" <<'RS'
#[test]
fn exact_builtin_test_call_is_allowed() {
    let mut store = crate::Store;
    store.set_gov_param_bootstrap_unchecked();
}

fn ordinary_helper_must_not_inherit_test_scope(store: &mut crate::Store) {
    store.set_gov_param_bootstrap_unchecked(); // ordinary_helper_marker
}
RS
set +e
detached_test_with_helper_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$detached_test_with_helper/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$detached_test_with_helper" \
    "$GUARD" 2>&1
)"
detached_test_with_helper_rc=$?
set -e
if [[ "$detached_test_with_helper_rc" -ne 2 ]] \
  || ! grep -Fq "ordinary_helper_marker" <<<"$detached_test_with_helper_output"; then
  echo "[FAIL] exact #[test] proof leaked into an ordinary helper in the same detached file" >&2
  echo "$detached_test_with_helper_output" >&2
  exit 1
fi

detached_hidden_definition="$TMP_DIR/detached-hidden-definition"
make_fixture "$detached_hidden_definition"
cat >"$detached_hidden_definition/crates/demo/src/detached_definition.rs" <<'RS'
pub struct DetachedStore;

impl DetachedStore {
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn set_gov_param_bootstrap_unchecked(&mut self) {}
}
RS
TRNM_UNCHECKED_GOV_SCAN_ROOT="$detached_hidden_definition/crates" \
TRNM_UNCHECKED_GOV_CARGO_ROOT="$detached_hidden_definition" \
  "$GUARD" >/dev/null

detached_definition_with_call="$TMP_DIR/detached-definition-with-call"
make_fixture "$detached_definition_with_call"
cat >"$detached_definition_with_call/crates/demo/src/detached_definition_and_call.rs" <<'RS'
pub struct DetachedStore;

impl DetachedStore {
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn set_gov_param_bootstrap_unchecked(&mut self) {}
}

fn ordinary_call_next_to_hidden_definition(store: &mut DetachedStore) {
    store.set_gov_param_bootstrap_unchecked(); // ordinary_call_marker
}
RS
set +e
detached_definition_with_call_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$detached_definition_with_call/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$detached_definition_with_call" \
    "$GUARD" 2>&1
)"
detached_definition_with_call_rc=$?
set -e
if [[ "$detached_definition_with_call_rc" -ne 2 ]] \
  || ! grep -Fq "ordinary_call_marker" <<<"$detached_definition_with_call_output"; then
  echo "[FAIL] hidden test-utils definition exemption leaked to another call in its detached file" >&2
  echo "$detached_definition_with_call_output" >&2
  exit 1
fi

same_line_test_then_production="$TMP_DIR/same-line-test-then-production"
make_fixture "$same_line_test_then_production"
cat >"$same_line_test_then_production/crates/demo/src/same_line_mixed.rs" <<'RS'
#[test] fn allowed_test_call() { let mut store = crate::Store; store.set_gov_param_bootstrap_unchecked(); } fn forbidden_production_call(store: &mut crate::Store) { store.set_gov_param_bootstrap_unchecked(); } // same_line_production_marker
RS
set +e
same_line_test_then_production_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$same_line_test_then_production/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$same_line_test_then_production" \
    "$GUARD" 2>&1
)"
same_line_test_then_production_rc=$?
set -e
if [[ "$same_line_test_then_production_rc" -ne 2 ]] \
  || ! grep -Fq "same_line_production_marker" <<<"$same_line_test_then_production_output"; then
  echo "[FAIL] an allowed #[test] occurrence hid a later production occurrence on the same line" >&2
  echo "$same_line_test_then_production_output" >&2
  exit 1
fi

same_line_definition_then_production="$TMP_DIR/same-line-definition-then-production"
make_fixture "$same_line_definition_then_production"
cat >"$same_line_definition_then_production/crates/demo/src/same_line_definition_and_call.rs" <<'RS'
pub struct SameLineStore; impl SameLineStore { #[cfg(feature = "test-utils")] #[doc(hidden)] pub fn set_gov_param_bootstrap_unchecked(&mut self) {} } fn forbidden_after_definition(store: &mut SameLineStore) { store.set_gov_param_bootstrap_unchecked(); } // same_line_definition_call_marker
RS
set +e
same_line_definition_then_production_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$same_line_definition_then_production/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$same_line_definition_then_production" \
    "$GUARD" 2>&1
)"
same_line_definition_then_production_rc=$?
set -e
if [[ "$same_line_definition_then_production_rc" -ne 2 ]] \
  || ! grep -Fq "same_line_definition_call_marker" <<<"$same_line_definition_then_production_output"; then
  echo "[FAIL] a hidden definition hid a later production occurrence on the same line" >&2
  echo "$same_line_definition_then_production_output" >&2
  exit 1
fi

same_line_hidden_definition="$TMP_DIR/same-line-hidden-definition"
make_fixture "$same_line_hidden_definition"
cat >"$same_line_hidden_definition/crates/demo/src/same_line_hidden_definition.rs" <<'RS'
pub struct SameLineStore;
impl SameLineStore { #[cfg(feature = "test-utils")] #[doc(hidden)] pub fn set_gov_param_bootstrap_unchecked(&mut self) {} }
RS
TRNM_UNCHECKED_GOV_SCAN_ROOT="$same_line_hidden_definition/crates" \
TRNM_UNCHECKED_GOV_CARGO_ROOT="$same_line_hidden_definition" \
  "$GUARD" >/dev/null

detached_definition_attrs="$TMP_DIR/detached-definition-attrs"
make_fixture "$detached_definition_attrs"
cat >"$detached_definition_attrs/crates/demo/src/decoy_same_line.rs" <<'RS'
pub struct SameLineDecoy;
impl SameLineDecoy { #[cfg(feature = "test-utils")] #[doc(hidden)] const DECOY: () = (); pub fn set_gov_param_bootstrap_unchecked(&mut self) {} } // decoy_same_line_marker
RS
cat >"$detached_definition_attrs/crates/demo/src/decoy_following.rs" <<'RS'
pub struct FollowingDecoy;
impl FollowingDecoy {
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    const DECOY: () = ();

    pub fn set_gov_param_bootstrap_unchecked(&mut self) {} // decoy_following_marker
}
RS
set +e
detached_definition_attrs_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$detached_definition_attrs/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$detached_definition_attrs" \
    "$GUARD" 2>&1
)"
detached_definition_attrs_rc=$?
set -e
if [[ "$detached_definition_attrs_rc" -ne 2 ]] \
  || ! grep -Fq "decoy_same_line_marker" <<<"$detached_definition_attrs_output" \
  || ! grep -Fq "decoy_following_marker" <<<"$detached_definition_attrs_output"; then
  echo "[FAIL] attributes attached to a decoy const leaked onto an ungated function definition" >&2
  echo "$detached_definition_attrs_output" >&2
  exit 1
fi

lexical_noise="$TMP_DIR/lexical-noise"
make_fixture "$lexical_noise"
raw_hashes_17="$(printf '%017d' 0 | tr '0' '#')"
raw_hashes_255="$(printf '%0255d' 0 | tr '0' '#')"
{
  cat <<'RS'
// set_gov_param_bootstrap_unchecked in a line comment is not code.
/* set_gov_param_bootstrap_unchecked in a block comment is not code. */
const NORMAL_STRING: &str = "set_gov_param_bootstrap_unchecked";
RS
  printf 'const RAW_STRING_17: &str = r%s"embedded " set_gov_param_bootstrap_unchecked remains raw"%s;\n' \
    "$raw_hashes_17" "$raw_hashes_17"
  printf 'const RAW_STRING_255: &str = r%s"embedded " set_gov_param_bootstrap_unchecked remains raw"%s;\n' \
    "$raw_hashes_255" "$raw_hashes_255"
} >"$lexical_noise/crates/demo/src/lexical_noise.rs"
TRNM_UNCHECKED_GOV_SCAN_ROOT="$lexical_noise/crates" \
TRNM_UNCHECKED_GOV_CARGO_ROOT="$lexical_noise" \
  "$GUARD" >/dev/null

lexical_noise_then_production="$TMP_DIR/lexical-noise-then-production"
make_fixture "$lexical_noise_then_production"
{
  cat <<'RS'
// set_gov_param_bootstrap_unchecked in a line comment is not code.
/* set_gov_param_bootstrap_unchecked in a block comment is not code. */
const NORMAL_STRING: &str = "set_gov_param_bootstrap_unchecked";
RS
  printf 'const RAW_STRING_17: &str = r%s"embedded " set_gov_param_bootstrap_unchecked remains raw"%s;\n' \
    "$raw_hashes_17" "$raw_hashes_17"
  printf 'const RAW_STRING_255: &str = r%s"embedded " set_gov_param_bootstrap_unchecked remains raw"%s;\n' \
    "$raw_hashes_255" "$raw_hashes_255"
  cat <<'RS'
fn forbidden_after_lexical_noise(store: &mut crate::Store) {
    store.set_gov_param_bootstrap_unchecked(); // lexical_noise_followup_marker
}
RS
} >"$lexical_noise_then_production/crates/demo/src/lexical_noise_then_production.rs"
set +e
lexical_noise_then_production_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$lexical_noise_then_production/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$lexical_noise_then_production" \
    "$GUARD" 2>&1
)"
lexical_noise_then_production_rc=$?
set -e
if [[ "$lexical_noise_then_production_rc" -ne 2 ]] \
  || ! grep -Fq "lexical_noise_followup_marker" <<<"$lexical_noise_then_production_output"; then
  echo "[FAIL] comments or 0/17/255-hash strings hid a later production occurrence" >&2
  echo "$lexical_noise_then_production_output" >&2
  exit 1
fi

production="$TMP_DIR/production"
make_fixture "$production"
cat >>"$production/crates/demo/src/lib.rs" <<'RS'

pub fn forbidden_production_call(store: &mut Store) {
    store.set_gov_param_bootstrap_unchecked();
}
RS
set +e
production_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$production/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$production" \
    "$GUARD" 2>&1
)"
production_rc=$?
set -e
if [[ "$production_rc" -ne 2 ]] || ! grep -Fq "disallowed set_gov_param_bootstrap_unchecked production usage" <<<"$production_output"; then
  echo "[FAIL] governance guard did not reject a production unchecked call" >&2
  echo "$production_output" >&2
  exit 1
fi

named_production="$TMP_DIR/named-production"
make_fixture "$named_production"
cat >>"$named_production/crates/demo/src/lib.rs" <<'RS'

mod tests_helpers;
RS
cat >"$named_production/crates/demo/src/tests_helpers.rs" <<'RS'
pub fn forbidden_named_production_call(store: &mut crate::Store) {
    store.set_gov_param_bootstrap_unchecked();
}
RS
set +e
named_production_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$named_production/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$named_production" \
    "$GUARD" 2>&1
)"
named_production_rc=$?
set -e
if [[ "$named_production_rc" -ne 2 ]] || ! grep -Fq "disallowed set_gov_param_bootstrap_unchecked production usage" <<<"$named_production_output"; then
  echo "[FAIL] governance guard trusted a production module solely because its name starts with tests_" >&2
  echo "$named_production_output" >&2
  exit 1
fi

macro_generated="$TMP_DIR/macro-generated"
make_fixture "$macro_generated"
cat >>"$macro_generated/crates/demo/src/lib.rs" <<'RS'

macro_rules! attach_module {
    ($name:ident) => {
        mod $name;
    };
}
attach_module!(generated_production);

// Even an exact cfg(test) edge in a production root must not grant a whole-file
// exemption when a separate macro can attach the same source in production.
#[cfg(test)]
#[path = "generated_production.rs"]
mod generated_production_test_decoy;
RS
cat >"$macro_generated/crates/demo/src/generated_production.rs" <<'RS'
pub fn macro_generated_production_call(store: &mut crate::Store) {
    store.set_gov_param_bootstrap_unchecked(); // macro_generated_marker
}
RS
cat >"$macro_generated/crates/demo/src/detached_decoy.rs" <<'RS'
// This source file is not reachable from any Cargo target. Its cfg(test) edge
// must not be accepted as provenance for another detached source file.
#[cfg(test)]
#[path = "generated_production.rs"]
mod generated_production;
RS
set +e
macro_generated_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$macro_generated/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$macro_generated" \
    "$GUARD" 2>&1
)"
macro_generated_rc=$?
set -e
if [[ "$macro_generated_rc" -ne 2 ]] || ! grep -Fq "macro_generated_marker" <<<"$macro_generated_output"; then
  echo "[FAIL] governance guard silently allowed an unmodelled module edge or detached cfg(test) decoy proof" >&2
  echo "$macro_generated_output" >&2
  exit 1
fi

pathless_bin="$TMP_DIR/pathless-bin"
mkdir -p "$pathless_bin/crates/demo/src"
cat >"$pathless_bin/Cargo.toml" <<'TOML'
[workspace]
members = ["crates/demo"]
resolver = "2"
TOML
cat >"$pathless_bin/crates/demo/Cargo.toml" <<'TOML'
[package]
name = "demo"
version = "0.1.0"
edition = "2021"
autobins = false

[[bin]]
name = "demo"
TOML
cat >"$pathless_bin/crates/demo/src/main.rs" <<'RS'
fn main() {
    let mut store = Store;
    store.set_gov_param_bootstrap_unchecked();
}
RS
set +e
pathless_bin_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$pathless_bin/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$pathless_bin" \
    "$GUARD" 2>&1
)"
pathless_bin_rc=$?
set -e
if [[ "$pathless_bin_rc" -ne 2 ]] \
  || ! grep -Fq "disallowed set_gov_param_bootstrap_unchecked production usage" <<<"$pathless_bin_output" \
  || grep -Fq "unclassified token-bearing Rust file" <<<"$pathless_bin_output"; then
  echo "[FAIL] governance guard did not model autobins=false with a pathless [[bin]] target" >&2
  echo "$pathless_bin_output" >&2
  exit 1
fi

dependency="$TMP_DIR/dependency"
make_fixture "$dependency"
cat >"$dependency/crates/demo/Cargo.toml" <<'TOML'
[package]
name = "demo"
version = "0.1.0"
edition = "2021"

[dependencies]
trnm-state = { path = "../trnm-state", features = ["test-utils"] }
TOML
set +e
dependency_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$dependency/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$dependency" \
    "$GUARD" 2>&1
)"
dependency_rc=$?
set -e
if [[ "$dependency_rc" -ne 2 ]] || ! grep -Fq "must remain dev-dependency-only" <<<"$dependency_output"; then
  echo "[FAIL] governance guard did not reject a production test-utils dependency" >&2
  echo "$dependency_output" >&2
  exit 1
fi

feature_forwarding="$TMP_DIR/feature-forwarding"
make_fixture "$feature_forwarding"
cat >"$feature_forwarding/crates/demo/Cargo.toml" <<'TOML'
[package]
name = "demo"
version = "0.1.0"
edition = "2021"

[dependencies]
state_alias = { package = "trnm-state", path = "../trnm-state", optional = true }

[features]
direct-forward = ["state_alias/test-utils"]
weak-forward = ["state_alias?/test-utils"]
TOML
set +e
feature_forwarding_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$feature_forwarding/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$feature_forwarding" \
    "$GUARD" 2>&1
)"
feature_forwarding_rc=$?
set -e
if [[ "$feature_forwarding_rc" -ne 2 ]] \
  || ! grep -Fq "[features].direct-forward forwards production capability state_alias/test-utils" <<<"$feature_forwarding_output" \
  || ! grep -Fq "[features].weak-forward forwards production capability state_alias?/test-utils" <<<"$feature_forwarding_output"; then
  echo "[FAIL] governance guard did not reject direct and weak production feature forwarding" >&2
  echo "$feature_forwarding_output" >&2
  exit 1
fi

workspace_member_features="$TMP_DIR/workspace-member-features"
mkdir -p "$workspace_member_features/crates/demo/src"
cat >"$workspace_member_features/Cargo.toml" <<'TOML'
[workspace]
members = ["crates/demo"]
resolver = "2"

[workspace.dependencies]
state_alias = { package = "trnm-state", path = "crates/trnm-state" }
TOML
cat >"$workspace_member_features/crates/demo/Cargo.toml" <<'TOML'
[package]
name = "demo"
version = "0.1.0"
edition = "2021"

[dependencies]
state_alias = { workspace = true, features = ["test-utils"] }
TOML
touch "$workspace_member_features/crates/demo/src/lib.rs"
set +e
workspace_member_features_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$workspace_member_features/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$workspace_member_features" \
    "$GUARD" 2>&1
)"
workspace_member_features_rc=$?
set -e
if [[ "$workspace_member_features_rc" -ne 2 ]] \
  || ! grep -Fq "[dependencies] enables trnm-state/test-utils" <<<"$workspace_member_features_output"; then
  echo "[FAIL] member-local features were not merged with the nearest workspace dependency spec" >&2
  echo "$workspace_member_features_output" >&2
  exit 1
fi

nested_workspace_alias="$TMP_DIR/nested-workspace-alias"
mkdir -p \
  "$nested_workspace_alias/crates/outer/src" \
  "$nested_workspace_alias/zz_nested/member/src"
cat >"$nested_workspace_alias/Cargo.toml" <<'TOML'
[workspace]
members = ["crates/outer"]
resolver = "2"

[workspace.dependencies]
state_alias = { package = "trnm-state", path = "crates/trnm-state", optional = true }
TOML
cat >"$nested_workspace_alias/crates/outer/Cargo.toml" <<'TOML'
[package]
name = "outer"
version = "0.1.0"
edition = "2021"

[dependencies]
state_alias = { workspace = true }

[features]
outer-leak = ["state_alias/test-utils"]
TOML
touch "$nested_workspace_alias/crates/outer/src/lib.rs"
cat >"$nested_workspace_alias/zz_nested/Cargo.toml" <<'TOML'
[workspace]
members = ["member"]
resolver = "2"

[workspace.dependencies]
state_alias = { package = "unrelated-state", path = "unrelated-state", optional = true }
TOML
cat >"$nested_workspace_alias/zz_nested/member/Cargo.toml" <<'TOML'
[package]
name = "nested-member"
version = "0.1.0"
edition = "2021"

[dependencies]
state_alias = { workspace = true }
TOML
touch "$nested_workspace_alias/zz_nested/member/src/lib.rs"
set +e
nested_workspace_alias_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$nested_workspace_alias/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$nested_workspace_alias" \
    "$GUARD" 2>&1
)"
nested_workspace_alias_rc=$?
set -e
if [[ "$nested_workspace_alias_rc" -ne 2 ]] \
  || ! grep -Fq "[features].outer-leak forwards production capability state_alias/test-utils" <<<"$nested_workspace_alias_output"; then
  echo "[FAIL] a nested workspace alias overwrote the outer member's nearest workspace dependency" >&2
  echo "$nested_workspace_alias_output" >&2
  exit 1
fi

nested_workspace_isolation="$TMP_DIR/nested-workspace-isolation"
mkdir -p \
  "$nested_workspace_isolation/crates/outer/src" \
  "$nested_workspace_isolation/zz_nested/member/src"
cat >"$nested_workspace_isolation/Cargo.toml" <<'TOML'
[workspace]
members = ["crates/outer"]
resolver = "2"

[workspace.dependencies]
state_alias = { package = "trnm-state", path = "crates/trnm-state" }
TOML
cat >"$nested_workspace_isolation/crates/outer/Cargo.toml" <<'TOML'
[package]
name = "outer"
version = "0.1.0"
edition = "2021"
TOML
touch "$nested_workspace_isolation/crates/outer/src/lib.rs"
cat >"$nested_workspace_isolation/zz_nested/Cargo.toml" <<'TOML'
[workspace]
members = ["member"]
resolver = "2"

[workspace.dependencies]
state_alias = { package = "unrelated-state", path = "unrelated-state" }
TOML
cat >"$nested_workspace_isolation/zz_nested/member/Cargo.toml" <<'TOML'
[package]
name = "nested-member"
version = "0.1.0"
edition = "2021"

[dependencies]
state_alias = { workspace = true, features = ["test-utils"] }
TOML
touch "$nested_workspace_isolation/zz_nested/member/src/lib.rs"
TRNM_UNCHECKED_GOV_SCAN_ROOT="$nested_workspace_isolation/crates" \
TRNM_UNCHECKED_GOV_CARGO_ROOT="$nested_workspace_isolation" \
  "$GUARD" >/dev/null

explicit_outer_workspace="$TMP_DIR/explicit-outer-workspace"
mkdir -p "$explicit_outer_workspace/inner/member/src"
cat >"$explicit_outer_workspace/Cargo.toml" <<'TOML'
[workspace]
members = []
resolver = "2"

[workspace.dependencies]
state_alias = { package = "trnm-state", path = "trnm-state" }
TOML
cat >"$explicit_outer_workspace/inner/Cargo.toml" <<'TOML'
[workspace]
members = []
resolver = "2"

[workspace.dependencies]
state_alias = { package = "unrelated-state", path = "unrelated-state" }
TOML
cat >"$explicit_outer_workspace/inner/member/Cargo.toml" <<'TOML'
[package]
name = "explicit-outer-member"
version = "0.1.0"
edition = "2021"
workspace = "../.."

[dependencies]
state_alias = { workspace = true }

[features]
explicit-outer-leak = ["state_alias/test-utils"]
TOML
touch "$explicit_outer_workspace/inner/member/src/lib.rs"
set +e
explicit_outer_workspace_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$explicit_outer_workspace/inner/member/src" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$explicit_outer_workspace" \
    "$GUARD" 2>&1
)"
explicit_outer_workspace_rc=$?
set -e
if [[ "$explicit_outer_workspace_rc" -ne 2 ]] \
  || ! grep -Fq "[features].explicit-outer-leak forwards production capability state_alias/test-utils" <<<"$explicit_outer_workspace_output"; then
  echo "[FAIL] nearest nested workspace overrode an explicit [package].workspace owner" >&2
  echo "$explicit_outer_workspace_output" >&2
  exit 1
fi

invalid_explicit_workspace="$TMP_DIR/invalid-explicit-workspace"
mkdir -p "$invalid_explicit_workspace/owner/member/src"
cat >"$invalid_explicit_workspace/owner/Cargo.toml" <<'TOML'
[package]
name = "not-a-workspace"
version = "0.1.0"
edition = "2021"
TOML
cat >"$invalid_explicit_workspace/owner/member/Cargo.toml" <<'TOML'
[package]
name = "invalid-explicit-member"
version = "0.1.0"
edition = "2021"
workspace = ".."

[dependencies]
state_alias = { workspace = true }
TOML
touch "$invalid_explicit_workspace/owner/member/src/lib.rs"
set +e
invalid_explicit_workspace_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$invalid_explicit_workspace/owner/member/src" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$invalid_explicit_workspace" \
    "$GUARD" 2>&1
)"
invalid_explicit_workspace_rc=$?
set -e
if [[ "$invalid_explicit_workspace_rc" -ne 2 ]] \
  || ! grep -Fq "[package].workspace does not name a valid [workspace] manifest" <<<"$invalid_explicit_workspace_output"; then
  echo "[FAIL] invalid explicit [package].workspace ownership did not fail closed" >&2
  echo "$invalid_explicit_workspace_output" >&2
  exit 1
fi

dependency_alias_collisions="$TMP_DIR/dependency-alias-collisions"
mkdir -p "$dependency_alias_collisions/crates/demo/src"
cat >"$dependency_alias_collisions/Cargo.toml" <<'TOML'
[workspace]
members = ["crates/demo"]
resolver = "2"
TOML
cat >"$dependency_alias_collisions/crates/demo/Cargo.toml" <<'TOML'
[package]
name = "demo"
version = "0.1.0"
edition = "2021"

[dependencies]
shared = { package = "trnm-state", path = "../trnm-state", optional = true }
build_shared = { package = "unrelated-state", path = "../unrelated-state", optional = true }

[build-dependencies]
shared = { package = "unrelated-state", path = "../unrelated-state" }
build_shared = { package = "trnm-state", path = "../trnm-state" }

[target.'cfg(unix)'.dependencies]
shared = { package = "unrelated-state", path = "../unrelated-state", optional = true }
build_shared = { package = "unrelated-state", path = "../unrelated-state", optional = true }

[features]
root-target-collision = ["shared/test-utils"]
build-target-collision = ["build_shared?/test-utils"]
TOML
touch "$dependency_alias_collisions/crates/demo/src/lib.rs"
set +e
dependency_alias_collisions_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$dependency_alias_collisions/crates" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$dependency_alias_collisions" \
    "$GUARD" 2>&1
)"
dependency_alias_collisions_rc=$?
set -e
if [[ "$dependency_alias_collisions_rc" -ne 2 ]] \
  || ! grep -Fq "[features].root-target-collision forwards production capability shared/test-utils" <<<"$dependency_alias_collisions_output" \
  || ! grep -Fq "[features].build-target-collision forwards production capability build_shared?/test-utils" <<<"$dependency_alias_collisions_output"; then
  echo "[FAIL] root/build/target alias collisions hid a trnm-state mapping" >&2
  echo "$dependency_alias_collisions_output" >&2
  exit 1
fi

self_feature_graph="$TMP_DIR/self-feature-graph"
mkdir -p "$self_feature_graph/src"
cat >"$self_feature_graph/Cargo.toml" <<'TOML'
[package]
name = "trnm-state"
version = "0.1.0"
edition = "2021"

[features]
default = ["chain"]
chain = ["bridge"]
bridge = ["test-utils"]
test-utils = []
TOML
touch "$self_feature_graph/src/lib.rs"
set +e
self_feature_graph_output="$(
  TRNM_UNCHECKED_GOV_SCAN_ROOT="$self_feature_graph/src" \
  TRNM_UNCHECKED_GOV_CARGO_ROOT="$self_feature_graph" \
    "$GUARD" 2>&1
)"
self_feature_graph_rc=$?
set -e
if [[ "$self_feature_graph_rc" -ne 2 ]] \
  || ! grep -Fq "[features].bridge transitively enables the intrinsic test-utils feature" <<<"$self_feature_graph_output" \
  || ! grep -Fq "[features].chain transitively enables the intrinsic test-utils feature" <<<"$self_feature_graph_output" \
  || ! grep -Fq "[features].default transitively enables the intrinsic test-utils feature" <<<"$self_feature_graph_output"; then
  echo "[FAIL] a local trnm-state feature chain exposed test-utils transitively" >&2
  echo "$self_feature_graph_output" >&2
  exit 1
fi

echo "[PASS] governance unchecked-access guard distinguishes exact test-only and production scopes"
