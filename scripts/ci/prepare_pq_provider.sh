#!/usr/bin/env bash
# Build the exact optional-feature provider without changing system OpenSSL.
set -euo pipefail

test "$#" -eq 0 || { printf '%s\n' 'prepare_pq_provider.sh takes no arguments' >&2; exit 2; }
: "${RUNNER_TEMP:?RUNNER_TEMP must be the isolated runner temporary directory}"
: "${GITHUB_ENV:?GITHUB_ENV must be the runner environment file}"
for pq_path in "$RUNNER_TEMP" "$GITHUB_ENV" "${TRNM_CI_RECEIPT_DIR:-$RUNNER_TEMP/ci-observations}"; do
  case "$pq_path" in
    /*) ;;
    *) printf '%s\n' 'PQ provider paths must be absolute' >&2; exit 2 ;;
  esac
  case "$pq_path" in
    *$'\n'*|*$'\r'*) printf '%s\n' 'PQ provider paths must not contain newlines' >&2; exit 2 ;;
  esac
done
test -d "$RUNNER_TEMP"
test -f "$GITHUB_ENV"
test ! -L "$GITHUB_ENV"
pq_jobs="${CARGO_BUILD_JOBS:-2}"
case "$pq_jobs" in [1-8]) ;; *) printf '%s\n' 'PQ provider build jobs must be 1 through 8' >&2; exit 2 ;; esac

readonly openssl_version='3.5.9'
readonly openssl_sha256='603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a'
readonly openssl_url="https://github.com/openssl/openssl/releases/download/openssl-${openssl_version}/openssl-${openssl_version}.tar.gz"
pq_runner_temp="$(cd "$RUNNER_TEMP" && pwd -P)"
pq_build="$(mktemp -d "$pq_runner_temp/trnm-pq-provider-${openssl_version}.XXXXXXXX")"
pq_prefix="$pq_build/install"
pq_archive="$pq_build/openssl-${openssl_version}.tar.gz"
pq_observations="${TRNM_CI_RECEIPT_DIR:-$pq_runner_temp/ci-observations}/pq-provider"
mkdir -p "$(dirname "$pq_observations")"
mkdir "$pq_observations" # A repeated step cannot overwrite an earlier failure.
pq_log="$pq_observations/build-and-smoke.log"
touch "$pq_log"
pq_script_sha256="$(sha256sum "${BASH_SOURCE[0]}" | cut -d ' ' -f 1)"
pq_stage='download'
pq_source_transport='download'
pq_smoke_passed=false
pq_started="$SECONDS"

pq_record_exit() {
  pq_exit="$?"
  trap - EXIT
  set +e
  python3 - "$pq_observations/provider.json" "$pq_exit" "$pq_stage" \
    "$openssl_version" "$openssl_sha256" "$openssl_url" "$pq_build" "$pq_prefix" \
    "$pq_script_sha256" "$pq_smoke_passed" "$((SECONDS - pq_started))" "$pq_source_transport" <<'PY'
import json, os, pathlib, sys
path, code, stage, version, archive_sha, url, build, prefix, script_sha, smoke, elapsed, transport = sys.argv[1:]
payload = {
    "schema": "trnm-ci-pq-provider-v2",
    "result": "PREPARED_AND_SMOKE_VERIFIED" if code == "0" and smoke == "true" else "FAILED",
    "exit_code": int(code), "last_stage": stage,
    "version": version, "source_url": url, "source_archive_sha256_expected": archive_sha,
    "source_transport": transport,
    "source_digest_verified": stage not in ("download", "local-archive-copy", "archive-digest"),
    "preparation_script_sha256": script_sha, "build_directory": build,
    "install_prefix": prefix, "static_build": smoke == "true", "upstream_full_tests_run": False,
    "ml_dsa_65_sign_verify_and_wrong_message_rejection": smoke == "true",
    "elapsed_wall_seconds": int(elapsed),
    "github_actions_reported": os.environ.get("GITHUB_ACTIONS") == "true",
    "runner_environment_reported": os.environ.get("RUNNER_ENVIRONMENT"),
    "native_rust_pq_tests_run_by_preparation": False,
    "whole_chain_quantum_security_qualified": False,
    "production_activation": False,
}
with pathlib.Path(path).open("x") as output:
    json.dump(payload, output, indent=2, sort_keys=True)
    output.write("\n")
PY
  pq_receipt_exit="$?"
  if test "$pq_receipt_exit" -ne 0; then
    printf '%s\n' 'PQ provider receipt could not be written' >&2
    test "$pq_exit" -ne 0 || pq_exit="$pq_receipt_exit"
  fi
  exit "$pq_exit"
}
trap pq_record_exit EXIT

# An explicit offline source avoids another download, never a build or smoke.
# It is copied into the fresh build directory and checked against the same pin.
if test -n "${TRNM_PQ_SOURCE_ARCHIVE:-}"; then
  pq_stage='local-archive-copy'
  pq_source_transport='explicit-local-archive'
  case "$TRNM_PQ_SOURCE_ARCHIVE" in /*) ;; *) exit 2 ;; esac
  test -f "$TRNM_PQ_SOURCE_ARCHIVE"
  test ! -L "$TRNM_PQ_SOURCE_ARCHIVE"
  printf '%s\n' "Copying explicit pinned OpenSSL source; log: $pq_log"
  cp -- "$TRNM_PQ_SOURCE_ARCHIVE" "$pq_archive" >> "$pq_log" 2>&1
else
  printf '%s\n' "Downloading pinned OpenSSL $openssl_version; log: $pq_log"
  curl --fail --location --retry 3 --connect-timeout 20 --max-time 300 \
    --proto '=https' --tlsv1.2 --output "$pq_archive" "$openssl_url" >> "$pq_log" 2>&1
fi
pq_stage='archive-digest'
printf '%s  %s\n' "$openssl_sha256" "$pq_archive" | sha256sum --check --strict >> "$pq_log" 2>&1
pq_stage='extract'
tar --extract --gzip --file "$pq_archive" --directory "$pq_build" >> "$pq_log" 2>&1
pq_stage='configure'
cd "$pq_build/openssl-$openssl_version"
./Configure no-shared no-tests --prefix="$pq_prefix" --openssldir="$pq_prefix/ssl" --libdir=lib >> "$pq_log" 2>&1
pq_stage='build'
make -j "$pq_jobs" >> "$pq_log" 2>&1
pq_stage='install'
make install_sw >> "$pq_log" 2>&1
test -f "$pq_prefix/lib/libcrypto.a"
test -f "$pq_prefix/lib/libssl.a"

# Invoke only the newly installed binary with its built-in default provider.
# These fresh test keys are not emitted in the uploaded observation directory.
pq_stage='ml-dsa-65-smoke'
pq_smoke="$pq_build/smoke"
mkdir "$pq_smoke"
pq_openssl() {
  env OPENSSL_CONF=/dev/null OPENSSL_MODULES="$pq_prefix/lib/ossl-modules" \
    "$pq_prefix/bin/openssl" "$@"
}
pq_version="$(pq_openssl version)"
printf '%s\n' "$pq_version" >> "$pq_log"
case "$pq_version" in "OpenSSL $openssl_version "*) ;; *) exit 1 ;; esac
printf '%s\n' 'Trillionnium CI ML-DSA-65 provider smoke v1' > "$pq_smoke/message"
printf '%s\n' 'Changed Trillionnium CI provider smoke message' > "$pq_smoke/wrong-message"
pq_openssl genpkey -provider default -algorithm ML-DSA-65 -out "$pq_smoke/private.pem" >> "$pq_log" 2>&1
pq_openssl pkey -provider default -in "$pq_smoke/private.pem" -pubout -out "$pq_smoke/public.pem" >> "$pq_log" 2>&1
pq_openssl pkeyutl -provider default -sign -rawin -inkey "$pq_smoke/private.pem" \
  -in "$pq_smoke/message" -out "$pq_smoke/signature.bin" >> "$pq_log" 2>&1
pq_openssl pkeyutl -provider default -verify -rawin -pubin -inkey "$pq_smoke/public.pem" \
  -in "$pq_smoke/message" -sigfile "$pq_smoke/signature.bin" >> "$pq_log" 2>&1
if pq_openssl pkeyutl -provider default -verify -rawin -pubin -inkey "$pq_smoke/public.pem" \
  -in "$pq_smoke/wrong-message" -sigfile "$pq_smoke/signature.bin" >> "$pq_log" 2>&1; then
  printf '%s\n' 'ML-DSA-65 accepted the wrong message' >&2
  exit 1
fi
pq_smoke_passed=true

# Export only after real key generation, signing, verification and rejection.
pq_stage='export'
printf 'OPENSSL_DIR=%s\nOPENSSL_STATIC=1\n' "$pq_prefix" >> "$GITHUB_ENV"
pq_stage='complete'
printf '%s\n' "Prepared isolated static OpenSSL $openssl_version with verified ML-DSA-65"
