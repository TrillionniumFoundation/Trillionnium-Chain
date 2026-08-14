#!/usr/bin/env bash
set -euo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# A continuous, single-validator Chain ceremony for the strict Paper Raid
# Review lane.  The process deliberately separates:
#
#   * the two candidate authority artifacts (consensus app + V4 finalizer),
#   * CometBFT execution infrastructure, and
#   * the legacy-harness CLI used only to create genesis/operator filler txs.
#
# The harness CLI never signs Paper Raid scientific finality.  The Hepta V4
# command is projected and signed only by the candidate finalizer with the
# separately staged Hepta authority key.

usage() {
  cat >&2 <<'EOF'
usage: run_paper_raid_v4_review_chain.sh \
  --root ABSOLUTE_NEW_DIRECTORY \
  --cometbft-bin ABSOLUTE_PATH --expected-cometbft-sha256 sha256:DIGEST \
  --consensus-app-bin ABSOLUTE_PATH --expected-consensus-app-sha256 sha256:DIGEST \
  --finalizer-bin ABSOLUTE_PATH --expected-finalizer-sha256 sha256:DIGEST \
  --harness-cli-bin ABSOLUTE_PATH --expected-harness-cli-sha256 sha256:DIGEST \
  --hepta-private-key ABSOLUTE_PATH --expected-hepta-public-key-hex LOWERCASE_HEX \
  [--rpc-port PORT] [--p2p-port PORT] [--abci-port PORT]

File control protocol under ROOT/control:
  1. Wait for anchor.ready.json. Pin/admit trust-anchor.v1.json before Hepta starts.
  2. Create start-checkpoint.request.json (0600):
       {"schema":"trnm.paper_raid.review-chain-start-checkpoint-request.v1",
        "request_id":"TOKEN"}
     Wait for start-checkpoint.ready.json, then admit its request and arm Hepta.
  3. Create final-checkpoint.request.json (0600):
       {"schema":"trnm.paper_raid.review-chain-final-checkpoint-request.v1",
        "request_id":"TOKEN","start_header_hash_hex":"HEX",
        "minimum_consensus_time_unix_ms":INTEGER}
     The minimum must equal start consensus time + 900000ms. Wait for
     final-checkpoint.ready.json, admit it, and ask Hepta to create preparation.
  4. Write hepta-finality-preparation.v2.json (0600) and then create
     hepta-preparation.request.json (0600):
       {"schema":"trnm.paper_raid.review-chain-hepta-preparation-request.v1",
        "request_id":"TOKEN","preparation_sha256":"sha256:DIGEST"}
     Wait for terminal.ready.json. The process exits only after the V4 command,
     H+1 commitment, evidence collection, and public Receipt V2 verification.
EOF
  exit 2
}

root=
cometbft_bin=
expected_cometbft_sha256=
consensus_app_bin=
expected_consensus_app_sha256=
finalizer_bin=
expected_finalizer_sha256=
harness_cli_bin=
expected_harness_cli_sha256=
hepta_private_key=
expected_hepta_public_key_hex=
rpc_port=27657
p2p_port=27656
abci_port=27658

while (($#)); do
  case "$1" in
    --root) root=${2-}; shift 2 ;;
    --cometbft-bin) cometbft_bin=${2-}; shift 2 ;;
    --expected-cometbft-sha256) expected_cometbft_sha256=${2-}; shift 2 ;;
    --consensus-app-bin) consensus_app_bin=${2-}; shift 2 ;;
    --expected-consensus-app-sha256) expected_consensus_app_sha256=${2-}; shift 2 ;;
    --finalizer-bin) finalizer_bin=${2-}; shift 2 ;;
    --expected-finalizer-sha256) expected_finalizer_sha256=${2-}; shift 2 ;;
    --harness-cli-bin) harness_cli_bin=${2-}; shift 2 ;;
    --expected-harness-cli-sha256) expected_harness_cli_sha256=${2-}; shift 2 ;;
    --hepta-private-key) hepta_private_key=${2-}; shift 2 ;;
    --expected-hepta-public-key-hex) expected_hepta_public_key_hex=${2-}; shift 2 ;;
    --rpc-port) rpc_port=${2-}; shift 2 ;;
    --p2p-port) p2p_port=${2-}; shift 2 ;;
    --abci-port) abci_port=${2-}; shift 2 ;;
    *) usage ;;
  esac
done

digest_pattern='^sha256:[0-9a-f]{64}$'
[[ "$root" = /* && "$root" != / && ! -e "$root" && ! -L "$root" \
  && "$expected_cometbft_sha256" =~ $digest_pattern \
  && "$expected_consensus_app_sha256" =~ $digest_pattern \
  && "$expected_finalizer_sha256" =~ $digest_pattern \
  && "$expected_harness_cli_sha256" =~ $digest_pattern \
  && "$expected_hepta_public_key_hex" =~ ^[0-9a-f]{64}$ ]] || usage
for port in "$rpc_port" "$p2p_port" "$abci_port"; do
  [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1024 && "$port" -le 65535 ]] || usage
done
[[ "$rpc_port" != "$p2p_port" && "$rpc_port" != "$abci_port" \
  && "$p2p_port" != "$abci_port" ]] || usage

require_single_link_file() {
  local path=$1
  local label=$2
  [[ "$path" = /* && -f "$path" && ! -L "$path" \
    && $(stat -c '%F:%h' "$path") == 'regular file:1' ]] || {
    printf 'ERROR: %s must be an absolute regular single-link non-symlink file\n' "$label" >&2
    exit 2
  }
}

verify_digest() {
  local path=$1
  local expected=$2
  local label=$3
  local actual
  actual="sha256:$(sha256sum "$path" | cut -d' ' -f1)"
  [[ "$actual" == "$expected" ]] || {
    printf 'ERROR: %s digest mismatch (expected %s, got %s)\n' \
      "$label" "$expected" "$actual" >&2
    exit 2
  }
}

for artifact in \
  "$cometbft_bin:CometBFT" \
  "$consensus_app_bin:consensus app" \
  "$finalizer_bin:V4 finalizer" \
  "$harness_cli_bin:internal harness CLI" \
  "$hepta_private_key:Hepta authority key"; do
  require_single_link_file "${artifact%%:*}" "${artifact#*:}"
done
[[ -x "$cometbft_bin" && -x "$consensus_app_bin" \
  && -x "$finalizer_bin" && -x "$harness_cli_bin" ]] || {
  echo 'ERROR: staged binaries must be executable' >&2
  exit 2
}
verify_digest "$cometbft_bin" "$expected_cometbft_sha256" CometBFT
verify_digest "$consensus_app_bin" "$expected_consensus_app_sha256" 'consensus app'
verify_digest "$finalizer_bin" "$expected_finalizer_sha256" 'V4 finalizer'
verify_digest "$harness_cli_bin" "$expected_harness_cli_sha256" 'internal harness CLI'

for command in base64 chown curl cut date env find install jq mktemp python3 seq \
  setpriv sha256sum sleep stat; do
  command -v "$command" >/dev/null || {
    printf 'ERROR: required command is unavailable: %s\n' "$command" >&2
    exit 2
  }
done

((EUID == 0)) || {
  echo 'ERROR: review Chain driver must run as root to isolate infrastructure' >&2
  exit 2
}
[[ $(stat -c '%u:%a' "$hepta_private_key") =~ ^0:(400|600)$ ]] || {
  echo 'ERROR: Hepta authority key must be root-owned with exact mode 0400 or 0600' >&2
  exit 2
}

install -d -m 0700 "$root"
install -d -m 0700 "$root/control" "$root/runtime" "$root/evidence"
control=$root/control
driver_runtime=$root/runtime
evidence=$root/evidence
chain_id=trnm-paper-raid-review
root_finalizer_bin=$driver_runtime/trnm-research-receipt-v2
install -m 0500 -- "$finalizer_bin" "$root_finalizer_bin"
require_single_link_file "$root_finalizer_bin" 'root-private V4 finalizer'
[[ $(stat -c '%u:%g:%a' "$root_finalizer_bin") == 0:0:500 ]] || {
  echo 'ERROR: root-private V4 finalizer must be root-owned with mode 0500' >&2
  exit 2
}
verify_digest "$root_finalizer_bin" "$expected_finalizer_sha256" \
  'root-private V4 finalizer'
app_pid=
comet_pid=
infra_sandbox=
infra_sandbox_identity=

remove_infra_sandbox() {
  [[ -n "$infra_sandbox" ]] || return 0
  [[ "$infra_sandbox" =~ ^/tmp/trnm-paper-raid-review-chain-infra\.[A-Za-z0-9]{12}$ ]] || {
    printf 'ERROR: refusing to clean invalid infrastructure sandbox path: %s\n' \
      "$infra_sandbox" >&2
    return 1
  }
  [[ -d "$infra_sandbox" && ! -L "$infra_sandbox" ]] || {
    printf 'ERROR: infrastructure sandbox disappeared or changed type: %s\n' \
      "$infra_sandbox" >&2
    return 1
  }
  [[ $(stat -c '%d:%i:%u:%g' "$infra_sandbox") == "$infra_sandbox_identity" ]] || {
    printf 'ERROR: infrastructure sandbox identity changed: %s\n' \
      "$infra_sandbox" >&2
    return 1
  }
  find "$infra_sandbox" -depth -delete
  [[ ! -e "$infra_sandbox" && ! -L "$infra_sandbox" ]] || {
    printf 'ERROR: infrastructure sandbox cleanup was incomplete: %s\n' \
      "$infra_sandbox" >&2
    return 1
  }
  infra_sandbox=
  infra_sandbox_identity=
}

terminate_pid() {
  local pid=$1
  [[ -n "$pid" ]] || return 0
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 40); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

shutdown_infrastructure() {
  terminate_pid "$comet_pid"
  terminate_pid "$app_pid"
  app_pid=
  comet_pid=
  remove_infra_sandbox
}

cleanup() {
  local status=$?
  local cleanup_status=0
  trap - EXIT INT TERM
  shutdown_infrastructure || cleanup_status=$?
  if [[ "$status" == 0 && "$cleanup_status" != 0 ]]; then
    status=$cleanup_status
  fi
  if [[ "$status" != 0 && ! -e "$control/failed.json" ]]; then
    jq -n --argjson status "$status" \
      '{schema:"trnm.paper_raid.review-chain-failure.v1",status:"failed",exit_code:$status}' \
      >"$control/.failed.json.tmp" || true
    chmod 0600 "$control/.failed.json.tmp" 2>/dev/null || true
    mv -n "$control/.failed.json.tmp" "$control/failed.json" 2>/dev/null || true
  fi
  printf 'TRNM_PAPER_RAID_REVIEW_CHAIN_EXIT status=%s root=%s\n' "$status" "$root" >&2
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
trap 'printf "ERROR: review Chain driver failed at line %s\n" "$LINENO" >&2' ERR

infra_sandbox=$(mktemp -d \
  /tmp/trnm-paper-raid-review-chain-infra.XXXXXXXXXXXX)
[[ "$infra_sandbox" =~ ^/tmp/trnm-paper-raid-review-chain-infra\.[A-Za-z0-9]{12}$ \
  && -d "$infra_sandbox" && ! -L "$infra_sandbox" \
  && $(stat -c '%u:%g:%a' "$infra_sandbox") == 0:0:700 ]] || {
  echo 'ERROR: mktemp did not create the exact root-owned infrastructure sandbox' >&2
  exit 2
}
infra_sandbox_identity=$(stat -c '%d:%i:%u:%g' "$infra_sandbox")
chmod 0711 "$infra_sandbox"
install -d -m 0555 "$infra_sandbox/bin"
harness_uid=65534
harness_gid=65534
comet_uid=65533
comet_gid=65533
app_uid=65532
app_gid=65532
harness_root=$infra_sandbox/harness
comet_root=$infra_sandbox/comet
app_root=$infra_sandbox/app
for role_root in "$harness_root" "$comet_root" "$app_root"; do
  install -d -m 0700 "$role_root" \
    "$role_root/home" "$role_root/tmp" "$role_root/work"
done
chown "$harness_uid:$harness_gid" \
  "$harness_root" "$harness_root/home" "$harness_root/tmp" "$harness_root/work"
chown "$comet_uid:$comet_gid" \
  "$comet_root" "$comet_root/home" "$comet_root/tmp" "$comet_root/work"
chown "$app_uid:$app_gid" \
  "$app_root" "$app_root/home" "$app_root/tmp" "$app_root/work"
harness_work=$harness_root/work
comet_work=$comet_root/work
app_work=$app_root/work
comet_home=$comet_work/node
app_config=$app_work/app.json
app_state=$app_work/app-state.json

infra_cometbft_bin=$infra_sandbox/bin/cometbft
infra_consensus_app_bin=$infra_sandbox/bin/trnm-consensus-app
infra_harness_cli_bin=$infra_sandbox/bin/trnm-chain-cli
install -m 0555 -- "$cometbft_bin" "$infra_cometbft_bin"
install -m 0555 -- "$consensus_app_bin" "$infra_consensus_app_bin"
install -m 0555 -- "$harness_cli_bin" "$infra_harness_cli_bin"
verify_staged_copy() {
  local staged_path=$1
  local staged_expected=$2
  local staged_label=$3
  require_single_link_file "$staged_path" "$staged_label"
  [[ $(stat -c '%u:%g:%a' "$staged_path") == 0:0:555 ]] || {
    printf 'ERROR: %s must be a root-owned immutable-mode staged copy\n' \
      "$staged_label" >&2
    exit 2
  }
  verify_digest "$staged_path" "$staged_expected" "$staged_label"
}
verify_staged_copy "$infra_cometbft_bin" \
  "$expected_cometbft_sha256" 'isolated CometBFT'
verify_staged_copy "$infra_consensus_app_bin" \
  "$expected_consensus_app_sha256" 'isolated consensus app'
verify_staged_copy "$infra_harness_cli_bin" \
  "$expected_harness_cli_sha256" 'isolated harness CLI'

setpriv_bin=$(command -v setpriv)
fd_closing_exec=$(cat <<'PY'
import os
import sys

try:
    os.close_range(3, 2**31 - 1)
except AttributeError:
    for entry in os.listdir("/proc/self/fd"):
        try:
            descriptor = int(entry)
        except ValueError:
            continue
        if descriptor < 3:
            continue
        try:
            os.close(descriptor)
        except OSError:
            pass

os.execvp(sys.argv[1], sys.argv[1:])
PY
)
make_role_exec() {
  local -n output=$1
  local uid=$2
  local gid=$3
  local role_root=$4
  output=(
    env -i
    "HOME=$role_root/home"
    "TMPDIR=$role_root/tmp"
    PATH=/usr/bin:/bin
    LC_ALL=C
    "$setpriv_bin"
    --reuid "$uid"
    --regid "$gid"
    --clear-groups
    --no-new-privs
    --pdeathsig KILL
    --inh-caps=-all
    --ambient-caps=-all
    --bounding-set=-all
    /usr/bin/python3
    -c
    "$fd_closing_exec"
  )
}
make_role_exec harness_exec "$harness_uid" "$harness_gid" "$harness_root"
make_role_exec comet_exec "$comet_uid" "$comet_gid" "$comet_root"
make_role_exec app_exec "$app_uid" "$app_gid" "$app_root"

for role_sentinel in \
  "$harness_root/private.sentinel:$harness_uid:$harness_gid" \
  "$comet_root/private.sentinel:$comet_uid:$comet_gid" \
  "$app_root/private.sentinel:$app_uid:$app_gid"; do
  sentinel_path=${role_sentinel%%:*}
  sentinel_identity=${role_sentinel#*:}
  sentinel_uid=${sentinel_identity%%:*}
  sentinel_gid=${sentinel_identity#*:}
  install -m 0600 /dev/null "$sentinel_path"
  chown "$sentinel_uid:$sentinel_gid" "$sentinel_path"
done

run_role_isolation_probe() {
  local -n role_exec=$1
  local role_name=$2
  local own_root=$3
  local denied_root_one=$4
  local denied_root_two=$5
  "${role_exec[@]}" python3 - "$hepta_private_key" "$role_name" \
    "$own_root" "$denied_root_one" "$denied_root_two" <<'PY'
import json
import os
import sys

status = {}
with open("/proc/self/status", encoding="utf-8") as handle:
    for line in handle:
        key, _, value = line.partition(":")
        if key in {"NoNewPrivs", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}:
            status[key] = value.strip()
def can_open(path, flags):
    try:
        descriptor = os.open(path, flags)
    except PermissionError:
        return False
    else:
        os.close(descriptor)
        return True

def can_create(directory, role_name):
    path = os.path.join(directory, f".{role_name}.write-probe")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except PermissionError:
        return False
    else:
        os.close(descriptor)
        os.unlink(path)
        return True

key_path, role_name, own_root, denied_root_one, denied_root_two = sys.argv[1:]
key_readable = can_open(key_path, os.O_RDONLY)
own_sentinel = os.path.join(own_root, "private.sentinel")
denied_sentinels = [
    os.path.join(denied_root_one, "private.sentinel"),
    os.path.join(denied_root_two, "private.sentinel"),
]

extra_open_fds = {}
for entry in os.listdir("/proc/self/fd"):
    descriptor = int(entry)
    if descriptor < 3:
        continue
    try:
        target = os.readlink(f"/proc/self/fd/{descriptor}")
    except FileNotFoundError:
        # The directory descriptor used by listdir() is already closed.
        continue
    extra_open_fds[str(descriptor)] = target
print(json.dumps({
    "role": role_name,
    "uid": os.getuid(), "euid": os.geteuid(),
    "gid": os.getgid(), "egid": os.getegid(),
    "groups": os.getgroups(), "status": status,
    "hepta_key_readable": key_readable,
    "extra_open_fds": extra_open_fds,
    "own_root": {
        "read_existing": can_open(own_sentinel, os.O_RDONLY),
        "write_existing": can_open(own_sentinel, os.O_WRONLY),
        "create_and_remove": can_create(own_root, role_name),
    },
    "denied_roots": [{
        "read_existing": can_open(path, os.O_RDONLY),
        "write_existing": can_open(path, os.O_WRONLY),
        "create": can_create(os.path.dirname(path), role_name),
    } for path in denied_sentinels],
}, sort_keys=True, separators=(",", ":")))
PY
}
harness_isolation_probe=$(run_role_isolation_probe harness_exec harness \
  "$harness_root" "$comet_root" "$app_root")
comet_isolation_probe=$(run_role_isolation_probe comet_exec comet \
  "$comet_root" "$harness_root" "$app_root")
app_isolation_probe=$(run_role_isolation_probe app_exec app \
  "$app_root" "$harness_root" "$comet_root")

verify_role_isolation_probe() {
  local probe=$1
  local role=$2
  local uid=$3
  local gid=$4
  printf '%s\n' "$probe" | jq -e \
    --arg role "$role" --argjson uid "$uid" --argjson gid "$gid" '
  .role == $role
  and .uid == $uid and .euid == $uid
  and .gid == $gid and .egid == $gid and .groups == []
  and .status.NoNewPrivs == "1"
  and .status.CapInh == "0000000000000000"
  and .status.CapPrm == "0000000000000000"
  and .status.CapEff == "0000000000000000"
  and .status.CapBnd == "0000000000000000"
  and .status.CapAmb == "0000000000000000"
  and .hepta_key_readable == false
  and .extra_open_fds == {}
  and .own_root == {read_existing:true,write_existing:true,create_and_remove:true}
  and (.denied_roots | length == 2)
  and all(.denied_roots[];
    . == {read_existing:false,write_existing:false,create:false})
' >/dev/null || {
    printf 'ERROR: %s isolation probe did not prove the exact boundary\n' \
      "$role" >&2
    exit 2
  }
}
verify_role_isolation_probe "$harness_isolation_probe" harness \
  "$harness_uid" "$harness_gid"
verify_role_isolation_probe "$comet_isolation_probe" comet \
  "$comet_uid" "$comet_gid"
verify_role_isolation_probe "$app_isolation_probe" app \
  "$app_uid" "$app_gid"

jq -S -n \
  --argjson harness_probe "$harness_isolation_probe" \
  --argjson comet_probe "$comet_isolation_probe" \
  --argjson app_probe "$app_isolation_probe" \
  --arg cometbft_sha256 "$expected_cometbft_sha256" \
  --arg consensus_app_sha256 "$expected_consensus_app_sha256" \
  --arg harness_cli_sha256 "$expected_harness_cli_sha256" '
  {
    schema:"trnm.paper_raid.review-chain-infrastructure-isolation.v1",
    status:"verified_before_execution",
    role_probes:{harness:$harness_probe,cometbft:$comet_probe,app:$app_probe},
    sandbox:{parent:"/tmp",ephemeral:true,root_owner_uid:0,
      roles:{
        harness:{uid:65534,gid:65534,private_root:true},
        cometbft:{uid:65533,gid:65533,private_root:true},
        app:{uid:65532,gid:65532,private_root:true}
      },supplementary_groups:[],no_new_privileges:true,
      capability_sets:"empty",cross_role_read_write:"denied"},
    staged_execution_artifacts:{
      cometbft:{sha256:$cometbft_sha256},
      consensus_app:{sha256:$consensus_app_sha256},
      internal_harness_cli:{sha256:$harness_cli_sha256}
    },
    hepta_signing_key:{root_only:true,readable_by_execution_roles:false},
    candidate_finalizer:{runs_as_root:true,staged_into_infrastructure:false}
  }' >"$evidence/infrastructure-isolation.json"
chmod 0600 "$evidence/infrastructure-isolation.json"

public_key_result="$($root_finalizer_bin public-key "$hepta_private_key")"
hepta_public_key_hex=$(printf '%s' "$public_key_result" | jq -er .public_key_hex)
[[ "$hepta_public_key_hex" == "$expected_hepta_public_key_hex" ]] || {
  echo 'ERROR: Hepta authority key does not match the pinned public key' >&2
  exit 2
}

harness_operator_key=$harness_work/operator.key
harness_nakama_key=$harness_work/nakama.key
operator_key_result="$("${harness_exec[@]}" "$infra_harness_cli_bin" \
  keygen --output "$harness_operator_key")"
operator_public_key_hex=$(printf '%s' "$operator_key_result" | jq -er .public_key_hex)
nakama_key_result="$("${harness_exec[@]}" "$infra_harness_cli_bin" \
  keygen --output "$harness_nakama_key")"
nakama_public_key_hex=$(printf '%s' "$nakama_key_result" | jq -er .public_key_hex)
for generated_key in "$harness_operator_key" "$harness_nakama_key"; do
  require_single_link_file "$generated_key" 'isolated harness private key'
  [[ $(stat -c '%u:%g:%a' "$generated_key") \
    == "$harness_uid:$harness_gid:600" ]] || {
    echo 'ERROR: isolated harness private key has the wrong owner or mode' >&2
    exit 2
  }
done
nakama_public_key_bytes=$(python3 - "$nakama_public_key_hex" <<'PY'
import json
import sys
value = bytes.fromhex(sys.argv[1])
if len(value) != 32:
    raise SystemExit("Nakama public key must be 32 bytes")
print(json.dumps(list(value), separators=(",", ":")))
PY
)
hepta_public_key_bytes=$(python3 - "$hepta_public_key_hex" <<'PY'
import json
import sys
value = bytes.fromhex(sys.argv[1])
if len(value) != 32:
    raise SystemExit("Hepta public key must be 32 bytes")
print(json.dumps(list(value), separators=(",", ":")))
PY
)

jq -n \
  --arg public_key "$operator_public_key_hex" \
  --arg nakama_public_key "$nakama_public_key_hex" \
  --arg hepta_public_key "$hepta_public_key_hex" \
  --arg state_path "$app_state" '
  {
    schema:"trnm_cometbft_app_config_v1",
    chain_id:"trnm-paper-raid-review",
    authorized_signers:[
      {signer_id:"did:operator:paper-raid-review",signer_role:"operator",public_key_hex:$public_key},
      {signer_id:"did:trnm:nakama-authority",signer_role:"nakama",public_key_hex:$nakama_public_key},
      {signer_id:"did:trnm:hepta-authority",signer_role:"hepta",public_key_hex:$hepta_public_key}
    ],
    state_path:$state_path
  }' >"$app_config"
chmod 0600 "$app_config"
chown "$app_uid:$app_gid" "$app_config"

"${comet_exec[@]}" "$infra_cometbft_bin" \
  init --home "$comet_home" >/dev/null
initial_validators=$(python3 - "$comet_home/config/genesis.json" <<'PY'
import base64
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    validators = json.load(handle)["validators"]
result = [{
    "public_key_hex": base64.b64decode(value["pub_key"]["value"]).hex(),
    "voting_power": int(value["power"]),
} for value in validators]
result.sort(key=lambda value: value["public_key_hex"])
print(json.dumps(result, separators=(",", ":")))
PY
)
jq \
  --arg operator_public_key "$operator_public_key_hex" \
  --arg nakama_public_key "$nakama_public_key_hex" \
  --arg hepta_public_key "$hepta_public_key_hex" \
  --argjson nakama_public_key_bytes "$nakama_public_key_bytes" \
  --argjson hepta_public_key_bytes "$hepta_public_key_bytes" \
  --argjson initial_validators "$initial_validators" '
  .chain_id="trnm-paper-raid-review"
  | .consensus_params.version.app="7"
  | .app_state={
      schema:"trnm_cometbft_genesis_v3",
      chain_id:"trnm-paper-raid-review",
      app_version:7,
      authorized_signers:[
        {signer_id:"did:operator:paper-raid-review",signer_role:"operator",public_key_hex:$operator_public_key},
        {signer_id:"did:trnm:nakama-authority",signer_role:"nakama",public_key_hex:$nakama_public_key},
        {signer_id:"did:trnm:hepta-authority",signer_role:"hepta",public_key_hex:$hepta_public_key}
      ],
      research_authorities:{
        nakama_authorities:[{signer_did:"did:trnm:nakama-authority",public_key:$nakama_public_key_bytes}],
        hepta_authorities:[{signer_did:"did:trnm:hepta-authority",public_key:$hepta_public_key_bytes}]
      },
      validator_governance:{
        schema:"trnm_validator_governance_v1",
        signer_id:"did:operator:paper-raid-review",
        min_activation_delay_blocks:2,
        unsafe_allow_single_validator_genesis:true
      },
      initial_validators:$initial_validators
    }' "$comet_home/config/genesis.json" >"$driver_runtime/genesis.json"
install -m 0600 "$driver_runtime/genesis.json" \
  "$comet_home/config/genesis.json"
chown "$comet_uid:$comet_gid" "$comet_home/config/genesis.json"

create_operator_credit_tx() {
  local nonce=$1
  local account=$2
  local amount=$3
  local payload=$harness_work/operator-payload-$nonce.json
  local output=$harness_work/operator-tx-$nonce.json
  local root_copy=$driver_runtime/operator-tx-$nonce.json
  local output_sha256
  jq -n \
    --arg account "$account" \
    --argjson nonce "$nonce" \
    --argjson amount "$amount" '
      {schema:"trnm_canonical_tx_v1",sender:"did:operator:paper-raid-review",
       nonce:$nonce,max_gas:100000,fee_limit:"100000",
       command:{type:"credit_account",account:$account,amount:($amount|tostring)}}' >"$payload"
  chmod 0600 "$payload"
  chown "$harness_uid:$harness_gid" "$payload"
  "${harness_exec[@]}" "$infra_harness_cli_bin" sign \
    --private-key "$harness_operator_key" \
    --chain-id "$chain_id" \
    --command-id "paper-raid-review-harness-$nonce" \
    --signer-id did:operator:paper-raid-review \
    --signer-role operator \
    --nonce "$nonce" \
    --payload-type trnm.canonical.tx.v1 \
    --payload-file "$payload" \
    --output "$output" >/dev/null
  require_single_link_file "$output" 'isolated harness transaction'
  [[ $(stat -c '%u:%g:%a' "$output") == "$harness_uid:$harness_gid:600" ]] || {
    echo 'ERROR: isolated harness transaction has the wrong owner or mode' >&2
    exit 2
  }
  output_sha256="sha256:$(sha256sum "$output" | cut -d' ' -f1)"
  install -m 0400 "$output" "$root_copy"
  [[ $(stat -c '%u:%g:%a' "$root_copy") == 0:0:400 ]] || {
    echo 'ERROR: root-mediated harness transaction copy is not root-only 0400' >&2
    exit 2
  }
  verify_digest "$root_copy" "$output_sha256" \
    'root-mediated immutable harness transaction copy'
}

create_operator_credit_tx 1 did:trnm:hepta-authority 1000000
create_operator_credit_tx 2 fixture:paper-raid-review:start 1
create_operator_credit_tx 3 fixture:paper-raid-review:final 1

run_role_asset_probe() {
  local -n role_exec=$1
  local role_name=$2
  local own_asset=$3
  local denied_asset_one=$4
  local denied_asset_two=$5
  "${role_exec[@]}" python3 - "$role_name" "$own_asset" \
    "$denied_asset_one" "$denied_asset_two" <<'PY'
import json
import os
import sys

def can_open(path, flags):
    try:
        descriptor = os.open(path, flags)
    except PermissionError:
        return False
    else:
        os.close(descriptor)
        return True

role, own_asset, denied_asset_one, denied_asset_two = sys.argv[1:]
print(json.dumps({
    "role": role,
    "own_asset": {
        "read": can_open(own_asset, os.O_RDONLY),
        "write": can_open(own_asset, os.O_WRONLY),
    },
    "denied_assets": [{
        "read": can_open(path, os.O_RDONLY),
        "write": can_open(path, os.O_WRONLY),
    } for path in (denied_asset_one, denied_asset_two)],
}, sort_keys=True, separators=(",", ":")))
PY
}
harness_asset_probe=$(run_role_asset_probe harness_exec harness \
  "$harness_operator_key" "$comet_home/config/genesis.json" "$app_config")
comet_asset_probe=$(run_role_asset_probe comet_exec cometbft \
  "$comet_home/config/genesis.json" "$harness_operator_key" "$app_config")
app_asset_probe=$(run_role_asset_probe app_exec app \
  "$app_config" "$harness_operator_key" "$comet_home/config/genesis.json")
for asset_probe in \
  "$harness_asset_probe" "$comet_asset_probe" "$app_asset_probe"; do
  printf '%s\n' "$asset_probe" | jq -e '
    .own_asset == {read:true,write:true}
    and (.denied_assets | length == 2)
    and all(.denied_assets[]; . == {read:false,write:false})
  ' >/dev/null || {
    echo 'ERROR: role asset read/write denial probe failed' >&2
    exit 2
  }
done
operator_tx_1_sha256="sha256:$(sha256sum \
  "$driver_runtime/operator-tx-1.json" | cut -d' ' -f1)"
operator_tx_2_sha256="sha256:$(sha256sum \
  "$driver_runtime/operator-tx-2.json" | cut -d' ' -f1)"
operator_tx_3_sha256="sha256:$(sha256sum \
  "$driver_runtime/operator-tx-3.json" | cut -d' ' -f1)"
jq -S \
  --argjson harness_asset_probe "$harness_asset_probe" \
  --argjson comet_asset_probe "$comet_asset_probe" \
  --argjson app_asset_probe "$app_asset_probe" \
  --arg operator_tx_1_sha256 "$operator_tx_1_sha256" \
  --arg operator_tx_2_sha256 "$operator_tx_2_sha256" \
  --arg operator_tx_3_sha256 "$operator_tx_3_sha256" '
  .asset_denial_probes = {
    harness:$harness_asset_probe,cometbft:$comet_asset_probe,app:$app_asset_probe
  }
  | .root_mediated_transfers = {
      harness_transactions:{mode:"0400",owner_uid:0,
        tx_1_sha256:$operator_tx_1_sha256,
        tx_2_sha256:$operator_tx_2_sha256,
        tx_3_sha256:$operator_tx_3_sha256}
    }
  | .abci_boundary = {transport:"tcp",address_family:"ipv4_loopback",
      shared_files_between_app_and_cometbft:false}
' "$evidence/infrastructure-isolation.json" \
  >"$evidence/.infrastructure-isolation.json.tmp"
chmod 0600 "$evidence/.infrastructure-isolation.json.tmp"
mv "$evidence/.infrastructure-isolation.json.tmp" \
  "$evidence/infrastructure-isolation.json"

jq -S -n \
  --arg consensus_app_sha256 "$expected_consensus_app_sha256" \
  --arg finalizer_sha256 "$expected_finalizer_sha256" \
  --arg cometbft_sha256 "$expected_cometbft_sha256" \
  --arg harness_cli_sha256 "$expected_harness_cli_sha256" '
  {
    schema:"trnm.paper_raid.review-chain-artifact-classification.v1",
    candidate_authority_artifacts:{
      consensus_app:{sha256:$consensus_app_sha256,role:"consensus_state_transition_authority"},
      receipt_v4:{sha256:$finalizer_sha256,role:"hepta_v4_projection_signing_and_receipt_verification"}
    },
    execution_infrastructure:{
      cometbft:{sha256:$cometbft_sha256,authority_artifact:false}
    },
    internal_harness:{
      chain_cli:{sha256:$harness_cli_sha256,
        purpose:"genesis_key_generation_and_operator_filler_transactions_only",
        authority_artifact:false,scientific_finality_signer:false}
    }
  }' >"$evidence/artifact-classification.json"
chmod 0600 "$evidence/artifact-classification.json"

"${app_exec[@]}" "$infra_consensus_app_bin" \
  --config "$app_config" \
  --listen-addr "127.0.0.1:$abci_port" >"$driver_runtime/app.log" 2>&1 &
app_pid=$!
"${comet_exec[@]}" "$infra_cometbft_bin" start \
  --home "$comet_home" \
  --proxy_app "tcp://127.0.0.1:$abci_port" \
  --rpc.laddr "tcp://127.0.0.1:$rpc_port" \
  --p2p.laddr "tcp://127.0.0.1:$p2p_port" \
  --consensus.create_empty_blocks=false >"$driver_runtime/comet.log" 2>&1 &
comet_pid=$!

for _ in $(seq 1 240); do
  curl -fsS "http://127.0.0.1:$rpc_port/status" >/dev/null 2>&1 && break
  kill -0 "$app_pid" 2>/dev/null && kill -0 "$comet_pid" 2>/dev/null || {
    echo 'ERROR: Chain process exited before RPC readiness' >&2
    exit 1
  }
  sleep 0.25
done
curl -fsS "http://127.0.0.1:$rpc_port/status" >/dev/null

broadcast_commit() {
  local tx_file=$1
  local tx_b64
  tx_b64=$(base64 -w0 "$tx_file")
  curl -fsS -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"broadcast_tx_commit\",\"params\":{\"tx\":\"$tx_b64\"}}" \
    "http://127.0.0.1:$rpc_port"
}

assert_committed() {
  local response=$1
  [[ $(printf '%s' "$response" | jq -er '.result.check_tx.code') == 0 \
    && $(printf '%s' "$response" | jq -er '.result.tx_result.code') == 0 \
    && $(printf '%s' "$response" | jq -er '.result.height | tonumber > 0') == true ]] || {
    printf 'ERROR: transaction did not commit successfully\n%s\n' "$response" >&2
    exit 1
  }
}

rpc_get() {
  local endpoint=$1
  local output=$2
  curl -fsS "http://127.0.0.1:$rpc_port/$endpoint" >"$output"
  jq -e '.error == null and .result != null' "$output" >/dev/null
  chmod 0600 "$output"
}

wait_control_file() {
  local path=$1
  local label=$2
  while [[ ! -e "$path" ]]; do
    kill -0 "$app_pid" 2>/dev/null && kill -0 "$comet_pid" 2>/dev/null || {
      printf 'ERROR: Chain process exited while waiting for %s\n' "$label" >&2
      exit 1
    }
    sleep 0.2
  done
  require_single_link_file "$path" "$label"
  [[ $(stat -c '%a' "$path") == 600 ]] || {
    printf 'ERROR: %s must have mode 0600\n' "$label" >&2
    exit 2
  }
}

publish_ready() {
  local tmp=$1
  local output=$2
  chmod 0600 "$tmp"
  mv -n "$tmp" "$output"
  [[ -f "$output" && ! -e "$tmp" ]] || {
    printf 'ERROR: ready output already exists: %s\n' "$output" >&2
    exit 1
  }
}

# Height 1 exists solely to establish the externally pinned trust root. The
# corresponding operator transaction credits the Hepta authority account but
# carries no scientific-finality assertion.
credit_response=$(broadcast_commit "$driver_runtime/operator-tx-1.json")
assert_committed "$credit_response"
[[ $(printf '%s' "$credit_response" | jq -er .result.height) == 1 ]] || {
  echo 'ERROR: the genesis credit transaction did not commit at height 1' >&2
  exit 1
}
rpc_get 'block?height=1' "$evidence/anchor-block.json"
# The trust anchor binds header H and the validator set for H+1. CometBFT
# creates that canonical commitment block after the height-1 transaction even
# when ordinary empty-block production is disabled.
for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:$rpc_port/block?height=2" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -fsS "http://127.0.0.1:$rpc_port/block?height=2" >/dev/null || {
  echo 'ERROR: CometBFT did not create the height-2 anchor commitment block' >&2
  exit 1
}
rpc_get 'validators?height=2&per_page=100' "$evidence/anchor-next-validators.json"
anchor_header_hash_hex=$(jq -er '.result.block_id.hash | ascii_downcase' \
  "$evidence/anchor-block.json")
anchor_result="$($root_finalizer_bin trust-anchor-from-rpc \
  "$evidence/anchor-block.json" \
  "$evidence/anchor-next-validators.json" \
  "$anchor_header_hash_hex" \
  "$evidence/trust-anchor.v1.json")"
trust_anchor_hash_hex=$(printf '%s' "$anchor_result" | jq -er .trust_anchor_hash_hex)
jq -S -n \
  --arg trust_anchor_hash_hex "$trust_anchor_hash_hex" \
  --arg anchor_header_hash_hex "$anchor_header_hash_hex" \
  --arg trust_anchor_path "$evidence/trust-anchor.v1.json" \
  --arg artifact_classification_path "$evidence/artifact-classification.json" \
  --arg consensus_app_sha256 "$expected_consensus_app_sha256" \
  --arg finalizer_sha256 "$expected_finalizer_sha256" \
  --arg harness_cli_sha256 "$expected_harness_cli_sha256" '
  {
    schema:"trnm.paper_raid.review-chain-anchor-ready.v1",status:"anchor_ready",
    chain_id:"trnm-paper-raid-review",trusted_height:1,
    trust_anchor_hash_hex:$trust_anchor_hash_hex,
    trusted_header_hash_hex:$anchor_header_hash_hex,
    trust_anchor_path:$trust_anchor_path,
    artifact_classification_path:$artifact_classification_path,
    candidate_authority_artifacts:{consensus_app_sha256:$consensus_app_sha256,
      receipt_v4_sha256:$finalizer_sha256},
    internal_harness_cli_sha256:$harness_cli_sha256
  }' >"$control/.anchor.ready.json.tmp"
publish_ready "$control/.anchor.ready.json.tmp" "$control/anchor.ready.json"

wait_control_file "$control/start-checkpoint.request.json" 'start-checkpoint request'
jq -e '
  keys == ["request_id","schema"]
  and .schema == "trnm.paper_raid.review-chain-start-checkpoint-request.v1"
  and (.request_id | type == "string" and test("^[A-Za-z0-9._:-]{1,128}$"))
' "$control/start-checkpoint.request.json" >/dev/null || {
  echo 'ERROR: invalid start-checkpoint request' >&2
  exit 2
}
start_request_id=$(jq -er .request_id "$control/start-checkpoint.request.json")
start_response=$(broadcast_commit "$driver_runtime/operator-tx-2.json")
assert_committed "$start_response"
start_monotonic_ns=$(python3 - <<'PY'
import time
print(time.monotonic_ns())
PY
)
start_height=$(printf '%s' "$start_response" | jq -er '.result.height | tonumber')
((start_height > 1)) || {
  echo 'ERROR: start checkpoint height did not advance beyond the trust anchor' >&2
  exit 1
}
rpc_get "block?height=$start_height" "$evidence/start-block.json"
rpc_get "commit?height=$start_height" "$evidence/start-commit.json"
rpc_get "validators?height=$start_height&per_page=100" "$evidence/start-validators.json"
start_proof_result="$($root_finalizer_bin chain-time-proof-from-rpc \
  "$evidence/start-block.json" "$evidence/start-commit.json" \
  "$evidence/start-validators.json" "$evidence/trust-anchor.v1.json" \
  "$evidence/start-checkpoint-admission.v1.json")"
start_header_hash_hex=$(printf '%s' "$start_proof_result" | jq -er .header_hash_hex)
start_consensus_time_unix_ms=$(printf '%s' "$start_proof_result" \
  | jq -er '.consensus_time_unix_ms | tostring')
minimum_final_consensus_time_unix_ms=$((start_consensus_time_unix_ms + 900000))
jq -S -n \
  --arg request_id "$start_request_id" \
  --arg trust_anchor_hash_hex "$trust_anchor_hash_hex" \
  --arg header_hash_hex "$start_header_hash_hex" \
  --arg checkpoint_request_path "$evidence/start-checkpoint-admission.v1.json" \
  --argjson consensus_time_unix_ms "$start_consensus_time_unix_ms" \
  --argjson minimum_final_consensus_time_unix_ms "$minimum_final_consensus_time_unix_ms" \
  --argjson height "$start_height" '
  {
    schema:"trnm.paper_raid.review-chain-start-checkpoint-ready.v1",
    status:"start_checkpoint_ready",request_id:$request_id,
    chain_id:"trnm-paper-raid-review",height:$height,
    trust_anchor_hash_hex:$trust_anchor_hash_hex,header_hash_hex:$header_hash_hex,
    consensus_time_unix_ms:$consensus_time_unix_ms,
    minimum_final_consensus_time_unix_ms:$minimum_final_consensus_time_unix_ms,
    checkpoint_request_path:$checkpoint_request_path
  }' >"$control/.start-checkpoint.ready.json.tmp"
publish_ready "$control/.start-checkpoint.ready.json.tmp" \
  "$control/start-checkpoint.ready.json"

wait_control_file "$control/final-checkpoint.request.json" 'final-checkpoint request'
jq -e \
  --arg start_header_hash_hex "$start_header_hash_hex" \
  --argjson minimum "$minimum_final_consensus_time_unix_ms" '
  keys == ["minimum_consensus_time_unix_ms","request_id","schema","start_header_hash_hex"]
  and .schema == "trnm.paper_raid.review-chain-final-checkpoint-request.v1"
  and (.request_id | type == "string" and test("^[A-Za-z0-9._:-]{1,128}$"))
  and .start_header_hash_hex == $start_header_hash_hex
  and .minimum_consensus_time_unix_ms == $minimum
' "$control/final-checkpoint.request.json" >/dev/null || {
  echo 'ERROR: invalid final-checkpoint request' >&2
  exit 2
}
final_request_id=$(jq -er .request_id "$control/final-checkpoint.request.json")
# No fake clock shortcut: require both the wall-clock threshold used by
# CometBFT and at least 900000ms on the host monotonic clock after the start
# block committed. A forward wall-clock adjustment therefore cannot shorten
# the real continuously-running wait.
python3 - "$start_monotonic_ns" "$minimum_final_consensus_time_unix_ms" \
  "$app_pid" "$comet_pid" <<'PY'
import os
import sys
import time

start_monotonic_ns = int(sys.argv[1])
minimum_wall_time_ms = int(sys.argv[2]) + 1000
pids = [int(value) for value in sys.argv[3:]]
minimum_monotonic_ns = start_monotonic_ns + 900_000_000_000
while (
    time.monotonic_ns() < minimum_monotonic_ns
    or time.time_ns() // 1_000_000 < minimum_wall_time_ms
):
    for pid in pids:
        try:
            os.kill(pid, 0)
        except OSError as error:
            raise SystemExit(
                "ERROR: Chain process exited during the 15-minute "
                "consensus-time wait"
            ) from error
    time.sleep(1)
PY
final_response=$(broadcast_commit "$driver_runtime/operator-tx-3.json")
assert_committed "$final_response"
final_height=$(printf '%s' "$final_response" | jq -er '.result.height | tonumber')
((final_height > start_height)) || {
  echo 'ERROR: final checkpoint height did not advance beyond the start checkpoint' >&2
  exit 1
}
rpc_get "block?height=$final_height" "$evidence/final-block.json"
rpc_get "commit?height=$final_height" "$evidence/final-commit.json"
rpc_get "validators?height=$final_height&per_page=100" "$evidence/final-validators.json"
final_proof_result="$($root_finalizer_bin chain-time-proof-from-rpc \
  "$evidence/final-block.json" "$evidence/final-commit.json" \
  "$evidence/final-validators.json" "$evidence/trust-anchor.v1.json" \
  "$evidence/final-checkpoint-admission.v1.json")"
final_header_hash_hex=$(printf '%s' "$final_proof_result" | jq -er .header_hash_hex)
final_consensus_time_unix_ms=$(printf '%s' "$final_proof_result" \
  | jq -er '.consensus_time_unix_ms | tostring')
((final_consensus_time_unix_ms >= minimum_final_consensus_time_unix_ms)) || {
  echo 'ERROR: final BFT timestamp did not reach the immutable 15-minute boundary' >&2
  exit 1
}
consensus_time_delta_ms=$((final_consensus_time_unix_ms - start_consensus_time_unix_ms))
((consensus_time_delta_ms >= 900000)) || {
  echo 'ERROR: final consensus-time delta is below the immutable 15-minute boundary' >&2
  exit 1
}
final_monotonic_ns=$(python3 - <<'PY'
import time
print(time.monotonic_ns())
PY
)
monotonic_elapsed_ms=$(((final_monotonic_ns - start_monotonic_ns) / 1000000))
((monotonic_elapsed_ms >= 900000)) || {
  echo 'ERROR: measured monotonic elapsed time is below 900000ms' >&2
  exit 1
}
jq -S -n \
  --arg request_id "$final_request_id" \
  --arg trust_anchor_hash_hex "$trust_anchor_hash_hex" \
  --arg header_hash_hex "$final_header_hash_hex" \
  --arg checkpoint_request_path "$evidence/final-checkpoint-admission.v1.json" \
  --argjson consensus_time_unix_ms "$final_consensus_time_unix_ms" \
  --argjson consensus_time_delta_ms "$consensus_time_delta_ms" \
  --argjson monotonic_elapsed_ms "$monotonic_elapsed_ms" \
  --argjson height "$final_height" '
  {
    schema:"trnm.paper_raid.review-chain-final-checkpoint-ready.v1",
    status:"final_checkpoint_ready",request_id:$request_id,
    chain_id:"trnm-paper-raid-review",height:$height,
    trust_anchor_hash_hex:$trust_anchor_hash_hex,header_hash_hex:$header_hash_hex,
    consensus_time_unix_ms:$consensus_time_unix_ms,
    consensus_time_delta_ms:$consensus_time_delta_ms,
    monotonic_elapsed_ms:$monotonic_elapsed_ms,
    required_minimum_delta_ms:900000,
    checkpoint_request_path:$checkpoint_request_path
  }' >"$control/.final-checkpoint.ready.json.tmp"
publish_ready "$control/.final-checkpoint.ready.json.tmp" \
  "$control/final-checkpoint.ready.json"

wait_control_file "$control/hepta-finality-preparation.v2.json" \
  'Hepta immutable V2 preparation'
wait_control_file "$control/hepta-preparation.request.json" 'Hepta preparation request'
jq -e '
  keys == ["preparation_sha256","request_id","schema"]
  and .schema == "trnm.paper_raid.review-chain-hepta-preparation-request.v1"
  and (.request_id | type == "string" and test("^[A-Za-z0-9._:-]{1,128}$"))
  and (.preparation_sha256 | type == "string" and test("^sha256:[0-9a-f]{64}$"))
' "$control/hepta-preparation.request.json" >/dev/null || {
  echo 'ERROR: invalid Hepta preparation request' >&2
  exit 2
}
preparation_request_id=$(jq -er .request_id "$control/hepta-preparation.request.json")
expected_preparation_sha256=$(jq -er .preparation_sha256 \
  "$control/hepta-preparation.request.json")
verify_digest "$control/hepta-finality-preparation.v2.json" \
  "$expected_preparation_sha256" 'Hepta immutable V2 preparation'
issued_at_unix_ms=$(date +%s%3N)
expires_at_unix_ms=$((issued_at_unix_ms + 300000))
jq -n \
  --arg chain_id "$chain_id" \
  --argjson issued_at_unix_ms "$issued_at_unix_ms" \
  --argjson expires_at_unix_ms "$expires_at_unix_ms" \
  --slurpfile preparation "$control/hepta-finality-preparation.v2.json" '
  {
    schema:"trnm_hepta_paper_raid_v4_sign_and_wrap_input_v1",
    chain_id:$chain_id,signer_did:"did:trnm:hepta-authority",nonce:1,
    max_gas:100000,fee_limit:100000,
    issued_at_unix_ms:$issued_at_unix_ms,expires_at_unix_ms:$expires_at_unix_ms,
    preparation:$preparation[0]
  }' >"$evidence/hepta-v4-signing-input.json"
chmod 0600 "$evidence/hepta-v4-signing-input.json"
v4_result="$($root_finalizer_bin paper-raid-v4-hepta-sign-and-wrap \
  "$evidence/hepta-v4-signing-input.json" "$hepta_private_key" \
  "$evidence/hepta-v4-signed-command.json" "$evidence/hepta-v4-transaction.bin")"
[[ $(printf '%s' "$v4_result" | jq -er .public_key_hex) \
  == "$expected_hepta_public_key_hex" ]] || {
  echo 'ERROR: V4 result is not signed by the pinned Hepta authority' >&2
  exit 1
}
v4_command_id=$(printf '%s' "$v4_result" | jq -er .command_id)
v4_applied_key=$(printf '%s' "$v4_result" | jq -er .applied_command_logical_key)
v4_response=$(broadcast_commit "$evidence/hepta-v4-transaction.bin")
assert_committed "$v4_response"
v4_execution_height=$(printf '%s' "$v4_response" | jq -er '.result.height | tonumber')
((v4_execution_height > final_height)) || {
  echo 'ERROR: V4 execution height did not advance beyond the final checkpoint' >&2
  exit 1
}
[[ $(printf '%s' "$v4_response" | jq -er '.result.tx_result.events[0].type') \
  == trnm.paper-raid.finality.applied.v4 ]] || {
  echo 'ERROR: V4 transaction did not emit the canonical applied event' >&2
  exit 1
}
# CometBFT must create H+1 to commit H's AppHash and LastResultsHash even with
# ordinary empty-block production disabled.  Waiting for that canonical block
# avoids inserting a harness transaction into the scientific receipt boundary.
v4_commitment_height=$((v4_execution_height + 1))
for _ in $(seq 1 120); do
  curl -fsS "http://127.0.0.1:$rpc_port/block?height=$v4_commitment_height" \
    >/dev/null 2>&1 && break
  sleep 0.25
done
curl -fsS "http://127.0.0.1:$rpc_port/block?height=$v4_commitment_height" >/dev/null || {
  echo 'ERROR: CometBFT did not create the canonical H+1 commitment block' >&2
  exit 1
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
receipt_rpc_evidence=$evidence/receipt-v2-rpc
"$script_dir/collect_research_receipt_v2_evidence.sh" \
  "http://127.0.0.1:$rpc_port" "$v4_execution_height" \
  "$v4_command_id" "$v4_applied_key" \
  "$receipt_rpc_evidence" paper_raid_finality_v4
trusted_execution_header_hash_hex=$(jq -er '.result.block_id.hash | ascii_downcase' \
  "$receipt_rpc_evidence/block-h.json")
receipt_result="$($root_finalizer_bin assemble-and-verify-with-anchor \
  "$receipt_rpc_evidence" "$evidence/paper-raid-v4-receipt-v2.json" \
  "$trusted_execution_header_hash_hex" "$evidence/trust-anchor.v1.json")"
[[ $(printf '%s' "$receipt_result" | jq -er .status) == final \
  && $(printf '%s' "$receipt_result" | jq -er .command_id) == "$v4_command_id" \
  && $(printf '%s' "$receipt_result" | jq -er .trust_anchor_hash_hex) \
    == "$trust_anchor_hash_hex" \
  && $(printf '%s' "$receipt_result" | jq -er .domain_command_version) \
    == paper_raid_finality_v4 ]] || {
  echo 'ERROR: public Receipt V2 verification did not bind the pinned V4 command' >&2
  exit 1
}
receipt_hash_hex=$(printf '%s' "$receipt_result" | jq -er .receipt_hash_hex)
shutdown_infrastructure
jq -S '
  .status = "verified_and_cleaned_before_terminal"
  | .sandbox.cleaned_before_terminal = true
' "$evidence/infrastructure-isolation.json" \
  >"$evidence/.infrastructure-isolation.json.tmp"
chmod 0600 "$evidence/.infrastructure-isolation.json.tmp"
mv "$evidence/.infrastructure-isolation.json.tmp" \
  "$evidence/infrastructure-isolation.json"
infrastructure_isolation_sha256="sha256:$(sha256sum \
  "$evidence/infrastructure-isolation.json" | cut -d' ' -f1)"
jq -S -n \
  --arg request_id "$preparation_request_id" \
  --arg trust_anchor_hash_hex "$trust_anchor_hash_hex" \
  --arg receipt_hash_hex "$receipt_hash_hex" \
  --arg command_id "$v4_command_id" \
  --arg preparation_sha256 "$expected_preparation_sha256" \
  --arg receipt_path "$evidence/paper-raid-v4-receipt-v2.json" \
  --arg trust_anchor_path "$evidence/trust-anchor.v1.json" \
  --arg artifact_classification_path "$evidence/artifact-classification.json" \
  --arg infrastructure_isolation_path "$evidence/infrastructure-isolation.json" \
  --arg infrastructure_isolation_sha256 "$infrastructure_isolation_sha256" \
  --arg consensus_app_sha256 "$expected_consensus_app_sha256" \
  --arg finalizer_sha256 "$expected_finalizer_sha256" \
  --arg harness_cli_sha256 "$expected_harness_cli_sha256" \
  --argjson start_consensus_time_unix_ms "$start_consensus_time_unix_ms" \
  --argjson final_consensus_time_unix_ms "$final_consensus_time_unix_ms" \
  --argjson consensus_time_delta_ms "$consensus_time_delta_ms" \
  --argjson monotonic_elapsed_ms "$monotonic_elapsed_ms" \
  --argjson execution_height "$v4_execution_height" \
  --argjson commitment_height "$v4_commitment_height" '
  {
    schema:"trnm.paper_raid.review-chain-terminal.v1",status:"verified_finality",
    request_id:$request_id,chain_id:"trnm-paper-raid-review",
    start_consensus_time_unix_ms:$start_consensus_time_unix_ms,
    final_consensus_time_unix_ms:$final_consensus_time_unix_ms,
    consensus_time_delta_ms:$consensus_time_delta_ms,
    monotonic_elapsed_ms:$monotonic_elapsed_ms,required_minimum_delta_ms:900000,
    hepta_preparation_sha256:$preparation_sha256,
    command_id:$command_id,execution_height:$execution_height,
    commitment_height:$commitment_height,
    receipt_hash_hex:$receipt_hash_hex,trust_anchor_hash_hex:$trust_anchor_hash_hex,
    receipt_path:$receipt_path,trust_anchor_path:$trust_anchor_path,
    artifact_classification_path:$artifact_classification_path,
    infrastructure_isolation:{path:$infrastructure_isolation_path,
      sha256:$infrastructure_isolation_sha256,
      sandbox_cleaned_before_terminal:true},
    candidate_authority_artifacts:{consensus_app_sha256:$consensus_app_sha256,
      receipt_v4_sha256:$finalizer_sha256},
    internal_harness:{chain_cli_sha256:$harness_cli_sha256,
      authority_artifact:false,scientific_finality_signer:false}
  }' >"$control/.terminal.ready.json.tmp"
publish_ready "$control/.terminal.ready.json.tmp" "$control/terminal.ready.json"
printf 'TRNM_PAPER_RAID_REVIEW_CHAIN_OK receipt_v2=%s root=%s\n' \
  "$receipt_hash_hex" "$root"
