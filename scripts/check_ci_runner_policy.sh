#!/usr/bin/env bash
set -euo pipefail

source_mode="${1:---worktree}"
expected='runs-on: [self-hosted, Linux, X64, x230, trillionnium-chain]'
standard_trust_guard="github.repository == 'TrillionniumFoundation/Trillionnium-Chain' && (github.event_name == 'schedule' || (github.actor == 'ProfAlexQI' && github.triggering_actor == 'ProfAlexQI' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)))"
# The payload/recovery workflow accepts the repository connector only for a
# same-repository, member-authored Chain feature PR. This does not authorize
# bot pushes, forks, workflow_dispatch, or a non-Chain branch.
payload_recovery_trust_guard="github.repository == 'TrillionniumFoundation/Trillionnium-Chain' && ((github.actor == 'ProfAlexQI' && github.triggering_actor == 'ProfAlexQI') || (github.actor == 'Tomasrgbsf' && github.triggering_actor == 'Tomasrgbsf') || (github.actor == 'github-actions[bot]' && github.triggering_actor == 'github-actions[bot]' && github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.author_association == 'MEMBER' && startsWith(github.head_ref, 'feature/chain-'))) && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)"
# The PoCO-BFT workflow has a first-class weekly schedule. Its scheduled
# branch is intentionally narrower than the historical shared guard: only the
# canonical default branch may execute it.
poco_bft_trust_guard="github.repository == 'TrillionniumFoundation/Trillionnium-Chain' && (github.event_name == 'schedule' && github.ref == 'refs/heads/main' || (github.actor == 'ProfAlexQI' && github.triggering_actor == 'ProfAlexQI' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)))"
p1_trust_guard="github.repository == 'TrillionniumFoundation/Trillionnium-Chain' && github.actor == 'ProfAlexQI' && github.triggering_actor == 'ProfAlexQI' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) && (github.event_name != 'workflow_dispatch' || github.ref == 'refs/heads/main')"
root=$(git rev-parse --show-toplevel)

list_index_workflows() {
  git -C "$root" ls-files --cached -- '.github/workflows/' | \
    sed 's#^.github/workflows/##' | \
    awk '/\.ya?ml$/ && index($0, "/") == 0' | sort
}

list_head_workflows() {
  git -C "$root" ls-tree -r --name-only HEAD -- .github/workflows/ | \
    sed 's#^.github/workflows/##' | \
    awk '/\.ya?ml$/ && index($0, "/") == 0' | sort
}

validate_workflow_jobs() {
  local workflow=$1

  awk -v workflow="$workflow" \
    -v expected="$expected" \
    -v standard_trust_guard="$standard_trust_guard" \
    -v payload_recovery_trust_guard="$payload_recovery_trust_guard" \
    -v poco_bft_trust_guard="$poco_bft_trust_guard" \
    -v p1_trust_guard="$p1_trust_guard" '
    function report(message) {
      printf "ERROR: %s: %s\n", workflow, message > "/dev/stderr"
      invalid = 1
    }

    function finish_job() {
      if (job == "") {
        return
      }
      if (job_uses > 0) {
        report("job " job " uses a reusable workflow; job-level uses is not authorized")
      }
      if (job_runs_on != 1) {
        report("job " job " must contain exactly one direct " expected \
          " (found " job_runs_on ")")
      }
      if (job_if != 1) {
        report("job " job " must contain exactly one direct folded trust guard (found " \
          job_if ")")
      } else {
        normalized_guard = job_guard
        gsub(/[[:space:]]+/, " ", normalized_guard)
        sub(/^ /, "", normalized_guard)
        sub(/ $/, "", normalized_guard)

        required_guard = standard_trust_guard
        if (workflow == "trnm-payload-replay-recovery-v1.yml" ||
            workflow == "trnm-replay-to-core-coordinator-v1.yml") {
          required_guard = payload_recovery_trust_guard
        }
        if (workflow == "trnm-poco-bft-v0.yml") {
          required_guard = poco_bft_trust_guard
        }
        if (workflow == "p1-rust-sidecar.yml") {
          required_guard = p1_trust_guard
        }
        if (normalized_guard != required_guard) {
          report("job " job " does not use the canonical trusted X230 invocation guard")
        }
      }
      job = ""
      job_runs_on = 0
      job_uses = 0
      job_if = 0
      job_guard = ""
      capture_job_if = 0
    }

    {
      line = $0
      sub(/\r$/, "", line)

      if (line ~ /^[ ]*$/ || line ~ /^[ ]*#/) {
        next
      }

      indent = 0
      while (substr(line, indent + 1, 1) == " ") {
        indent++
      }
      text = substr(line, indent + 1)

      if (capture_job_if) {
        if (indent > 4) {
          job_guard = job_guard " " text
          next
        }
        capture_job_if = 0
      }

      if (indent == 0 && text ~ /^jobs:[[:space:]]*(#.*)?$/) {
        if (in_jobs) {
          finish_job()
        }
        jobs_sections++
        if (jobs_sections > 1) {
          report("multiple top-level jobs mappings are not authorized")
        }
        in_jobs = 1
        next
      }

      if (in_jobs && indent == 0) {
        finish_job()
        in_jobs = 0
      }

      if (!in_jobs) {
        next
      }

      if (indent == 2) {
        finish_job()
        if (text !~ /^[A-Za-z_][A-Za-z0-9_-]*:/) {
          report("unsupported jobs entry: " text)
          next
        }

        job = text
        sub(/:.*/, "", job)
        jobs_seen++

        remainder = text
        sub(/^[^:]*:/, "", remainder)
        if (remainder !~ /^[[:space:]]*(#.*)?$/) {
          report("job " job " must use a block mapping so its runner policy can be validated")
        }
        next
      }

      if (job == "") {
        report("content appears in jobs before a supported job identifier: " text)
        next
      }

      if (indent == 4) {
        if (text ~ /^(runs-on|[\047\"]runs-on[\047\"])[[:space:]]*:/) {
          job_runs_on++
          if (text != expected) {
            report("job " job " uses unauthorized CI runner: " text)
          }
        } else if (text ~ /^(uses|[\047\"]uses[\047\"])[[:space:]]*:/) {
          job_uses++
        } else if (text ~ /^(if|[\047\"]if[\047\"])[[:space:]]*:/) {
          job_if++
          if (text != "if: >-") {
            report("job " job " trust guard must use the direct folded form: if: >-")
          }
          capture_job_if = 1
        }
      }
    }

    END {
      if (in_jobs) {
        finish_job()
      }
      if (jobs_sections == 0) {
        report("missing top-level jobs mapping")
      } else if (jobs_seen == 0) {
        report("top-level jobs mapping contains no supported jobs")
      }
      if (invalid) {
        exit 1
      }
      print jobs_seen
    }
  '
}

case "$source_mode" in
  --worktree)
    mapfile -t workflows < <(find "$root/.github/workflows" -maxdepth 1 -type f \
      \( -name '*.yml' -o -name '*.yaml' \) -printf '%P\n' | sort)
    read_workflow() {
      cat "$root/.github/workflows/$1"
    }
    ;;
  --staged)
    mapfile -t workflows < <(list_index_workflows)
    read_workflow() {
      git -C "$root" show ":.github/workflows/$1"
    }
    ;;
  --head)
    git -C "$root" cat-file -e 'HEAD^{commit}' 2>/dev/null || {
      echo "ERROR: HEAD does not name a commit for CI runner policy validation" >&2
      exit 2
    }
    mapfile -t workflows < <(list_head_workflows)
    read_workflow() {
      git -C "$root" show "HEAD:.github/workflows/$1"
    }
    ;;
  *)
    echo "ERROR: unsupported CI runner policy source: $source_mode" >&2
    exit 2
    ;;
esac

job_count=0
for workflow in "${workflows[@]}"; do
  if ! workflow_job_count=$(read_workflow "$workflow" | validate_workflow_jobs "$workflow"); then
    exit 1
  fi
  job_count=$((job_count + workflow_job_count))
done

if (( job_count == 0 )); then
  echo "ERROR: no GitHub Actions jobs were found for CI runner policy validation" >&2
  exit 1
fi

printf 'ci_runner_policy=x230-self-hosted-only jobs=%d source=%s\n' \
  "$job_count" "${source_mode#--}"
