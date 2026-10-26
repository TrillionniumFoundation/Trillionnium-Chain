# P1: Public V3 History loopback is not a trust or CPU-budget exemption

Source parent: Chain #342 e55107450eb1a1f051a6c98101f3f88b7afa8f91.
Security candidate, draft only; W1 proof, Ticket, target, chainwork, signed
V3 Cookie, Final-use and production activation are not changed.

## Problem

A remote History source can be exposed as 127.0.0.1 through a tunnel.
The old remote-sync Host guard treated this address as development-only
and would not require the fixed Host parent, even when PUBLIC V3 CLI
sync selected the more protected public service profile. Neither an
allowlisted signing key nor a local TCP address proves resource payment
or real historical packet origin.

## Added protection

- The new host_kernel_parent::require_for_public_history(address)
  ALWAYS requires the original root-provisioned
  /sys/fs/cgroup/trnmponpublic.slice, even when address is loopback.
  No resource allowance or child cgroup is minted.
- The main CLI sync path calls this stronger function when selecting
  the PUBLIC admission profile. Consequently public History from
  a loopback tunnel has the same finite CPU/memory/pids parent as
  direct WAN traffic. Its original native page imports and
  per-page Host checks remain intact.
- Explicit non-public local-only development sync retains the old
  loopback rule. Do not silently downgrade a public profile just
  because its configured peer has a loopback address.
- The new Rust native unit tests compare loopback/remote source
  kernel ownership with original fixed cgroup checker and assert
  that PUBLIC CLI cannot receive Ok(None).

## Important limits

The original exported receive_page_from receives caller-supplied
SocketAddr, which is routing context, NOT independent attestation
of remote origin. A separate library embedding or the original
non-public native sync route can still consume a tunneled source
if its operator deliberately chooses a locally trusted developer
path. Address-only checks cannot solve this. A public deployment
must prevent that downgrade, including across container/network
namespaces and proxy processes.

The stricter PUBLIC loopback route requires a real administrator
provisioned Host parent even during localhost developer tests. No
fake cgroup, OS-root bypass, weakened profile or artificial test
success is allowed.

W1 itself still admits cheaply fabricated ticket-positive false
transcripts to full CPU-intensive replays, and valid work with
invalid StateRoot remains another attack. No honest fairness
guarantee, GPU/ASIC pricing, all-source physical resource evidence,
A03 full original campaigns, W2 proof soundness or external P6
cryptography acceptance is conferred by this change. Original
P0–P6 gates remain OPEN until their actual independent receipts
pass. Keep draft / SHADOW_ONLY / HOLD_NO_GO.
