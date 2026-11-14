# Provider observations

These records distinguish a real resource probe, a refused build request and
an unresolved runtime lifecycle. None is a full W1 proof generation.

## Kaggle resource probe

The actual returned [resource observation](w1-resource-probe.json) and
[provider artifact manifest](w1-resource-manifest.json) belong to the original
request `trnm-w1-7d418660-kaggle-probe-01`, private notebook version 1.
The fixed normal account wrapper was used on the configured Hepta ROG host.
The provider reported COMPLETE, and the artifact reader then checked the
manifest, exact HTTP/body lengths and SHA256 of the downloaded original bytes.

The resource JSON is 1,528 bytes with SHA256
`58deb46f2e6f78f2f40b81bd659459c45db0ad6615a1501c544532902d6a6407`;
its manifest is 271 bytes with SHA256
`5764fd5f2df407113fc9c6fea3e81e630c64ad3b8f4ea99913fceba8deb8ea88`.
The provider's listing advertised different sizes, 920 and 929 bytes;
`PROVIDER_SIZE_CONFLICT` warnings were retained. These conflicting listing
values did not replace exact verified body lengths.

The actual CUDA driver allocation and 256-byte host/device roundtrip succeeded.
This proves that this probe reached GPU memory, not that the pinned CPU r0vm
used CUDA, that an entire prover process tree was metered, or that a W1 proof ran.

## CUDA build-only request

[The normal-channel request reconciliation](cuda-build-reconciliation.json)
records request `trnm-w1-7d418660-cuda-build-01` as `REJECTED / NOT_SENT` and
`remote_effect_unknown=false`. The account wrapper rejected owner-list evidence
with `NOTEBOOK_LIST_SCOPE` before SaveKernel dispatch. Notebook version, kernel
ID and session ID are null. The request was not assigned another ID or resubmitted.

The [reviewed source](w1_cuda_build_probe.py), SHA256
`b0fd8b867aecb3f2e9917bf0db14f07e7df8a32704d012553391e145c9cffcfd`,
would first compile and execute an actual sm75 CUDA kernel, then build fixed
upstream SDK commit `14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6` with its locked
dependencies and explicit `cuda,disable-dev-mode` features. It requires the
actual Git LFS recursion program, not its pointer. Its budget was 3,600 seconds.
This source was not executed remotely for the rejected request. It contains no
W1 input or full-proof invocation and cannot increase the fresh-proof count.

## Colab runtime attempt

The original allocation used key `trnm-w1-7d418660-colab-runtime-01`.
Binding was refused with `STATE_DESTINATION_CONFLICT` because the normal
account's fixed profile already existed with different content. Controlled
release was then refused with `RELEASE_BLOCKED_BY_FOREIGN_OR_BUSY_KERNEL`.
The existing profile and other kernels were not overwritten or killed.

The later [normal reconciliation](colab-reconciliation.json) reported
`FIXED_RUNTIME_NOT_FOUND`. No controlled release success receipt was obtained.
The record therefore does not assert either a completed release or continuing
billable occupancy after that observation. No user computation was submitted
to this Colab runtime.

No account credential, authorization scope, provider ownership guard, or
installed adapter was changed by this continuation.
