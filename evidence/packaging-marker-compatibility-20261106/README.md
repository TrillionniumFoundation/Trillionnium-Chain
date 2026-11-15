# Wheel metadata marker API compatibility

[Repository-truth job 127802226059](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42187752188/job/127802226059)
failed two metadata-marker controls because `Marker.evaluate()` rejected the
`context` keyword. The log does not report the installed packaging version.
The repository-truth workflow uses the runner's Python environment rather than
installing the separate model-runtime CPU requirements (which pin packaging26.3).

Packaging 25.0 introduced `context`, defaulting to `metadata`. Packaging 24.0
has no context parameter and already supplies the metadata `extra` default.
The caller explicitly supplies every validated environment field and `extra`.
Omitting only this newer keyword preserves that metadata behavior, actual PEP
marker evaluation and refusal of active missing dependencies. No TypeError retry,
unconditional acceptance, extra omission or ambient-platform fallback is added.

The unchanged test on baseline `56897f125df27994efa1dda935f2c62eceb36de9`
reproduced two TypeErrors under the official packaging24.0 wheel. After the fix,
the complete runtime-material test file passes 22/22 separately with packaging
24.0, 25.0 and 26.3. The first two are versioned PyPI wheels on PYTHONPATH; 26.3
is the existing local installation. Wheel hashes and Python identity are retained.
New tests cover the legacy method signature, explicit empty/selected extras,
pinned fields overriding ambient platform values, invalid marker refusal and
propagation of internal evaluator errors. Original wheel/dependency controls remain.

These are local runtime-material controls, not a complete repository-truth CI
rerun or model/production acceptance. Both edited source files have existing
corpus pins. Publication was initially held for permission review. Following
explicit user approval, only those two pins are updated to the exact changed
Git blobs; all other corpus entries and acceptance restrictions are preserved.
This does not claim a new full repository-truth CI pass.
