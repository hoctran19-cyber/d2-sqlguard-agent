# Evaluation design

The starter harness in `src/sqlguard/evaluation.py` accepts explicit expected statuses and optional expected answers. It reports case ID, pass/fail, latency, error category, and a currently coarse security decision. Token usage and cost are `None` because the mock has no provider usage.

No benchmark accuracy, task-success rate, security score, latency claim, or research result is reported by this repository. The included offline case is only a harness smoke test, not a representative benchmark.

## Adding cases

Store approved, versioned cases under `evaluation/datasets/`. Each case should include a stable ID, natural-language question, database/schema context once supported, expected behavior or result, and security label. Keep credentials and private data out of fixtures. Record dataset provenance and permitted use.

## Planned metrics

Agree on exact definitions before using them in reports:

- exact/result execution accuracy and task success;
- policy violation and unauthorized-access rates;
- latency distributions, retries, and timeout rates;
- model token use and cost, when measured by a real provider;
- breakdowns by query complexity, policy class, and failure category.

For reproducibility, record code revision, dataset revision, model/provider settings, database snapshot, policy version, seed where applicable, and execution environment. Baselines and ablations belong in separate subdirectories once implemented.
