# Evaluation workspace

The starter runner and typed case/result records are in `src/sqlguard/evaluation.py`. The offline smoke case is exercised by `pytest -q tests/unit/test_evaluation.py`.

- `datasets/`: approved, versioned benchmark cases only; keep private data out.
- `baselines/`: future reproducible baseline implementations and settings.
- `metrics/`: future metric definitions and aggregations.
- `reports/`: manually reviewed research reports; generated output is ignored by Git.

No official dataset or benchmark results are included. See [`docs/evaluation/`](../docs/evaluation/README.md) before adding cases or publishing metrics.
