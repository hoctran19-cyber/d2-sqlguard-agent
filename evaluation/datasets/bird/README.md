# BIRD-SQL Mini-Dev local intake and audit

This workflow audits local benchmark metadata and proposes a **provisional** Financial
candidate shortlist. It does not run SQL, compare results, call an agent/model, or establish
execution accuracy. The existing five-case `sales-bootstrap.json` remains a separate
`fixture_only` benchmark; do not combine its scores with BIRD results.

## Official sources and revision caution

- Hugging Face dataset: <https://huggingface.co/datasets/birdsql/bird_mini_dev>
- BIRD Mini-Dev repository: <https://github.com/bird-bench/mini_dev>
- License declared by the Hugging Face dataset card and repository README:
  **CC BY-SA 4.0**. Review the terms and attribution/share-alike obligations before
  redistributing any derived dataset content; verify the license of accompanying database
  assets independently.

The upstream sources have evolved and currently describe different snapshots. The
Hugging Face API reported `birdsql/bird_mini_dev` main at revision
`f65faf4ae3b638c1fa6df1d3370c8d92c8366301` (last modified 2026-01-18) when checked on
2026-10-20; the card describes its 2025-07-04 update as a 500-question, 11-database release
and lists Financial as 32 questions. The BIRD repository main was at
`abd11b6db92a1c9f809b32f7564c7c71b34d67f0` (2026-09-05) on that check; its README describes
a 2025-07-22 Mini-Dev V2 with 780 questions. These documentation statements are not a
substitute for inspecting exact downloaded files. In particular, they do **not** establish
the record count at a user-selected revision. Pin the actual Hugging Face commit SHA, record
acquisition date, and use the audit report's counts before choosing cases.

The audit tool never downloads data. The user must obtain the dataset from an official source,
record the exact source revision and acquisition date, and provide the local JSON/JSONL data
file. Hugging Face documents `mini_dev_sqlite`, `mini_dev_pg`, and `mini_dev_mysql` splits;
the repository/card describe source records with fields including `db_id`, `question`,
`evidence`, and `SQL`. This tool also accepts `question_id` or `id` when present. It identifies
Financial records only by case-insensitive equality of the upstream `db_id` value to
`financial` (override explicitly with `--financial-db-id` if the selected source documents a
different exact database ID).

## Local acquisition and privacy

1. Choose a source snapshot and download it yourself from the official source. Do not use this
   audit command as a downloader.
2. Keep the full benchmark, database files, credentials, and private data outside tracked
   repository paths. If keeping a local copy under the checkout, use
   `evaluation/datasets/private/`, which is ignored by Git.
3. Record the full upstream commit SHA and the date the snapshot was obtained. The local
   SHA-256 digest is computed by the audit tool for each input data file.
4. Inspect `git status --short --branch` before sharing changes. Never commit BIRD data,
   databases, credentials, or private data.

For the Hugging Face JSON split, place or export only the desired split file locally, such as
`mini_dev_sqlite-00000-of-00001.json`. A directory may contain several dialect files; the tool
selects files whose complete filename tokens identify the requested `--dialect`. If a
filename identifies a conflicting dialect, the audit fails and asks you to correct the
argument or select the intended file. For an explicitly supplied JSON/JSONL file with no
recognized dialect marker in its filename (for example, `export.json`), `--dialect` is the
caller's assertion and is used for records without per-record dialect metadata. This
ambiguity rule is reported here rather than inferred from the SQL text. Arrow-only exports
must first be exported locally to JSON/JSONL; no conversion dependency is added here.

## Run the audit

Run from the repository root, passing an immutable source revision and the real acquisition
date:

```bash
python -m evaluation.bird_audit \
  evaluation/datasets/private/bird/mini_dev_sqlite-00000-of-00001.json \
  --dialect sqlite \
  --revision <full-hugging-face-commit-sha> \
  --acquired-on YYYY-MM-DD
```

The default JSON report is written to an ignored
`evaluation/datasets/private/bird/audit-<revision>-<timestamp>.json` path. Use `--output` to
choose a different, non-existing report path. The report includes source file SHA-256 values,
the pinned revision/date, total and Financial counts, database IDs, missing/duplicate IDs,
missing questions/Gold SQL, and unsupported SQL dialects. It retains the original Financial
question and Gold SQL strings in the local audit output and points candidates to their source
file, record ID, `SQL` field, and dataset revision.

## Candidate report limits

The tool creates a shortlist of 20 only when at least 20 Financial records have a unique
source ID, a non-empty question, non-empty Gold SQL, and a supported dialect (`sqlite`,
`postgresql`, or `mysql`). Otherwise it emits an empty shortlist, the valid candidate pool,
and blockers; it does not fill missing cases with synthetic or unrelated data.

When enough records exist, the deterministic heuristic seeks coverage of the supplied
difficulty labels and SQL features (joins, grouping, subqueries, set operations, windows,
and related constructs), with stable source IDs breaking ties. Each recommendation includes
the exact original question, database ID, dialect, source Gold SQL reference, rationale, and
`verification_status: pending`. This is a candidate-generation aid, **not manual inspection
or Gold SQL validation**. A reviewer must resolve version/source questions, inspect the
question, schema and SQL, and mark verification only after a separate documented review.
Gold SQL is not executed in this task and is never sent to an agent or runtime context.

Missing files, malformed JSON/JSONL, missing revision/acquisition metadata, and ambiguous
multi-dialect directories fail with an actionable error. Unsupported dialects and malformed
records are reported rather than silently treated as valid Financial candidates.
