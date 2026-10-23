# BIRD-SQL Mini-Dev local intake and audit

This workflow audits local benchmark metadata and proposes a **provisional** Financial
candidate shortlist. It does not run SQL, compare results, call an agent/model, or establish
execution accuracy. The existing five-case `sales-bootstrap-v1.json` remains a separate
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

## Three-to-five-case PostgreSQL or SQLite pilot

The pilot command is `python -m evaluation.bird_pilot`. It is separate from the fixture
evaluation runner and never treats the provisional audit shortlist as approved. It requires
all of the following local inputs:

- A BIRD audit report and the exact source JSON/JSONL file(s) named in that report. The pilot
  verifies their SHA-256 hashes and selected question/Gold SQL text against the audited source.
- Three to five comma-separated case IDs that a human has reviewed against the source question,
  Gold SQL, target database schema, and selected role. The IDs are the explicit review
  declaration; candidates are never auto-selected from `candidate_report.shortlist`.
- The actual BIRD Financial database in the same dialect as the audited questions: PostgreSQL
  (PostgreSQL 16 supported) or SQLite (`mini_dev_sqlite`). Provide a logical database name and
  a local SQLGuard policy JSON in the existing `RolePolicy.from_file` format. The policy must
  describe the complete source schema. PostgreSQL grants are checked against that policy;
  SQLite instead relies on OS file permissions plus SQLGuard's application-level role policy.
- Importing/converting benchmark databases is a manual data-preparation step and is not performed
  by this pilot.

The Task 6B `compose.postgres-sandbox.yml` database is a synthetic SQLGuard fixture and is not
a BIRD database. Both backends require an explicit operator-maintained metadata marker matching
the audited BIRD database ID and source revision. For PostgreSQL, after independently loading
and checking the real BIRD database and the local policy/grants, a database owner must create
an inaccessible marker table:

```sql
CREATE TABLE public.sqlguard_bird_pilot_metadata (marker boolean PRIMARY KEY);
COMMENT ON TABLE public.sqlguard_bird_pilot_metadata IS
  'sqlguard-bird-pilot:v1; database_id=financial; revision=<full-audit-source-sha>';
```

Replace `financial` and the revision with the exact values in the audit report. Do not grant
the selected runtime role any access to this marker table. It is an operator attestation, not
cryptographic proof of data provenance; verify the database contents and schema independently.

For SQLite, create a separate metadata table in the database before the pilot (as the database
owner, not through SQLGuard):

```sql
CREATE TABLE sqlguard_bird_pilot_metadata (marker TEXT PRIMARY KEY);
INSERT INTO sqlguard_bird_pilot_metadata(marker) VALUES
  ('sqlguard-bird-pilot:v1; database_id=financial; revision=<full-audit-source-sha>');
```

The table must contain exactly one row and only the `marker` column, and must not be included in
the role policy. The pilot opens the database in read-only mode and checks this marker. This is
still only an operator attestation, not proof of provenance. SQLite has no per-user database
roles or grants; restrict file and sidecar access with OS permissions and run the pilot under an
appropriately restricted OS account.

Install the PostgreSQL driver (`python -m pip install -e ".[postgres]"`) and have a local
Ollama service/model ready. Configure these variables in a private, ignored `.env` (do not
print it or commit it):

- `SQLGUARD_PLANNER=ollama`
- `SQLGUARD_OLLAMA_URL` and `SQLGUARD_OLLAMA_MODEL` (optional; existing local defaults apply)
- For PostgreSQL: `SQLGUARD_SCHEMA_SOURCE=postgres`, `SQLGUARD_QUERY_SOURCE=postgres`,
  and `SQLGUARD_DB_DSN_FINANCE` for role `finance` (or the corresponding `SALES`/`OPERATIONS`
  DSN and policy role for another approved identity). Use the matching least-privilege login,
  never an admin or note-writer credential.
- For SQLite: set `SQLGUARD_SCHEMA_SOURCE=sqlite`, `SQLGUARD_QUERY_SOURCE=sqlite`, and
  `SQLGUARD_SQLITE_PATH` to the existing local BIRD SQLite database file.

Review case IDs manually, source the private environment without shell tracing, then run from
the repository root. Example paths and IDs below are placeholders, not supplied benchmark data:

```bash
python -m evaluation.bird_audit \
  evaluation/datasets/private/bird/mini_dev_postgresql.json \
  --dialect postgresql \
  --revision <full-upstream-commit-sha> \
  --acquired-on YYYY-MM-DD

# After reviewing the audit questions, Gold SQL, schema, and role grants:
set -a
. ./.env
set +a
python -m evaluation.bird_pilot \
  --audit-report evaluation/datasets/private/bird/audit-<revision>.json \
  --dataset-file evaluation/datasets/private/bird/mini_dev_postgresql.json \
  --reviewed-ids 12,34,56 \
  --policy /path/outside/repository/bird-financial-policy.json \
  --role finance \
  --database-name bird_financial
```

The pilot accepts only audited questions whose dialect matches the selected backend; it does not
translate SQL dialects or run against the fixture database. It builds the existing `OllamaPlanner`,
role-filtered `PostgresSchemaAdapter` or `SQLiteSchemaAdapter`, `PolicySQLGate`, `SecureSqlTool`,
and matching executor. The planner receives only the selected natural-language question and
role-authorized schema/context. Gold SQL stays out of the planner and is never executed.
Generated/repaired SQL returns to the gate before tool execution; retry, SQL/LLM/tool limits,
query/run timeouts, row cap, response-byte cap, and output canary check remain in force.
PostgreSQL uses database grants; SQLite relies on OS file permissions in addition to SQLGuard's
application-level controls.

Each run creates a new, mode-restricted directory under the ignored
`evaluation/datasets/private/bird/pilot-runs/<run-uuid>/pilot.json`; existing runs are never
overwritten. The JSON schema includes:

- run/source revision, acquisition date, Financial database ID, PostgreSQL database name, role,
  policy version/SHA-256, Ollama model name, configured execution budgets, and database
  preflight status;
- for each case: source and Gold SQL references (no Gold SQL text), question, generated SQL,
  gate outcomes/violation codes, execution status and sanitized error category, bounded result
  rows/summary, latency, attempt/LLM/tool/retry counts, trace events/reference, and audit
  records;
- separate `sql_generation_success`, `execution_status`, `result_correctness`,
  `result_comparison`, and `security_policy_compliance` fields.

`result_correctness` and `result_comparison` are always `not_evaluated`: successful execution
does not establish correctness. The pilot is not a full benchmark, does not evaluate all
Financial records, and does not prove provenance beyond the audited file hashes and the
operator-maintained database marker. Results contain private questions, generated SQL, and
database rows; keep the ignored output local and do not commit or share it without review.
