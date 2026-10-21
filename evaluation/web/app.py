"""Local evaluation console API. Start with: python -m evaluation.web

Wraps the existing fixture runner; it adds no LLM, database or policy of its own.
One experiment runs at a time; state lives in memory and artifacts on disk.
"""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

from evaluation.manifest import (
    CATEGORIES,
    DEFAULT_MANIFEST,
    SCENARIOS,
    load_manifest,
    validate_manifest,
)
from evaluation.runner import run_suite

STATIC_DIR = Path(__file__).parent / "static"
GENERATED_DIR = Path(__file__).resolve().parents[1] / "reports" / "generated"
MAX_UPLOAD_BYTES = 1_000_000
MAX_TASKS = 200
MAX_REPETITIONS = 5
KEPT_EXPERIMENTS = 20

TASK_FIELDS = [
    ("id", True, "Mã task duy nhất, ví dụ D2-L01."),
    ("category", True, "Nhóm task: " + " | ".join(sorted(CATEGORIES)) + "."),
    ("role", True, "Role của test principal: sales | finance | operations (chưa là auth thật)."),
    ("question", True, "Câu hỏi ngôn ngữ tự nhiên gửi cho Agent."),
    (
        "fixture_scenario",
        True,
        "Kịch bản fixture có sẵn (scripted planner): " + " | ".join(sorted(SCENARIOS)) + ".",
    ),
    ("comparison", True, "Cách so rows: ordered_rows | unordered_rows (multiset)."),
    ("expected.status", True, "Trạng thái kỹ thuật mong đợi: succeeded | refused | failed."),
    ("expected.disposition", True, "Hành vi nghiệp vụ: full | partial | refused | error."),
    ("expected.columns", True, "Danh sách tên cột mong đợi."),
    ("expected.rows", True, "Danh sách dòng; mỗi dòng cùng độ rộng columns, chỉ giá trị scalar."),
    ("expected.omitted_fields", True, "Các trường phải bị bỏ khi trả partial."),
    ("attack_payload", False, "Bắt buộc với category injection: nội dung ghi vào note."),
    ("gold_sql", False, "Đường dẫn gold SQL cho reviewer; không bao giờ gửi cho Agent."),
]

app = FastAPI(title="SQLGuard Evaluation Console", docs_url="/api/docs", redoc_url=None)
_experiments: dict[str, dict] = {}
_tasks: set[asyncio.Task] = set()


def normalize_upload(payload):
    """Accept a full manifest object or a bare list of tasks; return a validated manifest."""
    if isinstance(payload, list):
        payload = {
            "schema_version": 1,
            "mode": "fixture_only",
            "dataset_revision": "web-upload-unversioned",
            "policy_revision": "fixture-sales-v1",
            "tasks": payload,
        }
    document = validate_manifest(payload)
    if len(document["tasks"]) > MAX_TASKS:
        raise ValueError(f"At most {MAX_TASKS} tasks per upload")
    return document


def task_summary(case):
    return {
        "id": case["id"],
        "category": case["category"],
        "role": case["role"],
        "question": case["question"],
        "fixture_scenario": case["fixture_scenario"],
        "comparison": case["comparison"],
        "expected_status": case["expected"]["status"],
        "expected_disposition": case["expected"]["disposition"],
    }


async def read_json(request: Request):
    body = await request.body()
    if len(body) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"Body larger than {MAX_UPLOAD_BYTES} bytes")
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPException(400, f"Invalid JSON: {error}") from None


def active_experiment():
    return next((e for e in _experiments.values() if e["status"] in {"queued", "running"}), None)


async def execute(experiment, document):
    experiment["status"] = "running"
    output = GENERATED_DIR / f"web-{experiment['id']}"
    try:
        summary = await run_suite(
            document,
            output,
            repetitions=experiment["repetitions"],
            max_sql_attempts=experiment["max_sql_attempts"],
            on_record=lambda record: _record_done(experiment, record),
        )
        experiment["summary"] = summary
        experiment["status"] = "completed"
    except Exception as error:
        # Expose only the error type; details may contain paths or data.
        experiment["status"] = "failed"
        experiment["error"] = type(error).__name__
    finally:
        experiment["finished_at"] = datetime.now(UTC).isoformat()


def _record_done(experiment, record):
    experiment["records"].append(record)
    experiment["done"] = len(experiment["records"])


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/schema")
def task_schema():
    sample = load_manifest()["tasks"][0]
    return {
        "sample_task": sample,
        "envelope": {
            "schema_version": 1,
            "mode": "fixture_only",
            "dataset_revision": "sales-bootstrap-v1",
            "policy_revision": "fixture-sales-v1",
            "tasks": ["<task>", "..."],
        },
        "fields": [
            {"name": name, "required": required, "description": description}
            for name, required, description in TASK_FIELDS
        ],
        "limits": {
            "max_upload_bytes": MAX_UPLOAD_BYTES,
            "max_tasks": MAX_TASKS,
            "max_repetitions": MAX_REPETITIONS,
            "max_sql_attempts": [1, 3],
        },
        "mode_note": "fixture_only: scripted planner + SQLite fixture; no LLM benchmark claims.",
    }


@app.get("/api/schema/sample-manifest")
def sample_manifest():
    return JSONResponse(
        load_manifest(),
        headers={"Content-Disposition": f'attachment; filename="{DEFAULT_MANIFEST.name}"'},
    )


@app.post("/api/manifest/validate")
async def validate(request: Request):
    try:
        document = normalize_upload(await read_json(request))
    except ValueError as error:
        raise HTTPException(422, str(error)) from None
    return {"document": document, "tasks": [task_summary(case) for case in document["tasks"]]}


@app.post("/api/experiments", status_code=202)
async def start_experiment(request: Request):
    payload = await read_json(request)
    if not isinstance(payload, dict):
        raise HTTPException(400, "Body must be an object with manifest/repetitions")
    repetitions = payload.get("repetitions", 1)
    max_sql_attempts = payload.get("max_sql_attempts", 3)
    # type() rather than isinstance(): JSON true/false must not pass as 1/0.
    if type(repetitions) is not int or not 1 <= repetitions <= MAX_REPETITIONS:
        raise HTTPException(422, f"repetitions must be an integer 1..{MAX_REPETITIONS}")
    if type(max_sql_attempts) is not int or max_sql_attempts not in (1, 3):
        raise HTTPException(422, "max_sql_attempts must be 1 or 3")
    try:
        document = normalize_upload(payload.get("manifest"))
    except ValueError as error:
        raise HTTPException(422, str(error)) from None
    if active_experiment() is not None:
        raise HTTPException(409, "Another experiment is still running")

    experiment_id = uuid4().hex[:12]
    experiment = {
        "id": experiment_id,
        "status": "queued",
        "created_at": datetime.now(UTC).isoformat(),
        "finished_at": None,
        "repetitions": repetitions,
        "max_sql_attempts": max_sql_attempts,
        "total": len(document["tasks"]) * repetitions,
        "done": 0,
        "records": [],
        "summary": None,
        "error": None,
        "output": f"evaluation/reports/generated/web-{experiment_id}",
    }
    _experiments[experiment_id] = experiment
    for old_id in list(_experiments)[:-KEPT_EXPERIMENTS]:
        _experiments.pop(old_id)
    task = asyncio.create_task(execute(experiment, document))
    _tasks.add(task)  # Keep a reference so the task is not garbage-collected.
    task.add_done_callback(_tasks.discard)
    return {"id": experiment_id, "status": experiment["status"], "total": experiment["total"]}


@app.get("/api/experiments/{experiment_id}")
def get_experiment(experiment_id: str):
    experiment = _experiments.get(experiment_id)
    if experiment is None:
        raise HTTPException(404, "Unknown experiment")
    return experiment
