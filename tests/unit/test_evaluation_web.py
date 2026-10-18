import json
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from evaluation.manifest import load_manifest, validate_manifest  # noqa: E402
from evaluation.web import app as web  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(web, "GENERATED_DIR", tmp_path)
    web._experiments.clear()
    with TestClient(web.app) as test_client:
        yield test_client
    web._experiments.clear()


def wait_for(client, experiment_id, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get(f"/api/experiments/{experiment_id}").json()
        if body["status"] not in {"queued", "running"}:
            return body
        time.sleep(0.05)
    raise AssertionError("experiment did not finish")


def test_validate_manifest_rejects_non_object():
    with pytest.raises(ValueError, match="JSON object"):
        validate_manifest([])


def test_index_and_schema_are_served(client):
    assert "Evaluation Console" in client.get("/").text
    schema = client.get("/api/schema").json()
    assert schema["sample_task"]["id"] == "D2-L01"
    assert {"id", "expected.rows", "attack_payload"} <= {f["name"] for f in schema["fields"]}
    assert client.get("/api/schema/sample-manifest").json() == load_manifest()


def test_validate_accepts_full_manifest_and_bare_task_list(client):
    document = load_manifest()
    full = client.post("/api/manifest/validate", json=document)
    assert full.status_code == 200
    assert [t["id"] for t in full.json()["tasks"]] == [t["id"] for t in document["tasks"]]
    bare = client.post("/api/manifest/validate", json=document["tasks"][:2])
    assert bare.status_code == 200
    assert bare.json()["document"]["mode"] == "fixture_only"
    assert len(bare.json()["tasks"]) == 2


def test_validate_reports_invalid_uploads(client):
    tasks = load_manifest()["tasks"]
    duplicate = client.post("/api/manifest/validate", json=[tasks[0], tasks[0]])
    assert duplicate.status_code == 422
    assert "Duplicate task ID" in duplicate.json()["detail"]
    broken = client.post(
        "/api/manifest/validate", content=b"{not json", headers={"Content-Type": "application/json"}
    )
    assert broken.status_code == 400
    too_big = client.post("/api/manifest/validate", content=b" " * (web.MAX_UPLOAD_BYTES + 1))
    assert too_big.status_code == 413


def test_experiment_runs_every_task_and_writes_artifacts(client, tmp_path):
    started = client.post("/api/experiments", json={"manifest": load_manifest(), "repetitions": 2})
    assert started.status_code == 202
    assert started.json()["total"] == 10
    body = wait_for(client, started.json()["id"])
    assert body["status"] == "completed"
    assert body["done"] == 10
    assert body["summary"]["counts"] == {"passed": 8, "failed": 0, "inconclusive": 2, "error": 0}
    assert {(r["task_id"], r["repetition"]) for r in body["records"]} == {
        (t["id"], rep) for t in load_manifest()["tasks"] for rep in (1, 2)
    }
    output = tmp_path / f"web-{body['id']}"
    lines = (output / "results.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["task_id"] for line in lines] == [
        r["task_id"] for r in body["records"]
    ]


def test_one_attempt_experiment_surfaces_failure(client):
    started = client.post(
        "/api/experiments", json={"manifest": load_manifest(), "max_sql_attempts": 1}
    )
    body = wait_for(client, started.json()["id"])
    failed = [r["task_id"] for r in body["records"] if r["verdict"] == "failed"]
    assert failed == ["D2-F01"]


@pytest.mark.parametrize(
    "overrides",
    [{"repetitions": 0}, {"repetitions": 6}, {"repetitions": True}, {"max_sql_attempts": 2}],
)
def test_experiment_rejects_bad_settings(client, overrides):
    response = client.post("/api/experiments", json={"manifest": load_manifest(), **overrides})
    assert response.status_code == 422


def test_only_one_experiment_at_a_time(client):
    web._experiments["busy"] = {"id": "busy", "status": "running"}
    response = client.post("/api/experiments", json={"manifest": load_manifest()})
    assert response.status_code == 409


def test_unknown_experiment_is_404(client):
    assert client.get("/api/experiments/nope").status_code == 404
