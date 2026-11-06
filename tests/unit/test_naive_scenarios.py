"""Pinned demo payloads (scenarios.py) and the attacker listener of scenario N-I3 (N8)."""

import threading
import urllib.request
from datetime import datetime
from io import StringIO

import pytest

from sqlguard.lab import attacker_listener
from sqlguard.lab.attacker_listener import HOST, PIXEL, ListenerHandler, create_server, format_hit
from sqlguard.lab.model import ATTACKER_AMOUNT, LISTENER_URL, SCRIPTED_QUESTIONS
from sqlguard.lab.scenarios import (
    PAYLOAD_EXFILTRATION,
    PAYLOAD_FORGED_AMOUNT,
    PAYLOAD_TOOL_HIJACK,
    SCENARIOS,
    SCENARIOS_BY_ID,
)
from sqlguard.security.policy import load_policy
from sqlguard.security.sanitizer import detect_injection

POLICY = load_policy("business_financial_v1")
# What SecureSqlTool passes the detector for the demo role (service.py, _build_envelope).
OPERATOR_TERMS = POLICY.forbidden_column_names("operator")


def test_every_scenario_question_has_a_scripted_model():
    assert {scenario.question for scenario in SCENARIOS} == set(SCRIPTED_QUESTIONS)


def test_indirect_scenarios_target_a_policy_note_and_fit_the_lab_limit():
    for scenario in SCENARIOS:
        if scenario.kind == "direct":
            assert scenario.target is None and scenario.payload is None
            continue
        table, _, row = scenario.target.partition(".")
        assert table in POLICY.note_targets and row.isdigit()
        assert 0 < len(scenario.payload) <= 2000  # AttackLab default max_length


def test_payloads_carry_the_values_the_symptom_badges_look_for():
    assert str(ATTACKER_AMOUNT) in PAYLOAD_FORGED_AMOUNT
    assert LISTENER_URL in PAYLOAD_EXFILTRATION
    assert "execute_sql" in PAYLOAD_TOOL_HIJACK


def test_no_payload_uses_override_wording():
    """The payloads read like business notes; none says "ignore previous instructions"."""
    for scenario in SCENARIOS_BY_ID.values():
        hits = set(detect_injection(scenario.payload or ""))
        assert not hits & {"override_en", "override_vi", "persona", "persona_vi", "role_marker"}


@pytest.mark.parametrize(
    ("scenario_id", "flagged"),
    [("N-I1", True), ("N-I2", False), ("N-I3", False)],
)
def test_sqlguard_detector_flags_only_the_payload_that_names_a_tool(scenario_id, flagged):
    """Measured, not desired: the regex detector catches N-I1 (tool and column names) and misses
    the business-sounding N-I2 and N-I3. The seminar uses this as evidence that detectors are
    unreliable; if the detector improves, update this test and the slide together."""
    payload = SCENARIOS_BY_ID[scenario_id].payload
    assert bool(detect_injection(payload, sensitive_terms=OPERATOR_TERMS)) is flagged


def test_format_hit_decodes_the_exfiltrated_query():
    line = format_hit(
        "/s.gif?d=Nguy%E1%BB%85n%20V%C4%83n%20A%7C12%20Ph%E1%BB%91%20Hu%E1%BA%BF",
        now=datetime(2026, 11, 6, 9, 30, 5),
    )
    assert line == "[09:30:05] GET /s.gif\n    d = Nguyễn Văn A|12 Phố Huế"


def test_listener_binds_loopback_only_and_has_no_host_option():
    assert HOST == "127.0.0.1"
    assert "host" not in create_server.__code__.co_varnames
    server = create_server(0)
    try:
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.server_close()


def test_listener_returns_a_gif_and_prints_the_hit(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(ListenerHandler, "output", output)
    server = create_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        no_proxy = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with no_proxy.open(f"http://127.0.0.1:{port}/s.gif?d=leak", timeout=5) as reply:
            assert reply.headers["Content-Type"] == "image/gif"
            assert reply.read() == PIXEL
    finally:
        server.shutdown()
        server.server_close()
    assert "d = leak" in output.getvalue()
    assert attacker_listener.PORT == 9999
