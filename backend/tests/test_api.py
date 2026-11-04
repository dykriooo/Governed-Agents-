import json
import time

from governai import audit, planner
from governai.config import settings
from governai.db import AuditEvent, Document, Run, session_scope
from sqlalchemy import update
from governai.evaluation import ACADEMIC, PROFILE

TASK = "Complete my university admission application using my uploaded documents."


def upload(client, headers, name, text):
    response = client.post("/documents", headers=headers, files={"file": (name, text.encode(), "text/plain")})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def wait(client, headers, run_id, states, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = client.get(f"/runs/{run_id}", headers=headers).json()
        if run["status"] in states:
            return run
        time.sleep(0.1)
    raise AssertionError(f"stuck in {run['status']}")


def start(client, tokens, instruction=TASK):
    docs = [upload(client, tokens["student"], "p.txt", PROFILE), upload(client, tokens["student"], "a.txt", ACADEMIC)]
    response = client.post("/runs", headers=tokens["student"], json={"instruction": instruction, "document_ids": docs})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_requires_login(client):
    assert client.get("/runs").status_code == 401
    assert client.get("/runs", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.post("/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401


def test_role_boundaries(client, tokens):
    assert client.post("/policies", headers=tokens["student"], json={"name": "abc", "effect": "deny"}).status_code == 403
    assert client.post("/runs", headers=tokens["auditor"], json={"instruction": TASK}).status_code == 403
    assert client.get("/audit", headers=tokens["student"]).status_code == 403
    assert client.get("/approvals", headers=tokens["student"]).status_code == 403
    assert client.post("/evaluations", headers=tokens["approver"]).status_code == 403


def test_cannot_use_someone_elses_document(client, tokens):
    doc = upload(client, tokens["approver"], "x.txt", "private")
    response = client.post("/runs", headers=tokens["student"], json={"instruction": TASK, "document_ids": [doc]})
    assert response.status_code == 403


def test_documents_are_encrypted_at_rest(client, tokens):
    doc = upload(client, tokens["student"], "p.txt", PROFILE)
    with session_scope() as session:
        assert "Asha" not in session.get(Document, doc).content_enc


def test_full_workflow_through_the_api(client, tokens):
    run_id = start(client, tokens)
    paused = wait(client, tokens["student"], run_id, {"awaiting_approval"})
    assert [s["status"] for s in paused["plan"]][:7] == ["succeeded"] * 6 + ["awaiting_approval"]
    assert paused["planner"] == "rules"

    pending = [a for a in client.get("/approvals", headers=tokens["approver"]).json() if a["run_id"] == run_id]
    assert len(pending) == 1
    approval = pending[0]
    assert approval["review"]["fields"]["full_name"] == "Asha Raman"
    assert approval["review"]["fields"]["national_id"] == "•••• 1956"

    auditor_view = client.get("/approvals", headers=tokens["auditor"]).json()
    assert all(a["review"] is None for a in auditor_view)

    decide = f"/approvals/{approval['id']}/decision"
    assert client.post(decide, headers=tokens["student"], json={"approve": True}).status_code == 403
    assert client.post(decide, headers=tokens["approver"], json={"approve": True, "note": "ok"}).status_code == 200
    assert client.post(decide, headers=tokens["approver"], json={"approve": True}).status_code == 409

    done = wait(client, tokens["student"], run_id, {"completed", "failed"})
    assert done["status"] == "completed", done["error"]
    assert done["report"]["approvals"][0]["decided_by"] == "approver"
    # Decided twice on purpose: once when pausing, and again on resume, so a rule
    # tightened while the run was waiting still applies.
    assert done["report"]["policy_decisions"]["require_approval"] == 2
    submit_calls = [c for c in done["tool_calls"] if c["tool"] == "submit_form"]
    assert [c["attempts"] for c in submit_calls] == [0, 1]

    # Personal data never reaches the logs or the audit trail.
    logged = json.dumps([done["audit"], done["tool_calls"], done["report"]])
    for secret in ("Asha", "asha.raman@example.com", "4821 7730", "2001-03-14", "98765"):
        assert secret not in logged


def test_owner_cannot_approve_their_own_run_even_as_an_approver(client, tokens):
    docs = [upload(client, tokens["approver"], "p.txt", PROFILE), upload(client, tokens["approver"], "a.txt", ACADEMIC)]
    run_id = client.post("/runs", headers=tokens["approver"], json={"instruction": TASK, "document_ids": docs}).json()["id"]
    run = wait(client, tokens["approver"], run_id, {"awaiting_approval"})
    decide = f"/approvals/{run['approvals'][0]['id']}/decision"
    assert client.post(decide, headers=tokens["approver"], json={"approve": True}).status_code == 403
    assert client.post(decide, headers=tokens["admin"], json={"approve": False}).status_code == 200


def test_users_cannot_see_other_users_runs(client, tokens):
    docs = [upload(client, tokens["approver"], "p.txt", PROFILE)]
    run_id = client.post("/runs", headers=tokens["approver"],
                         json={"instruction": "Submit my expense claim from these receipts", "document_ids": docs}).json()["id"]
    assert client.get(f"/runs/{run_id}", headers=tokens["student"]).status_code == 404
    wait(client, tokens["approver"], run_id, {"failed"})


def test_unsupported_task_fails_with_a_clear_message(client, tokens):
    run_id = client.post("/runs", headers=tokens["student"], json={"instruction": "Book me a table"}).json()["id"]
    run = wait(client, tokens["student"], run_id, {"failed"})
    assert "supported workflow" in run["error"]


def test_locked_policies_cannot_be_disabled_or_deleted(client, tokens):
    rules = client.get("/policies", headers=tokens["admin"]).json()
    locked = next(r for r in rules if r["locked"])
    assert client.patch(f"/policies/{locked['id']}", headers=tokens["admin"], json={"enabled": False}).status_code == 409
    assert client.delete(f"/policies/{locked['id']}", headers=tokens["admin"]).status_code == 409


def test_new_policy_takes_effect_on_the_next_call(client, tokens):
    compiled = client.post("/policies/compile", headers=tokens["admin"], json={"text": "Do not make payments above ₹100"}).json()
    created = client.post("/policies", headers=tokens["admin"], json={"name": "Tight limit", **compiled["rule"]})
    assert created.status_code == 201, created.text
    rule_id = created.json()["id"]
    try:
        doc = upload(client, tokens["student"], "r.txt", "Expense: Taxi | 500 | travel")
        run_id = client.post("/runs", headers=tokens["student"],
                             json={"instruction": "File my expense claim", "document_ids": [doc]}).json()["id"]
        run = wait(client, tokens["student"], run_id, {"awaiting_approval"})
        assert run["approvals"][0]["required_role"] == "admin"
        client.post(f"/approvals/{run['approvals'][0]['id']}/decision", headers=tokens["admin"], json={"approve": False})
    finally:
        assert client.delete(f"/policies/{rule_id}", headers=tokens["admin"]).status_code == 204


def test_invalid_policy_is_rejected(client, tokens):
    response = client.post("/policies", headers=tokens["admin"], json={"name": "Loosen", "effect": "allow"})
    assert response.status_code == 422
    assert client.post("/policies/compile", headers=tokens["admin"], json={"text": "be nice"}).status_code == 422


def test_restart_recovery_resumes_from_checkpoint(client, tokens):
    from governai import engine

    run_id = start(client, tokens)
    wait(client, tokens["student"], run_id, {"awaiting_approval"})
    # Simulate a crash in the middle of a step, just after the validation checkpoint.
    with session_scope() as session:
        run = session.get(Run, run_id)
        run.status, run.cursor = "running", run.cursor - 1
    assert run_id in engine.recover_interrupted_runs()
    resumed = wait(client, tokens["student"], run_id, {"awaiting_approval"})
    assert sum(c["tool"] == "read_documents" for c in resumed["tool_calls"]) == 1
    assert sum(c["tool"] == "validate_form" for c in resumed["tool_calls"]) == 2
    pending = [a for a in resumed["approvals"] if a["status"] == "pending"]
    client.post(f"/approvals/{pending[-1]['id']}/decision", headers=tokens["approver"], json={"approve": False})


def test_tampering_with_the_audit_log_is_detected(client, tokens):
    assert client.get("/audit/verify", headers=tokens["auditor"]).json()["valid"] is True
    with session_scope() as session:
        event_id = session.query(AuditEvent).order_by(AuditEvent.id).first().id
        original = session.get(AuditEvent, event_id).actor
        session.execute(update(AuditEvent).where(AuditEvent.id == event_id).values(actor="someone-else"))
    try:
        result = audit.verify_chain()
        assert result["valid"] is False and result["broken_at"] == event_id
    finally:
        with session_scope() as session:
            session.execute(update(AuditEvent).where(AuditEvent.id == event_id).values(actor=original))
    assert audit.verify_chain()["valid"] is True


def test_llm_plan_used_when_valid_and_rejected_when_not(monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key", "test-key")
    good = {"steps": planner.rule_plan(TASK)[1]}
    monkeypatch.setattr(planner, "call_llm", lambda system, user: json.dumps(good))
    assert planner.make_plan(TASK).planner.startswith("openai:")

    skipping_validation = [s for s in good["steps"] if s["tool"] != "validate_form"]
    monkeypatch.setattr(planner, "call_llm", lambda system, user: json.dumps({"steps": skipping_validation}))
    result = planner.make_plan(TASK)
    assert result.planner == "rules" and "validated" in result.note

    bad_tool = [{"tool": "rm_rf", "args": {}}]
    monkeypatch.setattr(planner, "call_llm", lambda system, user: json.dumps({"steps": bad_tool}))
    assert planner.make_plan(TASK).planner == "rules"

    monkeypatch.setattr(planner, "call_llm", lambda system, user: "not json")
    assert planner.make_plan(TASK).planner == "rules"


def test_llm_never_sees_document_content(monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key", "test-key")
    seen = {}

    def fake(system, user):
        seen.update(system=system, user=user)
        return json.dumps({"steps": planner.rule_plan(TASK)[1]})

    monkeypatch.setattr(planner, "call_llm", fake)
    planner.make_plan(TASK)
    assert seen["user"] == TASK
    assert "Asha" not in seen["system"]


def test_an_approval_authorizes_only_one_execution(client, tokens):
    from governai import engine
    from governai.db import ToolCall

    run_id = start(client, tokens)
    run = wait(client, tokens["student"], run_id, {"awaiting_approval"})
    approval = run["approvals"][0]
    with session_scope() as session:
        call = session.query(ToolCall).filter_by(run_id=run_id, tool="submit_form").first()
        args_hash, step_index = call.args_hash, call.step_index
    client.post(f"/approvals/{approval['id']}/decision", headers=tokens["approver"], json={"approve": True})
    assert wait(client, tokens["student"], run_id, {"completed", "failed"})["status"] == "completed"
    assert engine._consume_approval(run_id, step_index, "submit_form", args_hash, "approver") is None


def test_custom_ask_rule_offers_every_scope_but_always_is_admin_only(client, tokens):
    created = client.post("/policies", headers=tokens["admin"], json={
        "name": "Ask before filling forms", "effect": "require_approval", "match": {"tools": ["fill_form"]}, "conditions": []})
    assert created.status_code == 201, created.text
    try:
        run_id = start(client, tokens)
        run = wait(client, tokens["student"], run_id, {"awaiting_approval"})
        assert run["approvals"][0]["tool"] == "fill_form"
        admin_view = client.get(f"/runs/{run_id}", headers=tokens["admin"]).json()["approvals"][0]
        assert admin_view["scopes"] == ["once", "task", "always"]
        decide = f"/approvals/{admin_view['id']}/decision"
        assert client.post(decide, headers=tokens["approver"], json={"approve": True, "scope": "always"}).status_code == 403
        assert client.post(decide, headers=tokens["approver"], json={"approve": True, "scope": "bogus"}).status_code == 409
        assert client.post(decide, headers=tokens["approver"], json={"approve": True, "scope": "task"}).status_code == 200
        deadline = time.monotonic() + 30
        pending = []
        while not pending and time.monotonic() < deadline:
            time.sleep(0.1)
            run = client.get(f"/runs/{run_id}", headers=tokens["student"]).json()
            pending = [a for a in run["approvals"] if a["status"] == "pending"]
        assert pending and pending[0]["tool"] == "submit_form"
        assert pending[0]["scopes"] == ["once", "task"] and pending[0]["irreversible"] is True
        client.post(f"/approvals/{pending[0]['id']}/decision", headers=tokens["approver"], json={"approve": False})
    finally:
        client.delete(f"/policies/{created.json()['id']}", headers=tokens["admin"])


def test_always_allow_is_only_offered_to_admins(client, tokens):
    from governai import engine
    from governai.planner import step

    with session_scope() as session:
        owner = session.query(Run).first().owner_id
    plan = [step("http_request", {"url": f"{settings.portal_url}/api/claims", "method": "POST", "body": {"items": [], "amount": 1}}, "post")]
    run_id = engine.create_run(owner, "post a draft claim", [], forged_plan=plan)
    run = wait(client, tokens["admin"], run_id, {"awaiting_approval"})
    assert run["approvals"][0]["scopes"] == ["once", "task", "always"]
    assert run["approvals"][0]["grant_target"] == f"POST requests to {settings.portal_host}"
    approver_view = client.get(f"/runs/{run_id}", headers=tokens["approver"]).json()["approvals"][0]
    assert approver_view["scopes"] == ["once", "task"]
    client.post(f"/approvals/{approver_view['id']}/decision", headers=tokens["approver"], json={"approve": False})


def test_api_refuses_allow_rules_on_irreversible_or_unknown_tools(client, tokens):
    for tool in ("submit_form", "submit_claim", "made_up_tool"):
        response = client.post("/policies", headers=tokens["admin"], json={
            "name": "Unlock it", "effect": "allow", "match": {"tools": [tool]}, "conditions": []})
        assert response.status_code == 422, tool


def test_existing_database_gets_the_new_column(client):
    from sqlalchemy import inspect, text
    from governai.db import engine as db_engine, init_db

    with db_engine.begin() as connection:
        connection.execute(text("ALTER TABLE approvals DROP COLUMN scope"))
    init_db()
    assert "scope" in {c["name"] for c in inspect(db_engine).get_columns("approvals")}
