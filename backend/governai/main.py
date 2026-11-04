"""REST API."""
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import select

from . import audit, engine, evaluation, planner, policy
from .config import settings
from .db import Approval, AuditEvent, Document, EvalReport, Policy, Run, ToolCall, User, init_db, session_scope
from .security import create_token, decrypt, encrypt, hash_password, read_token, verify_password
from .tools import REGISTRY, catalog

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
MAX_UPLOAD_BYTES = 1_000_000
OVERSIGHT_ROLES = {"approver", "admin", "auditor"}


def seed_users() -> None:
    with session_scope() as session:
        for username, role in [("student", "end_user"), ("approver", "approver"), ("admin", "admin"), ("auditor", "auditor")]:
            if not session.scalar(select(User).where(User.username == username)):
                session.add(User(username=username, role=role, password_hash=hash_password(settings.demo_password)))


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    seed_users()
    policy.seed_policies()
    engine.recover_interrupted_runs()
    yield


app = FastAPI(title="GovernAI", lifespan=lifespan)
bearer = HTTPBearer(auto_error=False)


@app.exception_handler(engine.Forbidden)
async def _forbidden(_: Request, exc: engine.Forbidden):
    return JSONResponse({"detail": str(exc)}, status_code=403)


@app.exception_handler(engine.BadRequest)
async def _bad_request(_: Request, exc: engine.BadRequest):
    return JSONResponse({"detail": str(exc)}, status_code=409)


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    user_id = read_token(credentials.credentials) if credentials else None
    if user_id:
        with session_scope() as session:
            user = session.get(User, user_id)
            if user:
                return {"id": user.id, "username": user.username, "role": user.role}
    raise HTTPException(401, "Please sign in")


def require_role(*roles: str):
    def check(user: dict = Depends(current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(403, f"This needs one of these roles: {', '.join(roles)}")
        return user

    return check


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


class LoginIn(BaseModel):
    username: str
    password: str


@app.post("/auth/login")
def login(body: LoginIn):
    with session_scope() as session:
        user = session.scalar(select(User).where(User.username == body.username))
        if not user or not verify_password(body.password, user.password_hash):
            raise HTTPException(401, "Wrong username or password")
        result = {"token": create_token(user.id), "user": {"id": user.id, "username": user.username, "role": user.role}}
    audit.record("auth.login", f"user:{body.username}")
    return result


@app.get("/me")
def me(user: dict = Depends(current_user)):
    return user


@app.get("/tools")
def tools(_: dict = Depends(current_user)):
    return catalog()


def _document_row(document: Document) -> dict:
    return {"id": document.id, "filename": document.filename, "created_at": iso(document.created_at)}


def _save_document(owner_id: str, filename: str, text: str) -> dict:
    with session_scope() as session:
        document = Document(owner_id=owner_id, filename=filename, content_enc=encrypt(text))
        session.add(document)
        session.flush()
        return _document_row(document)


@app.post("/documents", status_code=201)
async def upload_document(file: UploadFile = File(...), user: dict = Depends(require_role("end_user", "approver", "admin"))):
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Files can be up to 1 MB")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(415, "Only text files are supported for now") from None
    row = _save_document(user["id"], file.filename or "document.txt", text)
    audit.record("document.uploaded", f"user:{user['username']}", document_id=row["id"], filename=row["filename"])
    return row


@app.post("/documents/samples", status_code=201)
def load_samples(user: dict = Depends(require_role("end_user", "approver", "admin"))):
    return [_save_document(user["id"], path.name, path.read_text()) for path in sorted(SAMPLES.glob("*.txt"))]


@app.get("/documents")
def list_documents(user: dict = Depends(current_user)):
    with session_scope() as session:
        rows = session.scalars(select(Document).where(Document.owner_id == user["id"]).order_by(Document.created_at.desc()))
        return [_document_row(row) for row in rows]


class RunIn(BaseModel):
    instruction: str = Field(min_length=3, max_length=2000)
    document_ids: list[str] = []


@app.post("/runs", status_code=201)
def create_run(body: RunIn, user: dict = Depends(require_role("end_user", "approver", "admin"))):
    with session_scope() as session:
        owned = set(session.scalars(select(Document.id).where(Document.owner_id == user["id"], Document.id.in_(body.document_ids))))
    if owned != set(body.document_ids):
        raise HTTPException(403, "You can only use your own documents")
    return {"id": engine.create_run(user["id"], body.instruction, body.document_ids)}


def _run_row(run: Run, owner: str | None = None) -> dict:
    return {
        "id": run.id, "instruction": run.instruction, "status": run.status, "workflow": run.workflow,
        "planner": run.planner, "planner_note": run.planner_note, "owner": owner, "error": run.error,
        "created_at": iso(run.created_at), "finished_at": iso(run.finished_at), "cursor": run.cursor,
        "steps": len(run.plan or []), "is_eval": run.is_eval,
    }


@app.get("/runs")
def list_runs(include_eval: bool = False, user: dict = Depends(current_user)):
    with session_scope() as session:
        query = select(Run, User.username).join(User, User.id == Run.owner_id).order_by(Run.created_at.desc()).limit(100)
        if user["role"] not in OVERSIGHT_ROLES:
            query = query.where(Run.owner_id == user["id"])
        if not include_eval:
            query = query.where(Run.is_eval.is_(False))
        return [_run_row(run, owner) for run, owner in session.execute(query)]


def _can_view(run: Run, user: dict) -> bool:
    return run.owner_id == user["id"] or user["role"] in OVERSIGHT_ROLES


def _can_see_review_data(run: Run, user: dict) -> bool:
    # Auditors see decisions and redacted logs, not applicants' personal data.
    return run.owner_id == user["id"] or user["role"] in policy.ROLE_RANK


def _approval_row(approval: Approval, include_review: bool, user: dict, run: Run | None = None, owner: str | None = None) -> dict:
    scopes = engine.approval_scopes(approval)
    return {
        "scope": approval.scope,
        "scopes": [scope for scope in scopes if scope != "always" or user["role"] == "admin"],
        "irreversible": engine.is_irreversible(approval.tool),
        "grant_target": engine.grant_target(approval),
        "id": approval.id, "run_id": approval.run_id, "tool": approval.tool, "summary": approval.summary,
        "consequences": approval.consequences, "risk": approval.risk, "reasons": approval.reasons,
        "required_role": approval.required_role, "status": approval.status, "decided_by": approval.decided_by,
        "decided_at": iso(approval.decided_at), "note": approval.note, "created_at": iso(approval.created_at),
        "review": decrypt(approval.review_enc) if include_review else None,
        "requested_by": owner, "instruction": run.instruction if run else None,
    }


def _event_row(event: AuditEvent) -> dict:
    return {"id": event.id, "run_id": event.run_id, "tool_call_id": event.tool_call_id, "ts": event.ts,
            "actor": event.actor, "type": event.type, "data": event.data, "hash": event.hash}


@app.get("/runs/{run_id}")
def get_run(run_id: str, user: dict = Depends(current_user)):
    with session_scope() as session:
        run = session.get(Run, run_id)
        if run is None or not _can_view(run, user):
            raise HTTPException(404, "No such task")
        owner = session.get(User, run.owner_id).username
        calls = session.scalars(select(ToolCall).where(ToolCall.run_id == run_id).order_by(ToolCall.created_at))
        approvals = session.scalars(select(Approval).where(Approval.run_id == run_id).order_by(Approval.created_at))
        events = session.scalars(select(AuditEvent).where(AuditEvent.run_id == run_id).order_by(AuditEvent.id))
        return {
            **_run_row(run, owner),
            "plan": run.plan,
            "missing": run.missing,
            "report": run.report,
            "tool_calls": [
                {"id": c.id, "step_index": c.step_index, "tool": c.tool, "args": c.args, "risk": c.risk,
                 "decision": c.decision, "reasons": c.reasons, "status": c.status, "attempts": c.attempts,
                 "output": c.output, "error": c.error, "duration_ms": c.duration_ms, "created_at": iso(c.created_at)}
                for c in calls
            ],
            "approvals": [_approval_row(a, _can_see_review_data(run, user), user) for a in approvals],
            "audit": [_event_row(event) for event in events],
        }


class InputIn(BaseModel):
    values: dict[str, str]


@app.post("/runs/{run_id}/input")
def supply_input(run_id: str, body: InputIn, user: dict = Depends(current_user)):
    engine.supply_input(run_id, user, body.values)
    return {"ok": True}


@app.post("/runs/{run_id}/retry")
def retry(run_id: str, user: dict = Depends(current_user)):
    engine.retry_run(run_id, user)
    return {"ok": True}


@app.get("/approvals")
def list_approvals(status: str = "pending", user: dict = Depends(require_role("approver", "admin", "auditor"))):
    with session_scope() as session:
        rows = session.execute(
            select(Approval, Run, User.username)
            .join(Run, Run.id == Approval.run_id).join(User, User.id == Run.owner_id)
            .where(Approval.status == status, Run.is_eval.is_(False)).order_by(Approval.created_at.desc()).limit(100)
        )
        return [_approval_row(a, user["role"] in policy.ROLE_RANK, user, run, owner) for a, run, owner in rows]


class DecisionIn(BaseModel):
    approve: bool
    note: str | None = Field(default=None, max_length=500)
    scope: str = "once"


@app.post("/approvals/{approval_id}/decision")
def decide(approval_id: str, body: DecisionIn, user: dict = Depends(current_user)):
    return engine.decide_approval(approval_id, user, body.approve, body.note, body.scope)


def _policy_row(rule: Policy) -> dict:
    return {
        "id": rule.id, "name": rule.name, "description": rule.description, "source_text": rule.source_text,
        "effect": rule.effect, "hard": rule.hard, "locked": rule.locked, "enabled": rule.enabled, "match": rule.match,
        "conditions": rule.conditions, "required_role": rule.required_role, "created_by": rule.created_by,
        "created_at": iso(rule.created_at),
    }


def _rule_problem(values: dict) -> str | None:
    """Checks that need the tool registry, on top of policy.validate_rule."""
    if problem := policy.validate_rule(values):
        return problem
    named = (values.get("match") or {}).get("tools") or []
    if unknown := [name for name in named if name not in REGISTRY]:
        return f"Unknown tool: {', '.join(unknown)}"
    if values.get("effect") == "allow" and any(REGISTRY[name].tags & policy.IRREVERSIBLE_TAGS for name in named):
        return "A rule can't allow submissions or payments. Choose Always allow while reviewing one instead."
    return None


@app.get("/policies")
def list_policies(_: dict = Depends(current_user)):
    with session_scope() as session:
        return [_policy_row(rule) for rule in session.scalars(select(Policy).order_by(Policy.created_at))]


class CompileIn(BaseModel):
    text: str = Field(min_length=3, max_length=500)


@app.post("/policies/compile")
def compile_policy(body: CompileIn, _: dict = Depends(require_role("admin"))):
    """Translate natural language into a structured rule, for the admin to review."""
    rule = policy.compile_rule_text(body.text)
    source = "patterns"
    if rule is None and settings.openai_api_key:
        rule, source = policy.compile_with_llm(body.text, planner.call_llm), "openai"
    if rule is None:
        raise HTTPException(422, "Couldn't turn that into a rule. Try: \"Do not make payments above ₹2,000\" or "
                                 "\"Only access approved websites: portal.example.edu\".")
    return {"rule": {"hard": False, "required_role": "approver", **rule}, "source": source}


class PolicyIn(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    description: str = ""
    source_text: str | None = None
    effect: str
    hard: bool = False
    required_role: str = "approver"
    match: dict[str, Any] = {}
    conditions: list[dict[str, Any]] = []


@app.post("/policies", status_code=201)
def create_policy(body: PolicyIn, user: dict = Depends(require_role("admin"))):
    values = body.model_dump()
    if problem := _rule_problem(values):
        raise HTTPException(422, problem)
    with session_scope() as session:
        rule = Policy(**values, created_by=user["username"])
        session.add(rule)
        session.flush()
        row = _policy_row(rule)
    audit.record("policy.created", f"user:{user['username']}", policy_id=row["id"], name=row["name"],
                 effect=row["effect"], conditions=row["conditions"])
    return row


class PolicyPatch(BaseModel):
    enabled: bool | None = None
    conditions: list[dict[str, Any]] | None = None


@app.patch("/policies/{policy_id}")
def update_policy(policy_id: str, body: PolicyPatch, user: dict = Depends(require_role("admin"))):
    with session_scope() as session:
        rule = session.get(Policy, policy_id)
        if rule is None:
            raise HTTPException(404, "No such policy")
        if body.enabled is False and rule.locked:
            raise HTTPException(409, "This is a locked safety policy and can't be disabled")
        if body.conditions is not None:
            if problem := _rule_problem({"effect": rule.effect, "match": rule.match, "conditions": body.conditions}):
                raise HTTPException(422, problem)
            rule.conditions = body.conditions
        if body.enabled is not None:
            rule.enabled = body.enabled
        row = _policy_row(rule)
    audit.record("policy.updated", f"user:{user['username']}", policy_id=policy_id, name=row["name"],
                 enabled=row["enabled"], conditions=row["conditions"])
    return row


@app.delete("/policies/{policy_id}", status_code=204)
def delete_policy(policy_id: str, user: dict = Depends(require_role("admin"))):
    with session_scope() as session:
        rule = session.get(Policy, policy_id)
        if rule is None:
            raise HTTPException(404, "No such policy")
        if rule.locked:
            raise HTTPException(409, "This is a locked safety policy and can't be deleted")
        name = rule.name
        session.delete(rule)
    audit.record("policy.deleted", f"user:{user['username']}", policy_id=policy_id, name=name)


@app.get("/metrics")
def metrics(_: dict = Depends(require_role("approver", "admin", "auditor"))):
    return evaluation.live_metrics()


def _report_row(report: EvalReport) -> dict:
    return {"id": report.id, "status": report.status, "triggered_by": report.triggered_by, "results": report.results,
            "metrics": report.metrics, "error": report.error, "created_at": iso(report.created_at),
            "finished_at": iso(report.finished_at)}


@app.post("/evaluations", status_code=202)
def start_evaluation(user: dict = Depends(require_role("admin"))):
    with session_scope() as session:
        if session.scalar(select(EvalReport).where(EvalReport.status == "running")):
            raise HTTPException(409, "An evaluation is already running")
        report = EvalReport(triggered_by=user["username"])
        session.add(report)
        session.flush()
        report_id = report.id
    audit.record("evaluation.started", f"user:{user['username']}", report_id=report_id)
    threading.Thread(target=evaluation.run_suite, args=(report_id,), daemon=True).start()
    return {"id": report_id}


@app.get("/evaluations")
def list_evaluations(_: dict = Depends(require_role("approver", "admin", "auditor"))):
    with session_scope() as session:
        rows = session.scalars(select(EvalReport).order_by(EvalReport.created_at.desc()).limit(10))
        return [_report_row(report) for report in rows]


@app.get("/audit")
def audit_log(limit: int = Query(200, le=1000), run_id: str | None = None,
              _: dict = Depends(require_role("admin", "auditor"))):
    with session_scope() as session:
        query = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)
        if run_id:
            query = query.where(AuditEvent.run_id == run_id)
        return [_event_row(event) for event in session.scalars(query)]


@app.get("/audit/verify")
def audit_verify(_: dict = Depends(require_role("admin", "auditor"))):
    return audit.verify_chain()
