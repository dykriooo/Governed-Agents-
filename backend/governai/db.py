"""Data layer: users, documents, runs, tool calls, approvals, policies, audit, memory."""
from contextlib import contextmanager
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .config import settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid4().hex[:12]


engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False, "timeout": 15} if settings.database_url.startswith("sqlite") else {},
)

if settings.database_url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(connection, _record):
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")

SessionLocal = sessionmaker(engine, expire_on_commit=False)


@contextmanager
def session_scope():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String, unique=True)
    password_hash: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String)  # end_user | approver | admin | auditor


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    filename: Mapped[str] = mapped_column(String)
    content_enc: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Run(Base):
    __tablename__ = "runs"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    instruction: Mapped[str] = mapped_column(Text)
    document_ids: Mapped[list] = mapped_column(JSON, default=list)
    workflow: Mapped[str | None] = mapped_column(String, nullable=True)
    planner: Mapped[str | None] = mapped_column(String, nullable=True)
    planner_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    # queued | planning | running | awaiting_input | awaiting_approval
    # | completed | failed | blocked | rejected
    status: Mapped[str] = mapped_column(String, default="queued")
    plan: Mapped[list] = mapped_column(JSON, default=list)
    cursor: Mapped[int] = mapped_column(Integer, default=0)  # checkpoint: next step to run
    context_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    missing: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    report: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    is_eval: Mapped[bool] = mapped_column(Boolean, default=False)
    tool_calls_used: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ToolCall(Base):
    __tablename__ = "tool_calls"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    step_index: Mapped[int] = mapped_column(Integer)
    tool: Mapped[str] = mapped_column(String)
    args: Mapped[dict] = mapped_column(JSON, default=dict)  # redacted
    args_hash: Mapped[str] = mapped_column(String, default="")
    risk: Mapped[str] = mapped_column(String, default="high")
    decision: Mapped[str] = mapped_column(String, default="deny")  # allow | require_approval | deny
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    approval_id: Mapped[str | None] = mapped_column(String, nullable=True)
    # not_executed | running | succeeded | failed | interrupted
    status: Mapped[str] = mapped_column(String, default="not_executed")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    output: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # redacted
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    step_index: Mapped[int] = mapped_column(Integer)
    tool: Mapped[str] = mapped_column(String)
    args_hash: Mapped[str] = mapped_column(String)  # approval is bound to these exact arguments
    review_enc: Mapped[str] = mapped_column(Text)
    summary: Mapped[str] = mapped_column(Text)
    consequences: Mapped[str] = mapped_column(Text)
    risk: Mapped[str] = mapped_column(String)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    required_role: Mapped[str] = mapped_column(String, default="approver")
    status: Mapped[str] = mapped_column(String, default="pending")  # pending | approved | rejected
    scope: Mapped[str | None] = mapped_column(String, nullable=True)  # once | task | always
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)  # single use
    decided_by: Mapped[str | None] = mapped_column(String, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TaskGrant(Base):
    """"Allow for this task": covers later calls with the same tool, host and method."""
    __tablename__ = "task_grants"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    approval_id: Mapped[str] = mapped_column(ForeignKey("approvals.id"))
    tool: Mapped[str] = mapped_column(String)
    host: Mapped[str | None] = mapped_column(String, nullable=True)
    method: Mapped[str | None] = mapped_column(String, nullable=True)
    required_role: Mapped[str] = mapped_column(String, default="approver")
    granted_by: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text, default="")
    source_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    effect: Mapped[str] = mapped_column(String)  # deny | require_approval | allow
    hard: Mapped[bool] = mapped_column(Boolean, default=False)
    locked: Mapped[bool] = mapped_column(Boolean, default=False)  # cannot be disabled or deleted
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    match: Mapped[dict] = mapped_column(JSON, default=dict)  # {"tools": [...], "tags": [...]}
    conditions: Mapped[list] = mapped_column(JSON, default=list)
    required_role: Mapped[str] = mapped_column(String, default="approver")
    created_by: Mapped[str] = mapped_column(String, default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    tool_call_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    ts: Mapped[str] = mapped_column(String)
    actor: Mapped[str] = mapped_column(String)
    type: Mapped[str] = mapped_column(String)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String)
    hash: Mapped[str] = mapped_column(String)


class Memory(Base):
    __tablename__ = "memories"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    source_run_id: Mapped[str | None] = mapped_column(String, nullable=True)
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvalReport(Base):
    __tablename__ = "eval_reports"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    status: Mapped[str] = mapped_column(String, default="running")  # running | finished | error
    triggered_by: Mapped[str] = mapped_column(String)
    results: Mapped[list] = mapped_column(JSON, default=list)
    metrics: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


def init_db() -> None:
    Base.metadata.create_all(engine)
    # create_all doesn't add columns to tables that already exist.
    if "scope" not in {column["name"] for column in inspect(engine).get_columns("approvals")}:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE approvals ADD COLUMN scope VARCHAR"))
