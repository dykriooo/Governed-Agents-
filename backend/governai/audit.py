"""Append-only, hash-chained audit log. Changing or removing any past event
breaks the chain, which verify_chain() detects."""
import hashlib
import json
import threading

from sqlalchemy import select

from .db import AuditEvent, session_scope, utcnow
from .security import redact

_lock = threading.Lock()
GENESIS = "0" * 64


def _digest(prev_hash: str, ts: str, actor: str, event_type: str, run_id, tool_call_id, data: dict) -> str:
    payload = json.dumps(
        [prev_hash, ts, actor, event_type, run_id, tool_call_id, data], sort_keys=True, default=str
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def record(event_type: str, actor: str, run_id: str | None = None, tool_call_id: str | None = None, **data) -> None:
    clean = json.loads(json.dumps(redact(data), default=str))
    with _lock, session_scope() as session:
        last = session.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1))
        prev_hash = last.hash if last else GENESIS
        ts = utcnow().isoformat()
        session.add(
            AuditEvent(
                run_id=run_id,
                tool_call_id=tool_call_id,
                ts=ts,
                actor=actor,
                type=event_type,
                data=clean,
                prev_hash=prev_hash,
                hash=_digest(prev_hash, ts, actor, event_type, run_id, tool_call_id, clean),
            )
        )


def verify_chain() -> dict:
    with session_scope() as session:
        prev_hash = GENESIS
        count = 0
        for event in session.scalars(select(AuditEvent).order_by(AuditEvent.id)):
            count += 1
            expected = _digest(
                prev_hash, event.ts, event.actor, event.type, event.run_id, event.tool_call_id, event.data
            )
            if event.prev_hash != prev_hash or event.hash != expected:
                return {"valid": False, "events": count, "broken_at": event.id}
            prev_hash = event.hash
        return {"valid": True, "events": count, "head": prev_hash}
