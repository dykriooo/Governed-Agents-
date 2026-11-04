"""Execution engine. A run is a durable state machine: the plan, a cursor and an
encrypted context are checkpointed after every step, so pausing for a human and
restarting the backend both work the same way, by resuming from the cursor.

invoke_tool is the single gateway to tool execution. Order is fixed: validate
inputs, classify risk, decide by policy, write the audit record, then execute.
"""
import copy
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from sqlalchemy import select, update

from . import audit, policy
from .config import settings
from .db import Approval, AuditEvent, Policy, Run, TaskGrant, ToolCall, User, session_scope, utcnow
from .planner import UnsupportedTask, make_plan, validate_plan
from .security import decrypt, encrypt, mask_for_review, redact, stable_hash
from .tools import REGISTRY, NeedsInput, RecoverableToolError, ToolContext, ToolFailure

ACTIVE = {"queued", "planning", "running"}
TERMINAL = {"completed", "failed", "blocked", "rejected"}
_pool = ThreadPoolExecutor(max_workers=settings.max_workers, thread_name_prefix="agent")


class RunBlocked(Exception):
    def __init__(self, reasons: list[dict]):
        super().__init__("; ".join(r["why"] for r in reasons))
        self.reasons = reasons


class AwaitingApproval(Exception):
    pass


class StepFailed(Exception):
    pass


class BadRequest(Exception):
    pass


class Forbidden(Exception):
    pass


def resolve(value: Any, ctx: dict, actor: dict, strict: bool = True) -> Any:
    """Substitute $ctx.x.y and $actor.x references. With strict=False, references
    that can't be resolved yet stay in place (used when preflighting a plan)."""
    if isinstance(value, dict):
        return {key: resolve(item, ctx, actor, strict) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve(item, ctx, actor, strict) for item in value]
    if isinstance(value, str) and value.startswith("$"):
        root, _, path = value[1:].partition(".")
        current: Any = {"ctx": ctx, "actor": actor}.get(root)
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                if strict:
                    raise StepFailed(f"Reference {value} could not be resolved")
                return value
            current = current[part]
        return current
    return value


def _actor(session, run: Run) -> dict:
    user = session.get(User, run.owner_id)
    return {"id": user.id, "username": user.username, "role": user.role}


def _claim(run_id: str, from_states: set[str], to_state: str) -> bool:
    """Atomic status change, so a run can never have two workers."""
    with session_scope() as session:
        result = session.execute(
            update(Run).where(Run.id == run_id, Run.status.in_(from_states)).values(status=to_state)
        )
        return result.rowcount == 1


def _save_plan_status(run_id: str, index: int, status: str, advance: bool = False) -> None:
    with session_scope() as session:
        run = session.get(Run, run_id)
        plan = copy.deepcopy(run.plan)
        plan[index]["status"] = status
        run.plan = plan
        if advance:
            run.cursor = index + 1


def invoke_tool(run_id: str, index: int, step: dict, ctx: dict, actor: dict) -> dict:
    name = step["tool"]
    tool = REGISTRY.get(name)
    actor_name = f"agent:{actor['username']}"

    if tool is None:
        decision = policy.unknown_tool_decision(name)
        args: dict = step.get("args", {})
        inputs = None
    else:
        args = resolve(step.get("args", {}), ctx, actor)
        try:
            inputs = tool.input_model.model_validate(args)
        except ValueError as exc:
            with session_scope() as session:
                session.add(ToolCall(run_id=run_id, step_index=index, tool=name, args=redact(args), risk="high",
                                     decision="deny", status="failed", error="Invalid tool input",
                                     reasons=[{"policy": "Input validation", "effect": "deny", "why": "Invalid tool input"}]))
            audit.record("tool.invalid_input", actor_name, run_id, tool=name)
            raise StepFailed(f"{name} received invalid input: {exc}") from exc
        args = inputs.model_dump()
        risk = tool.risk_for(inputs)
        try:
            decision = policy.evaluate(name, tool.tags, risk, args, actor)
        except Exception as exc:  # the policy engine failing must never let a call through
            decision = policy.Decision("deny", risk, [{"policy_id": None, "policy": "Policy engine", "effect": "deny",
                                                       "hard": True, "why": f"Policy evaluation failed: {type(exc).__name__}"}])

    args_hash = stable_hash({"tool": name, "args": args})
    with session_scope() as session:
        call = ToolCall(run_id=run_id, step_index=index, tool=name, args=redact(args), args_hash=args_hash,
                        risk=decision.risk, decision=decision.effect, reasons=decision.reasons)
        session.add(call)
        session.flush()
        call_id = call.id
    audit.record("policy.decision", "policy-engine", run_id, call_id, tool=name, risk=decision.risk,
                 decision=decision.effect, reasons=[r["policy"] for r in decision.reasons], args=args)

    if decision.effect == "deny":
        audit.record("tool.blocked", "policy-engine", run_id, call_id, tool=name)
        raise RunBlocked(decision.reasons)

    if decision.effect == "require_approval":
        approval_id = _consume_approval(run_id, index, name, args_hash, decision.required_role)
        if approval_id is not None:
            with session_scope() as session:
                session.get(ToolCall, call_id).approval_id = approval_id
            audit.record("approval.consumed", actor_name, run_id, call_id, approval_id=approval_id, tool=name)
        else:
            grant = _find_task_grant(run_id, tool, args, decision.required_role)
            if grant is None:
                _request_approval(run_id, index, tool, inputs, args, args_hash, decision, call_id)
                raise AwaitingApproval()
            with session_scope() as session:
                call = session.get(ToolCall, call_id)
                call.reasons = [*decision.reasons, {
                    "policy_id": None, "policy": "Allowed for this task", "effect": "allow", "grant_id": grant["id"],
                    "why": f"{grant['granted_by']} allowed this for the rest of the task."}]
            audit.record("grant.used", actor_name, run_id, call_id, grant_id=grant["id"], tool=name)

    return _execute(tool, inputs, run_id, call_id, actor)


def _consume_approval(run_id: str, index: int, tool: str, args_hash: str, required_role: str) -> str | None:
    """An approval authorizes exactly one execution of exactly these arguments,
    at the authority level policy demands right now."""
    with session_scope() as session:
        candidates = session.scalars(
            select(Approval).where(
                Approval.run_id == run_id, Approval.step_index == index, Approval.tool == tool,
                Approval.args_hash == args_hash, Approval.status == "approved", Approval.consumed.is_(False),
            )
        ).all()
        for approval in candidates:
            if policy.ROLE_RANK.get(approval.required_role, 0) < policy.ROLE_RANK.get(required_role, 2):
                continue
            result = session.execute(
                update(Approval).where(Approval.id == approval.id, Approval.consumed.is_(False)).values(consumed=True)
            )
            if result.rowcount == 1:
                return approval.id
    return None


def _grant_key(args: dict) -> tuple[str | None, str | None]:
    method = args.get("method")
    return policy.host_of(args.get("url")), method.upper() if isinstance(method, str) else None


def _find_task_grant(run_id: str, tool, args: dict, required_role: str) -> dict | None:
    if tool.tags & policy.IRREVERSIBLE_TAGS:
        return None
    host, method = _grant_key(args)
    with session_scope() as session:
        grants = session.scalars(select(TaskGrant).where(
            TaskGrant.run_id == run_id, TaskGrant.tool == tool.name,
            TaskGrant.host.is_(host) if host is None else TaskGrant.host == host,
            TaskGrant.method.is_(method) if method is None else TaskGrant.method == method,
        )).all()
        for grant in grants:
            if policy.ROLE_RANK.get(grant.required_role, 0) >= policy.ROLE_RANK.get(required_role, 2):
                return {"id": grant.id, "granted_by": grant.granted_by}
    return None


def approval_scopes(approval: Approval) -> list[str]:
    """Which ways of saying yes this request offers. Irreversible actions are
    decided one at a time. "Always" only replaces the default prompt, because an
    explicit ask rule outranks allow rules and a standing yes would have no effect."""
    tool = REGISTRY.get(approval.tool)
    if tool is None or tool.tags & policy.IRREVERSIBLE_TAGS:
        return ["once"]
    scopes = ["once", "task"]
    if all(reason.get("policy_id") is None for reason in approval.reasons):
        scopes.append("always")
    return scopes


def grant_target(approval: Approval) -> str:
    """Plain description of what a wider approval would cover."""
    host, method = _grant_key(decrypt(approval.review_enc, {}))
    target = f"{method} requests" if method else approval.tool
    return f"{target} to {host}" if host else target


def _standing_rule(approval: Approval, username: str) -> Policy:
    args = decrypt(approval.review_enc, {})
    host, method = _grant_key(args)
    conditions = []
    if host:
        conditions.append({"field": "args.url", "op": "domain_in", "value": [host]})
    if method:
        conditions.append({"field": "args.method", "op": "eq", "value": args["method"]})
    target = grant_target(approval)
    return Policy(name=f"Always allow {target}", effect="allow", match={"tools": [approval.tool]}, conditions=conditions,
                  description=f"{username} chose \"Always allow\" while reviewing a request. Hard denies still apply.",
                  created_by=username)


def _request_approval(run_id, index, tool, inputs, args, args_hash, decision, call_id) -> None:
    with session_scope() as session:
        approval = Approval(
            run_id=run_id, step_index=index, tool=tool.name, args_hash=args_hash,
            review_enc=encrypt(mask_for_review(args)),
            summary=tool.summarize(inputs) if tool.summarize else f"Run {tool.name}",
            consequences=tool.consequences(inputs) if tool.consequences else f"The agent runs {tool.name} with the values shown.",
            risk=decision.risk, reasons=decision.reasons, required_role=decision.required_role,
        )
        session.add(approval)
        session.flush()
        approval_id = approval.id
        session.get(ToolCall, call_id).approval_id = approval_id
    audit.record("approval.requested", "policy-engine", run_id, call_id, approval_id=approval_id, tool=tool.name,
                 required_role=decision.required_role)


def _execute(tool, inputs, run_id: str, call_id: str, actor: dict) -> dict:
    context = ToolContext(run_id=run_id, owner_id=actor["id"], owner_username=actor["username"])
    actor_name = f"agent:{actor['username']}"
    audit.record("tool.started", actor_name, run_id, call_id, tool=tool.name)  # no audit record, no execution
    started = time.monotonic()
    attempt = 0
    while True:
        attempt += 1
        with session_scope() as session:
            call = session.get(ToolCall, call_id)
            call.status, call.attempts = "running", attempt
        try:
            output = tool.fn(inputs, context)
        except RecoverableToolError as exc:
            audit.record("tool.retryable_error", actor_name, run_id, call_id, tool=tool.name, attempt=attempt, error=str(exc))
            if attempt < settings.max_attempts:
                time.sleep(settings.retry_backoff_seconds * 2 ** (attempt - 1))
                continue
            _finish_call(call_id, "failed", started, error=str(exc))
            audit.record("tool.failed", actor_name, run_id, call_id, tool=tool.name, error=str(exc), attempts=attempt)
            raise StepFailed(f"{tool.name} kept failing after {attempt} attempts: {exc}") from exc
        except NeedsInput as exc:
            _finish_call(call_id, "needs_input", started, error=str(exc))
            audit.record("tool.needs_input", actor_name, run_id, call_id, tool=tool.name,
                         missing=[f["name"] for f in exc.fields])
            raise
        except ToolFailure as exc:
            _finish_call(call_id, "failed", started, error=str(exc))
            audit.record("tool.failed", actor_name, run_id, call_id, tool=tool.name, error=str(exc), attempts=attempt)
            raise StepFailed(str(exc)) from exc
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            _finish_call(call_id, "failed", started, error=message)
            audit.record("tool.failed", actor_name, run_id, call_id, tool=tool.name, error=message, attempts=attempt)
            raise StepFailed(f"{tool.name} crashed: {message}") from exc
        _finish_call(call_id, "succeeded", started, output=output)
        audit.record("tool.succeeded", actor_name, run_id, call_id, tool=tool.name, attempts=attempt, output=output)
        return output


def _finish_call(call_id: str, status: str, started: float, output=None, error=None) -> None:
    with session_scope() as session:
        call = session.get(ToolCall, call_id)
        call.status = status
        call.duration_ms = (time.monotonic() - started) * 1000
        call.output = redact(output) if output is not None else None
        call.error = redact(error) if error else None


def preflight(steps: list[dict], ctx: dict, actor: dict) -> list[dict]:
    """Annotate each step with its expected decision. Returns any hard denies."""
    denied = []
    for item in steps:
        tool = REGISTRY[item["tool"]]
        args = resolve(item.get("args", {}), ctx, actor, strict=False)
        try:
            inputs = tool.input_model.model_construct(**args)
            risk = tool.risk_for(inputs)
        except (AttributeError, TypeError):
            risk = "high"
        decision = policy.evaluate(item["tool"], tool.tags, risk, args, actor, preflight=True)
        item.update(risk=risk, expected_decision=decision.effect,
                    status="blocked" if decision.effect == "deny" else "pending",
                    policies=[r["policy"] for r in decision.reasons])
        if decision.effect == "deny":
            denied.extend(decision.reasons)
    return denied


def _plan_run(run_id: str) -> None:
    with session_scope() as session:
        run = session.get(Run, run_id)
        instruction, actor = run.instruction, _actor(session, run)
        ctx = decrypt(run.context_enc, {})
        actor_name = f"agent:{actor['username']}"
    plan = make_plan(instruction)
    denied = preflight(plan.steps, ctx, actor)
    with session_scope() as session:
        run = session.get(Run, run_id)
        run.workflow, run.planner, run.planner_note, run.plan = plan.workflow, plan.planner, plan.note, plan.steps
    audit.record("plan.created", actor_name, run_id, workflow=plan.workflow, planner=plan.planner, note=plan.note,
                 steps=[item["tool"] for item in plan.steps])
    if denied:
        # A denial at plan time is still a policy decision on a tool call: record it
        # as one (never executed), so reports and metrics count it.
        for index, item in enumerate(plan.steps):
            if item["expected_decision"] != "deny":
                continue
            reasons = [r for r in denied if r["policy"] in item["policies"]]
            with session_scope() as session:
                call = ToolCall(run_id=run_id, step_index=index, tool=item["tool"], args=redact(item.get("args", {})),
                                args_hash=stable_hash({"tool": item["tool"], "args": item.get("args", {})}),
                                risk=item["risk"], decision="deny", reasons=reasons)
                session.add(call)
                session.flush()
                call_id = call.id
            audit.record("policy.decision", "policy-engine", run_id, call_id, tool=item["tool"], risk=item["risk"],
                         decision="deny", reasons=[r["policy"] for r in reasons], stage="plan")
        audit.record("plan.blocked", "policy-engine", run_id, reasons=[r["policy"] for r in denied])
        raise RunBlocked(denied)


def _close(run_id: str, status: str, error: str | None = None) -> None:
    with session_scope() as session:
        run = session.get(Run, run_id)
        run.status, run.error, run.finished_at = status, redact(error) if error else None, utcnow()
    audit.record(f"run.{status}", "engine", run_id, error=error)
    report = build_report(run_id)
    with session_scope() as session:
        session.get(Run, run_id).report = report


def _pause(run_id: str, status: str, missing: list | None = None) -> None:
    with session_scope() as session:
        run = session.get(Run, run_id)
        run.status, run.missing = status, missing or []
    audit.record(f"run.{status}", "engine", run_id)


def _work(run_id: str) -> None:
    """Worker body. Never raises: every outcome ends in a recorded run state."""
    try:
        if _claim(run_id, {"queued"}, "planning"):
            with session_scope() as session:
                has_plan = bool(session.get(Run, run_id).plan)
            if not has_plan:
                _plan_run(run_id)
            _claim(run_id, {"planning"}, "running")
        _advance(run_id)
    except RunBlocked as exc:
        _close(run_id, "blocked", str(exc))
    except UnsupportedTask as exc:
        _close(run_id, "failed", str(exc))
    except StepFailed as exc:
        _close(run_id, "failed", str(exc))
    except AwaitingApproval:
        _pause(run_id, "awaiting_approval")
    except NeedsInput as exc:
        _pause(run_id, "awaiting_input", exc.fields)
    except Exception as exc:  # last resort, so a run can never hang silently
        _close(run_id, "failed", f"Internal error: {type(exc).__name__}: {exc}")


def _advance(run_id: str) -> None:
    while True:
        with session_scope() as session:
            run = session.get(Run, run_id)
            if run.status != "running":
                return
            cursor, plan = run.cursor, copy.deepcopy(run.plan)
            ctx = decrypt(run.context_enc, {})
            actor = _actor(session, run)
            if cursor >= len(plan):
                break
            if run.tool_calls_used >= settings.max_tool_calls:
                raise StepFailed(f"Stopped: the limit of {settings.max_tool_calls} tool calls was reached")
            run.tool_calls_used += 1
        step = plan[cursor]
        _save_plan_status(run_id, cursor, "running")
        try:
            output = invoke_tool(run_id, cursor, step, ctx, actor)
        except RunBlocked:
            _save_plan_status(run_id, cursor, "blocked")
            raise
        except AwaitingApproval:
            _save_plan_status(run_id, cursor, "awaiting_approval")
            raise
        except NeedsInput:
            _save_plan_status(run_id, cursor, "awaiting_input")
            raise
        except StepFailed:
            _save_plan_status(run_id, cursor, "failed")
            raise
        if step.get("save_as"):
            ctx[step["save_as"]] = output
        with session_scope() as session:
            session.get(Run, run_id).context_enc = encrypt(ctx)
        _save_plan_status(run_id, cursor, "succeeded", advance=True)
    _close(run_id, "completed")


def create_run(owner_id: str, instruction: str, document_ids: list[str], is_eval: bool = False,
               forged_plan: list[dict] | None = None) -> str:
    """forged_plan bypasses the planner and preflight. Only the evaluation suite
    passes it, to prove the runtime gate holds even if planning is compromised."""
    ctx = {"portal_url": settings.portal_url, "document_ids": document_ids, "user_inputs": {}}
    with session_scope() as session:
        run = Run(owner_id=owner_id, instruction=instruction, document_ids=document_ids, is_eval=is_eval,
                  context_enc=encrypt(ctx))
        if forged_plan is not None:
            problem = validate_plan(copy.deepcopy(forged_plan))
            for item in forged_plan:
                item.setdefault("status", "pending")
            run.plan, run.planner, run.workflow = forged_plan, "forged", "forged"
            run.planner_note = problem
        session.add(run)
        session.flush()
        run_id = run.id
        username = session.get(User, owner_id).username
    audit.record("run.created", f"user:{username}", run_id, instruction=instruction, documents=len(document_ids))
    _pool.submit(_work, run_id)
    return run_id


def supply_input(run_id: str, user: dict, values: dict[str, str]) -> None:
    with session_scope() as session:
        run = session.get(Run, run_id)
        if run is None or run.owner_id != user["id"]:
            raise Forbidden("Only the person who started this task can supply its information")
        if run.status != "awaiting_input":
            raise BadRequest("This task is not waiting for information")
        expected = {field["name"] for field in run.missing}
        ctx = decrypt(run.context_enc, {})
        ctx["user_inputs"].update({k: str(v).strip() for k, v in values.items() if k in expected and str(v).strip()})
        run.context_enc = encrypt(ctx)
        fields = sorted(expected & set(values))
    audit.record("input.supplied", f"user:{user['username']}", run_id, fields=fields)
    if _claim(run_id, {"awaiting_input"}, "running"):
        _pool.submit(_work, run_id)


def retry_run(run_id: str, user: dict) -> None:
    """Resume a failed run from its last checkpoint."""
    with session_scope() as session:
        run = session.get(Run, run_id)
        if run is None or (run.owner_id != user["id"] and user["role"] != "admin"):
            raise Forbidden("You can't retry this task")
        if run.status != "failed" or not run.plan:
            raise BadRequest("Only a failed task that has a plan can be retried")
        run.error, run.finished_at, run.report, run.tool_calls_used = None, None, None, 0
    if _claim(run_id, {"failed"}, "running"):
        audit.record("run.retried", f"user:{user['username']}", run_id)
        _pool.submit(_work, run_id)


def decide_approval(approval_id: str, user: dict, approve: bool, note: str | None = None, scope: str = "once") -> dict:
    with session_scope() as session:
        approval = session.get(Approval, approval_id)
        if approval is None:
            raise BadRequest("No such approval")
        run = session.get(Run, approval.run_id)
        if user["role"] not in policy.ROLE_RANK:
            raise Forbidden("Only approvers and admins can decide approvals")
        if policy.ROLE_RANK[user["role"]] < policy.ROLE_RANK.get(approval.required_role, 2):
            raise Forbidden(f"This action needs authorization from the {approval.required_role} role")
        if run.owner_id == user["id"]:
            raise Forbidden("You can't approve a task you started yourself")
        if approve and scope not in approval_scopes(approval):
            raise BadRequest(f"This action can't be approved with the scope '{scope}'")
        if approve and scope == "always" and user["role"] != "admin":
            raise Forbidden("Only an administrator can choose Always allow")
        result = session.execute(
            update(Approval).where(Approval.id == approval_id, Approval.status == "pending").values(
                status="approved" if approve else "rejected", scope=scope if approve else None,
                decided_by=user["username"], decided_at=utcnow(), note=note)
        )
        if result.rowcount != 1:
            raise BadRequest("This approval has already been decided")
        run_id = approval.run_id
        rule_id = None
        if approve and scope == "task":
            host, method = _grant_key(decrypt(approval.review_enc, {}))
            session.add(TaskGrant(run_id=run_id, approval_id=approval_id, tool=approval.tool, host=host, method=method,
                                  required_role=approval.required_role, granted_by=user["username"]))
        elif approve and scope == "always":
            rule = _standing_rule(approval, user["username"])
            session.add(rule)
            session.flush()
            rule_id = rule.id
    audit.record("approval.approved" if approve else "approval.rejected", f"user:{user['username']}", run_id,
                 approval_id=approval_id, note=note, role=user["role"], scope=scope if approve else None, policy_id=rule_id)
    if approve:
        if _claim(run_id, {"awaiting_approval"}, "running"):
            _pool.submit(_work, run_id)
    elif _claim(run_id, {"awaiting_approval"}, "running"):
        with session_scope() as session:
            run = session.get(Run, run_id)
            plan = copy.deepcopy(run.plan)
            plan[run.cursor]["status"] = "rejected"
            run.plan = plan
        _close(run_id, "rejected", f"{user['username']} rejected this action" + (f": {note}" if note else ""))
    return {"run_id": run_id, "status": "approved" if approve else "rejected"}


def recover_interrupted_runs() -> list[str]:
    """After a restart, continue active runs from their last checkpoint. A step that
    was mid-flight runs again; tools check for completed work, and an approval
    already used for it is gone, so an interrupted high-risk step asks again."""
    with session_scope() as session:
        runs = session.scalars(select(Run).where(Run.status.in_(ACTIVE))).all()
        ids = [run.id for run in runs]
        for run in runs:
            run.status = "queued"
        if ids:
            session.execute(update(ToolCall).where(ToolCall.run_id.in_(ids), ToolCall.status == "running")
                            .values(status="interrupted"))
    for run_id in ids:
        audit.record("run.recovered", "engine", run_id)
        _pool.submit(_work, run_id)
    return ids


def build_report(run_id: str) -> dict:
    with session_scope() as session:
        run = session.get(Run, run_id)
        calls = session.scalars(select(ToolCall).where(ToolCall.run_id == run_id).order_by(ToolCall.created_at)).all()
        approvals = session.scalars(select(Approval).where(Approval.run_id == run_id).order_by(Approval.created_at)).all()
        events = session.scalars(select(AuditEvent).where(AuditEvent.run_id == run_id).order_by(AuditEvent.id)).all()
        finished = run.finished_at or utcnow()
        created = run.created_at if run.created_at.tzinfo else run.created_at.replace(tzinfo=utcnow().tzinfo)
        finished = finished if finished.tzinfo else finished.replace(tzinfo=utcnow().tzinfo)
        return {
            "run_id": run.id,
            "instruction": redact(run.instruction),
            "workflow": run.workflow,
            "planner": run.planner,
            "status": run.status,
            "error": run.error,
            "duration_seconds": round((finished - created).total_seconds(), 2),
            "tool_calls": [
                {"tool": c.tool, "risk": c.risk, "decision": c.decision, "status": c.status, "attempts": c.attempts,
                 "policies": [r.get("policy") for r in c.reasons]} for c in calls
            ],
            "policy_decisions": {
                "allow": sum(c.decision == "allow" for c in calls),
                "require_approval": sum(c.decision == "require_approval" for c in calls),
                "deny": sum(c.decision == "deny" for c in calls),
            },
            "approvals": [
                {"tool": a.tool, "status": a.status, "scope": a.scope, "decided_by": a.decided_by, "required_role": a.required_role,
                 "note": a.note, "decided_at": a.decided_at.isoformat() if a.decided_at else None} for a in approvals
            ],
            "audit_events": len(events),
            "audit_head": events[-1].hash if events else None,
        }
