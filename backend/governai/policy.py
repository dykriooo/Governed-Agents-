"""Policy engine. Rules are data and can only tighten behaviour: there is no
"allow" effect, so no configuration can loosen the code-level floor below.

Floor (not configurable):
  * unknown tools are denied;
  * high-risk tools always need human approval;
  * a rule that cannot be evaluated counts as triggered (fail closed).

Precedence: deny > require_approval > allow. A deny never creates an approval
request, so hard-deny policies cannot be overridden by a human approver.
"""
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select

from .config import settings
from .db import Policy, session_scope
from .security import contains_pii

ROLE_RANK = {"approver": 1, "admin": 2}
OPS = {"gt", "gte", "eq", "ne", "domain_not_in", "contains_pii", "not_actor"}


@dataclass
class Decision:
    effect: str
    risk: str
    reasons: list[dict] = field(default_factory=list)
    required_role: str = "approver"


def host_of(url: Any) -> str | None:
    """host[:port] of an http(s) URL, or None if it is not one. urlsplit handles
    tricks such as http://approved.example@evil.com, whose host is evil.com."""
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url)
        hostname, port = parts.hostname, parts.port
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or not hostname:
        return None
    return f"{hostname}:{port}" if port else hostname


def domain_allowed(url: Any, allowed: list[str]) -> bool:
    host = host_of(url)
    return host is not None and host.lower() in {item.lower() for item in allowed}


def is_unresolved(value: Any) -> bool:
    if isinstance(value, str):
        return value.startswith("$")
    if isinstance(value, dict):
        return any(is_unresolved(item) for item in value.values())
    if isinstance(value, list):
        return any(is_unresolved(item) for item in value)
    return False


def _lookup(path: str, scope: dict) -> tuple[bool, Any]:
    current: Any = scope
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _number(value: Any) -> float:
    return float(value)  # raises for "6,000" or None: fails closed in _triggered


def _triggered(condition: dict, scope: dict, preflight: bool) -> bool:
    op = condition.get("op")
    found, value = _lookup(condition.get("field", ""), scope)
    if preflight and (not found or is_unresolved(value)):
        return False  # not knowable yet; re-evaluated with real values at runtime
    if not found or op not in OPS:
        return True
    try:
        if op == "gt":
            return _number(value) > _number(condition["value"])
        if op == "gte":
            return _number(value) >= _number(condition["value"])
        if op == "eq":
            return value == condition["value"]
        if op == "ne":
            return value != condition["value"]
        if op == "domain_not_in":
            return not domain_allowed(value, condition["value"])
        if op == "contains_pii":
            return contains_pii(value)
        return value != scope["actor"]["id"]  # not_actor
    except (KeyError, TypeError, ValueError):
        return True


def _applies(rule: Policy, tool: str, tags: set[str]) -> bool:
    match = rule.match or {}
    tools, wanted = match.get("tools") or [], match.get("tags") or []
    if not tools and not wanted:
        return True
    return tool in tools or bool(tags & set(wanted))


def load_rules() -> list[Policy]:
    with session_scope() as session:
        return list(session.scalars(select(Policy).where(Policy.enabled.is_(True))))


def evaluate(tool: str, tags: set[str], risk: str, args: dict, actor: dict, preflight: bool = False) -> Decision:
    scope = {"args": args, "actor": actor, "tool": tool, "risk": risk}
    denies, approvals = [], []
    required_role = "approver"
    for rule in load_rules():
        if not _applies(rule, tool, tags):
            continue
        # All conditions must hold for a rule to fire.
        if rule.conditions and not all(_triggered(c, scope, preflight) for c in rule.conditions):
            continue
        reason = {"policy_id": rule.id, "policy": rule.name, "effect": rule.effect, "hard": rule.hard, "why": rule.description}
        if rule.effect == "deny":
            denies.append(reason)
        else:
            approvals.append(reason)
            if ROLE_RANK.get(rule.required_role, 2) > ROLE_RANK.get(required_role, 2):
                required_role = rule.required_role
    if denies:
        return Decision("deny", risk, denies)
    if risk == "high" and not approvals:
        approvals.append(
            {"policy_id": None, "policy": "High-risk floor", "effect": "require_approval", "hard": False,
             "why": "High-risk actions always require human approval."}
        )
    if approvals:
        return Decision("require_approval", risk, approvals, required_role)
    return Decision(
        "allow", risk,
        [{"policy_id": None, "policy": f"{risk.title()}-risk default", "effect": "allow", "hard": False,
          "why": "Executed automatically and logged." if risk == "low" else "Executed with input validation and logging."}],
    )


def unknown_tool_decision(tool: str) -> Decision:
    return Decision(
        "deny", "high",
        [{"policy_id": None, "policy": "Tool registry", "effect": "deny", "hard": True,
          "why": f"'{tool}' is not a registered tool."}],
    )


def allowed_hosts() -> list[str]:
    """Hosts the browser may load, used to block redirects and embedded requests
    that a per-call policy check would never see. The portal is the floor."""
    hosts = {settings.portal_host}
    for rule in load_rules():
        for condition in rule.conditions or []:
            if condition.get("op") == "domain_not_in":
                hosts.update(condition.get("value") or [])
    return sorted(hosts)


def seed_policies() -> None:
    domains = [settings.portal_host]
    defaults = [
        dict(name="Only access approved websites", effect="deny", hard=True, locked=True,
             description="The agent may only reach allowlisted domains. Unapproved destinations are blocked and cannot be approved.",
             match={"tags": ["network"]},
             conditions=[{"field": "args.url", "op": "domain_not_in", "value": domains}]),
        dict(name="Never share personal information externally", effect="deny", hard=True, locked=True,
             description="Personal data may not leave through general-purpose outbound calls, even with approval.",
             match={"tags": ["external_transfer"]},
             conditions=[{"field": "args", "op": "contains_pii"}]),
        dict(name="Agent memory is private to its owner", effect="deny", hard=True, locked=True,
             description="An agent may only read or write the memory of the user it is acting for.",
             match={"tags": ["memory"]},
             conditions=[{"field": "args.owner_id", "op": "not_actor"}]),
        dict(name="Never submit a form without approval", effect="require_approval",
             description="Final submissions wait for a human approver.",
             match={"tags": ["submission"]}, conditions=[]),
        dict(name="Payments above ₹5,000 need additional authorization", effect="require_approval",
             required_role="admin",
             description="High-value payments must be authorized by an administrator, not just an approver.",
             match={"tags": ["payment"]},
             conditions=[{"field": "args.amount", "op": "gt", "value": 5000}]),
    ]
    with session_scope() as session:
        if session.scalar(select(Policy).limit(1)):
            return
        for values in defaults:
            session.add(Policy(**values))


_AMOUNT = r"(?:₹|rs\.?|inr)?\s*([\d,]+(?:\.\d+)?)"


def compile_rule_text(text: str) -> dict | None:
    """Offline natural-language compiler for the common policy shapes."""
    lower = text.lower().strip()
    if match := re.search(rf"payments?\s+(?:above|over|more than|exceeding)\s+{_AMOUNT}", lower):
        amount = float(match.group(1).replace(",", ""))
        return dict(effect="require_approval", required_role="admin", match={"tags": ["payment"]},
                    conditions=[{"field": "args.amount", "op": "gt", "value": amount}])
    if re.search(r"(only|just).*(website|domain|site)", lower):
        domains = re.findall(r"\b(?:[a-z0-9-]+\.)*[a-z0-9-]+(?:\.[a-z]{2,}|:\d+)(?::\d+)?\b", lower)
        if domains:
            return dict(effect="deny", hard=True, match={"tags": ["network"]},
                        conditions=[{"field": "args.url", "op": "domain_not_in", "value": domains}])
        return None
    if re.search(r"(personal|sensitive|private).*(extern|outside|third)", lower):
        return dict(effect="deny", hard=True, match={"tags": ["external_transfer"]},
                    conditions=[{"field": "args", "op": "contains_pii"}])
    if re.search(r"(never|don'?t|do not).*\b(submit|send)\b.*without", lower):
        return dict(effect="require_approval", match={"tags": ["submission"]}, conditions=[])
    if re.search(r"(never|don'?t|do not|block).*\b(external|outbound|http)\b", lower):
        return dict(effect="deny", hard=True, match={"tags": ["external_transfer"]}, conditions=[])
    return None


def compile_with_llm(text: str, client_call) -> dict | None:
    """Ask the model to translate a rule, then validate it like any other input."""
    raw = client_call(
        "Translate the policy into JSON with keys effect ('deny'|'require_approval'), hard (bool), "
        "required_role ('approver'|'admin'), match ({'tags': [...]} using submission, payment, network, "
        "external_transfer, memory), conditions (list of {field, op, value}; op in gt, gte, eq, ne, "
        "domain_not_in, contains_pii, not_actor; fields look like args.amount, args.url, or args for the whole call). "
        "Reply with JSON only.",
        text,
    )
    try:
        rule = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return rule if validate_rule(rule) is None else None


def validate_rule(rule: dict) -> str | None:
    if rule.get("effect") not in {"deny", "require_approval"}:
        return "effect must be 'deny' or 'require_approval'"
    if rule.get("required_role", "approver") not in ROLE_RANK:
        return "required_role must be 'approver' or 'admin'"
    if not isinstance(rule.get("match", {}), dict):
        return "match must be an object"
    conditions = rule.get("conditions", [])
    if not isinstance(conditions, list):
        return "conditions must be a list"
    for condition in conditions:
        if not isinstance(condition, dict) or condition.get("op") not in OPS or not condition.get("field"):
            return f"invalid condition: {condition}"
        if condition["op"] == "domain_not_in" and not isinstance(condition.get("value"), list):
            return "domain_not_in needs a list of domains"
        if condition["op"] in {"gt", "gte"}:
            try:
                float(condition.get("value"))
            except (TypeError, ValueError):
                return f"{condition['op']} needs a numeric value"
    return None
