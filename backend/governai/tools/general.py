"""Document processing, expense handling, REST calls, memory and reporting.

Document text is untrusted. Extraction here is deterministic and local on
purpose: applicant data never goes to an LLM provider, and instructions hidden
in a document have no path to influencing the plan.
"""
import difflib
import re
from typing import Any

import httpx
from pydantic import BaseModel
from sqlalchemy import select

from ..config import settings
from ..db import Document, Memory, session_scope
from ..security import MEMORY_SAFE_KEYS, decrypt
from .base import NeedsInput, RecoverableToolError, Tool, ToolContext, ToolFailure, register


def _normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9 ]", "", text.lower()).strip()


def _http(method: str, url: str, **kwargs) -> httpx.Response:
    try:
        # Redirects are not followed: a redirect could reach a host policy never saw.
        response = httpx.request(method, url, timeout=8, follow_redirects=False, **kwargs)
    except httpx.TransportError as exc:
        raise RecoverableToolError(f"{method} {url} failed: {exc}") from exc
    if response.status_code >= 500:
        raise RecoverableToolError(f"{method} {url} returned HTTP {response.status_code}")
    if response.status_code >= 300:
        raise ToolFailure(f"{method} {url} returned HTTP {response.status_code}")
    return response


class ReadDocumentsInput(BaseModel):
    document_ids: list[str]


def read_documents(inputs: ReadDocumentsInput, tc: ToolContext) -> dict:
    with session_scope() as session:
        rows = session.scalars(
            select(Document).where(Document.id.in_(inputs.document_ids), Document.owner_id == tc.owner_id)
        ).all()
        documents = [{"name": row.filename, "text": decrypt(row.content_enc)} for row in rows]
    if len(documents) != len(set(inputs.document_ids)):
        raise ToolFailure("One or more documents do not exist or do not belong to this user")
    return {"documents": documents, "count": len(documents)}


def parse_key_values(documents: list[dict]) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for document in documents:
        for line in document.get("text", "").splitlines():
            key, separator, value = line.partition(":")
            value = value.strip()
            if separator and value and len(key) <= 40:
                found.setdefault(_normalize(key), []).append(value)
    return found


def _match_values(field: dict, parsed: dict[str, list[str]]) -> list[str]:
    targets = {_normalize(field["label"]), _normalize(field["name"].replace("_", " "))}
    values: list[str] = []
    for key, candidates in parsed.items():
        if key in targets or any(difflib.SequenceMatcher(None, key, t).ratio() >= 0.88 for t in targets):
            values.extend(candidates)
    return list(dict.fromkeys(values))


def _check_format(field: dict, value: str) -> tuple[str | None, str | None]:
    """Returns (normalized value, problem)."""
    if field["type"] == "select":
        for option in field["options"]:
            if option.lower() == value.lower():
                return option, None
        return None, f"'{value}' is not one of the portal's options"
    if field["type"] == "date" and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return None, "must be a date in YYYY-MM-DD format"
    if field["type"] == "email" and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        return None, "is not a valid email address"
    return value, None


class ExtractInput(BaseModel):
    documents: dict[str, Any]
    form: dict[str, Any]
    memory: dict[str, Any] = {}
    user_inputs: dict[str, str] = {}


def extract_fields(inputs: ExtractInput, _: ToolContext) -> dict:
    parsed = parse_key_values(inputs.documents.get("documents", []))
    remembered = inputs.memory.get("values", {})
    values: dict[str, str] = {}
    sources: dict[str, str] = {}
    missing: list[dict] = []
    for field in inputs.form.get("fields", []):
        name = field["name"]
        problem = None
        raw = None
        source = None
        found = _match_values(field, parsed)
        if inputs.user_inputs.get(name):
            raw, source = inputs.user_inputs[name], "user"
        elif len(found) > 1:
            problem = f"documents disagree: {', '.join(found)}"
        elif found:
            raw, source = found[0], "document"
        elif remembered.get(name) and name in MEMORY_SAFE_KEYS:
            raw, source = remembered[name], "memory"
        if raw is not None:
            value, problem = _check_format(field, raw)
            if value is not None:
                values[name], sources[name] = value, source
                continue
        if field["required"] or problem:
            missing.append({"name": name, "label": field["label"], "type": field["type"],
                            "options": field["options"], "reason": problem or "not found in your documents"})
    if missing:
        raise NeedsInput(missing)
    return {"values": values, "sources": sources}


class ExtractExpensesInput(BaseModel):
    documents: dict[str, Any]


def extract_expenses(inputs: ExtractExpensesInput, _: ToolContext) -> dict:
    items = []
    for document in inputs.documents.get("documents", []):
        for line in document.get("text", "").splitlines():
            match = re.fullmatch(r"\s*Expense:\s*(.+?)\s*\|\s*([\d,]+(?:\.\d+)?)\s*\|\s*(\w+)\s*", line, re.I)
            if match:
                items.append({"description": match[1], "amount": float(match[2].replace(",", "")),
                              "category": match[3].lower()})
    if not items:
        raise ToolFailure("No expenses found. Upload receipts with lines like 'Expense: Taxi | 1200 | travel'.")
    return {"items": items}


RESTRICTED_CATEGORIES = {"alcohol", "personal", "entertainment"}
CATEGORY_CAPS = {"meals": 3000.0, "lodging": 8000.0, "travel": 15000.0}


class CheckExpensesInput(BaseModel):
    expenses: dict[str, Any]


def check_expense_policy(inputs: CheckExpensesInput, tc: ToolContext) -> dict:
    allowed, excluded = [], []
    for item in inputs.expenses["items"]:
        category, amount = item["category"], item["amount"]
        if category in RESTRICTED_CATEGORIES:
            excluded.append({**item, "reason": f"'{category}' expenses are not reimbursable"})
        elif category not in CATEGORY_CAPS:
            excluded.append({**item, "reason": f"unknown category '{category}'"})
        elif amount > CATEGORY_CAPS[category]:
            excluded.append({**item, "reason": f"over the {CATEGORY_CAPS[category]:.0f} cap for {category}"})
        else:
            allowed.append(item)
    if not allowed:
        raise ToolFailure("No expense in this claim is reimbursable under company policy")
    return {"employee": tc.owner_username, "items": allowed, "excluded": excluded,
            "amount": round(sum(item["amount"] for item in allowed), 2)}


class PrepareClaimInput(BaseModel):
    url: str
    claim: dict[str, Any]


def prepare_claim(inputs: PrepareClaimInput, _: ToolContext) -> dict:
    claim = inputs.claim
    payload = {"employee": claim.get("employee", ""), "items": claim["items"], "amount": claim["amount"]}
    return {"claim_id": _http("POST", f"{inputs.url}/api/claims", json=payload).json()["id"]}


class SubmitClaimInput(BaseModel):
    url: str
    claim_id: str
    amount: float


def submit_claim(inputs: SubmitClaimInput, _: ToolContext) -> dict:
    current = _http("GET", f"{inputs.url}/api/claims/{inputs.claim_id}.json").json()
    if current["status"] == "submitted":
        return {"claim_id": inputs.claim_id, "status": "submitted", "already_submitted": True}
    if current["amount"] != inputs.amount:
        raise ToolFailure(f"The claim amount changed after approval ({current['amount']}); not submitting")
    result = _http("POST", f"{inputs.url}/api/claims/{inputs.claim_id}/submit").json()
    return {"claim_id": inputs.claim_id, "status": result["status"], "amount": result["amount"]}


class HttpInput(BaseModel):
    url: str
    method: str = "GET"
    body: Any = None


def http_request(inputs: HttpInput, _: ToolContext) -> dict:
    kwargs = {"json": inputs.body} if inputs.body is not None else {}
    response = _http(inputs.method.upper(), inputs.url, **kwargs)
    return {"status_code": response.status_code, "bytes": len(response.content)}


class MemoryRecallInput(BaseModel):
    owner_id: str


def memory_recall(inputs: MemoryRecallInput, _: ToolContext) -> dict:
    with session_scope() as session:
        rows = session.scalars(
            select(Memory).where(Memory.owner_id == inputs.owner_id).order_by(Memory.created_at.desc()).limit(5)
        ).all()
        values: dict[str, Any] = {}
        for row in rows:  # newest first, so newer values win
            for key, value in row.content.items():
                values.setdefault(key, value)
    return {"values": values, "episodes": len(rows)}


class MemoryStoreInput(BaseModel):
    owner_id: str
    values: dict[str, Any]


def memory_store(inputs: MemoryStoreInput, tc: ToolContext) -> dict:
    kept = {key: value for key, value in inputs.values.items() if key in MEMORY_SAFE_KEYS}
    with session_scope() as session:
        session.add(Memory(owner_id=inputs.owner_id, source_run_id=tc.run_id, content=kept))
    return {"stored": sorted(kept), "discarded_count": len(inputs.values) - len(kept)}


class EmptyInput(BaseModel):
    pass


def generate_report(_: EmptyInput, tc: ToolContext) -> dict:
    # The full report is built when the run closes, once its final status is known.
    return {"run_id": tc.run_id, "report": "generated when the run closes"}


portal_note = f"Use the portal URL {settings.portal_url} via $ctx.portal_url."
register(Tool("read_documents", "Load the user's uploaded documents.", ReadDocumentsInput, read_documents,
              "low", {"documents"}, output_hint="{documents:[{name,text}],count}"))
register(Tool("extract_fields", "Match document contents to the form's fields; pauses to ask the user for anything missing.",
              ExtractInput, extract_fields, "low", {"documents"}, output_hint="{values,sources}"))
register(Tool("extract_expenses", "Read expense lines from uploaded receipts.", ExtractExpensesInput, extract_expenses,
              "low", {"documents"}, output_hint="{items}"))
register(Tool("check_expense_policy", "Categorize expenses, exclude restricted ones, calculate the reimbursement.",
              CheckExpensesInput, check_expense_policy, "low", {"expenses"},
              output_hint="{employee,items,excluded,amount}"))
register(Tool("prepare_claim", f"Create a draft claim through the expense API. {portal_note}", PrepareClaimInput,
              prepare_claim, "medium", {"network", "api"}, output_hint="{claim_id}"))
register(Tool("submit_claim", "Submit a reimbursement claim, which pays out money. Irreversible.", SubmitClaimInput,
              submit_claim, "high", {"network", "api", "submission", "payment"}, output_hint="{claim_id,status,amount}",
              summarize=lambda i: f"Submit reimbursement claim {i.claim_id} for ₹{i.amount:,.2f}",
              consequences=lambda i: f"₹{i.amount:,.2f} will be paid out to the employee. This cannot be undone by the agent."))
register(Tool("http_request", "Make a general HTTP request. Anything other than GET is treated as high risk.", HttpInput,
              http_request, lambda i: "low" if i.method.upper() == "GET" else "high", {"network", "external_transfer"},
              output_hint="{status_code,bytes}",
              summarize=lambda i: f"{i.method.upper()} {i.url}",
              consequences=lambda i: "Data is sent to a system outside GovernAI's control."))
register(Tool("memory_recall", "Recall non-sensitive details from this user's earlier sessions.", MemoryRecallInput,
              memory_recall, "low", {"memory"}, output_hint="{values,episodes}"))
register(Tool("memory_store", "Remember non-sensitive details for later sessions. Everything else is discarded.",
              MemoryStoreInput, memory_store, "low", {"memory"}, output_hint="{stored,discarded_count}"))
register(Tool("generate_report", "Mark the point at which the execution report is produced.", EmptyInput, generate_report,
              "low", set(), output_hint="{run_id,report}"))
