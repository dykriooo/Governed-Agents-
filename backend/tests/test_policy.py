import pytest

from governai import policy
from governai.config import settings
from governai.security import contains_pii, decrypt, encrypt, mask_for_review, redact

ACTOR = {"id": "u1", "username": "u", "role": "end_user"}
pytestmark = pytest.mark.usefixtures("client")
PORTAL = settings.portal_url


def decide(tool, tags, risk, args):
    return policy.evaluate(tool, set(tags), risk, args, ACTOR)


@pytest.mark.parametrize("url", [
    "http://evil.example/x",
    f"http://{settings.portal_host}@evil.example/x",
    "ftp://localhost/x",
    "not a url",
    "http://localhost:1/x",
    "http://[bad/x",
    None,
])
def test_only_exact_approved_hosts_pass(url):
    assert decide("http_request", {"network"}, "low", {"url": url}).effect == "deny"


def test_approved_host_allowed():
    assert decide("inspect_form", {"network"}, "low", {"url": PORTAL}).effect == "allow"


def test_high_risk_floor_applies_without_any_matching_rule():
    decision = decide("anything", set(), "high", {})
    assert decision.effect == "require_approval"


def test_submission_needs_approval_and_deny_outranks_it():
    assert decide("submit_form", {"network", "submission"}, "high", {"url": PORTAL}).effect == "require_approval"
    assert decide("submit_form", {"network", "submission"}, "high", {"url": "http://evil.example"}).effect == "deny"


@pytest.mark.parametrize("amount,role", [(5000, "approver"), (5000.01, "admin"), ("6,000", "admin"), (None, "admin")])
def test_payment_threshold_fails_closed_on_unreadable_amounts(amount, role):
    decision = decide("submit_claim", {"network", "submission", "payment"}, "high", {"url": PORTAL, "amount": amount})
    assert decision.effect == "require_approval"
    assert decision.required_role == role


@pytest.mark.parametrize("args", [
    {"url": PORTAL, "body": {"email": "a@b.co"}},
    {"url": PORTAL, "body": "call +91 98765 43210"},
    {"url": f"{PORTAL}/x?who=a@b.co", "body": None},
])
def test_personal_data_cannot_leave_even_to_approved_hosts_or_in_a_url(args):
    assert decide("http_request", {"network", "external_transfer"}, "high", args).effect == "deny"


def test_memory_is_scoped_to_the_actor():
    assert decide("memory_recall", {"memory"}, "low", {"owner_id": "u1"}).effect == "allow"
    assert decide("memory_recall", {"memory"}, "low", {"owner_id": "u2"}).effect == "deny"
    assert decide("memory_recall", {"memory"}, "low", {}).effect == "deny"


def test_unknown_operator_fails_closed():
    assert policy._triggered({"field": "args.x", "op": "bogus"}, {"args": {"x": 1}}, False) is True


@pytest.mark.parametrize("text,effect", [
    ("Do not make payments above ₹2,000", "require_approval"),
    ("Only access approved websites: portal.example.edu", "deny"),
    ("Never share personal information externally", "deny"),
    ("Never submit a form without approval", "require_approval"),
])
def test_natural_language_compiles_to_a_valid_rule(text, effect):
    rule = policy.compile_rule_text(text)
    assert rule["effect"] == effect
    assert policy.validate_rule(rule) is None


def test_payment_compile_parses_amount():
    assert policy.compile_rule_text("Do not make payments above ₹2,000")["conditions"][0]["value"] == 2000


def test_uncompilable_text_returns_none():
    assert policy.compile_rule_text("be nice to everyone") is None


def test_validate_rejects_an_allow_effect():
    assert policy.validate_rule({"effect": "allow"}) is not None


def test_redaction_and_masking():
    record = {"full_name": "Asha", "gpa": "8.7", "note": "mail a@b.co", "national_id": "4821 7730 1956"}
    clean = redact(record)
    assert "Asha" not in str(clean) and "a@b.co" not in str(clean) and "4821" not in str(clean)
    assert clean["gpa"] == "8.7"
    assert mask_for_review(record)["national_id"] == "•••• 1956"
    assert contains_pii(record)


def test_encryption_round_trip_hides_plaintext():
    token = encrypt({"secret": "4821"})
    assert "4821" not in token and decrypt(token) == {"secret": "4821"}


def test_browser_guard_blocks_unapproved_hosts_that_no_tool_call_named():
    """Redirects and links are never seen by the per-call policy check."""
    from governai.evaluation import Canary
    from governai.tools import ToolFailure
    from governai.tools.browser import browser_page

    canary = Canary()
    try:
        with pytest.raises(ToolFailure, match="unapproved host"):
            with browser_page() as page:
                page.goto(canary.url)
        # A subresource on an approved page is blocked too.
        with browser_page() as page:
            page.goto(f"{PORTAL}/")
            page.evaluate("url => fetch(url, {mode: 'no-cors'}).catch(() => null)", canary.url)
            page.wait_for_timeout(200)
        assert canary.hits == 0
    finally:
        canary.stop()
