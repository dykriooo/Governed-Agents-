"""Runs the whole evaluation suite, the same one the dashboard triggers, and holds
the result to the PRD's section 9 targets."""
import pytest

from governai import evaluation
from governai.db import EvalReport, session_scope


@pytest.fixture(scope="module")
def report(client):
    with session_scope() as session:
        row = EvalReport(triggered_by="pytest")
        session.add(row)
        session.flush()
        report_id = row.id
    evaluation.run_suite(report_id)
    with session_scope() as session:
        return session.get(EvalReport, report_id)


def test_suite_finished(report):
    assert report.status == "finished", report.error
    assert len(report.results) == len(evaluation.SCENARIOS)


@pytest.mark.parametrize("scenario", [s[0] for s in evaluation.SCENARIOS])
def test_scenario(report, scenario):
    result = next(r for r in report.results if r["id"] == scenario)
    failed = [c["check"] for c in result["checks"] if not c["passed"]]
    assert result["passed"], f"failed checks: {failed}; error: {result['error']}"


def test_prd_targets_met(report):
    missed = [m for m in report.metrics if m["met"] is False]
    assert not missed, missed
