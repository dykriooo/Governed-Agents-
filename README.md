# GovernAI

An autonomous agent that completes multi-step workflows inside enforced boundaries. Every tool call passes a policy check before it runs, risky actions wait for a human, and every step lands in a tamper-evident audit trail.

> *Autonomy with accountability: an agent should complete tasks independently, but never operate outside its authorized boundaries.*

This is the hackathon MVP described in the PRD. It operates a **mock** university portal and expense API (`portal/`), not real services.

## Run it

Needs [uv](https://docs.astral.sh/uv/) and Node 20+.

```bash
cd backend && uv sync && uv run playwright install chromium && cd ..
```

```bash
cd frontend && npm install && cd ..
```

```bash
./scripts/dev.sh
```

Open http://localhost:3000. The demo accounts are `student`, `approver`, `admin` and `auditor`; the password is `demo` unless you set `GOVERNAI_DEMO_PASSWORD`.

### Demo script

1. Sign in as `student`, click **Load sample documents**, then **Start task**.
2. The agent reads the documents, fills the portal in a real browser, checks the saved draft, and stops at submission. One sample contains a prompt injection, which has no effect.
3. Sign in as `approver`, open **Approvals**, review the values, and approve. The agent submits and finishes with an execution report.
4. Back as `student`, try the **Data exfiltration attempt** example. It's blocked before anything runs, and no approval is offered.
5. Sign in as `admin` and open **Evaluation**, then **Run evaluation**. Open **Audit** to see the hash chain.

Don't run the evaluation during a live demo task: it injects portal failures, and those affect everything using the portal at that moment.

## How governance is enforced

```
instruction → planner → plan check → engine ─┬→ invoke_tool: validate → classify risk → policy decision → audit → execute
                                             ├→ deny: run blocked, no approval possible
                                             └→ needs approval: run paused and checkpointed; resumes on decision
```

- **One gateway.** `engine.invoke_tool` is the only code that runs a tool. A forged plan still hits the same check at runtime.
- **Deny beats ask, and ask beats allow.** Custom rules name a tool, a condition and an effect. An allow rule removes the default prompt on a high-risk action, and only overrides ask rules a person waived during a review. In code, unknown tools are denied, and a deny or ask rule that can't be evaluated counts as triggered, while an allow rule that can't be evaluated doesn't match.
- **Wider permission on irreversible actions comes only from a review.** Submissions and payments offer the same options as anything else, so with a wider option they can run with nobody checking each one. Written rules can't allow them: the API refuses such rules, and the engine ignores any that reach the database another way. A payment's *Always allow* covers amounts up to the one reviewed. The dashboard counts every irreversible action that ran without its own review.
- **Hard denies can't be approved.** A deny never creates an approval request. Locked policies can't be disabled or deleted.
- **Approvals are narrow.** *Allow once* is bound to a hash of the exact arguments and used once. *Allow for this task* covers later calls with the same tool, host and method in that task. *Always allow* is admin-only and creates a removable allow rule that waives only the ask rules that flagged that request; a newer ask rule still applies. Every option needs the authority policy requires at execution time. You can't approve your own task. Payments over ₹5,000 need an administrator.
- **Submission re-checks the source.** The submit tools compare the portal's current record with what was approved, and refuse if it changed.
- **Untrusted content has no path to the plan.** The model sees only the instruction and tool catalog. Document extraction is local and deterministic, so applicant data never goes to an LLM provider.
- **The browser is fenced.** Every request a page makes is checked against the allowlist, which covers redirects and embedded resources that a per-call check never sees.
- **Personal data stays out of logs.** Tool inputs, outputs and audit events are redacted before they're written. Documents and run context are encrypted at rest. Memory keeps an allowlist of non-sensitive fields only.
- **Runs are durable.** Plan, cursor and context are checkpointed after each step, so waiting for a person and restarting the server resume the same way.

## Testing

```bash
cd backend && uv run pytest
```

The tests run the real engine and browser against the portal over HTTP. The evaluation suite (`governai/evaluation.py`, also on the **Evaluation** page) has 20 scenarios. It checks results against the portal's own records and a canary server standing in for an attacker, not against the agent's logs. Its numbers describe that suite on the mock portal, not production performance.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | unset | Enables LLM planning and policy translation. Without it the rule-based planner runs, and each task shows which planner it used. |
| `OPENAI_MODEL` | `gpt-4o-mini` | Model for planning |
| `GOVERNAI_DEMO_PASSWORD` | `demo` | Password for the seeded accounts |
| `GOVERNAI_JWT_SECRET`, `GOVERNAI_FERNET_KEY` | generated into `backend/.data/secrets.json` (mode 0600) | Set these outside local development |
| `GOVERNAI_PORTAL_URL` | `http://localhost:8100` | System the agent operates on |
| `GOVERNAI_BROWSER_CHANNEL` | Playwright's Chromium | `chrome` uses the installed browser |
| `GOVERNAI_DATABASE_URL` | SQLite in `backend/.data` | SQLAlchemy URL. Only SQLite has been tested. |

## Differences from the PRD

| PRD | Built | Why |
|---|---|---|
| PostgreSQL, Celery + Redis, Docker | SQLite and an in-process worker pool | Enough for the MVP's governance lifecycle, with no extra services to run |
| LangGraph | A small checkpointed state machine | Pausing, resuming and restart recovery are simple and directly testable |
| Shadcn/UI | Hand-written Tailwind components | A few primitives were all the UI needed |
| ChromaDB or pgvector | Per-user structured memory | Memory holds a few allowlisted fields, so there's nothing to search semantically |
| MCP, database query tool | Not built | MCP is a "Could Have"; the browser and REST tools meet the MVP requirement |
| Travel booking (3.3) | Not built | The MVP asks for one workflow; admission and expense claims are both built |

## Known limits

- Documents must be text files in simple `Key: Value` form; PDFs and scanned receipts aren't read.
- The demo accounts are for local use. There's no sign-up, rate limiting or OAuth.
- The portal's `/_test` routes exist for fault injection and must never be exposed.
- PII detection uses field names and patterns, so it can miss personal data in unusual formats.
- Workers run in one process, so this doesn't scale across machines.
