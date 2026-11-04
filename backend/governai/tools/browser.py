"""Browser automation with Playwright. Each call opens a fresh browser and works
from server-side draft state, so a run can pause for hours for approval, or
survive a backend restart, without holding a browser open.

Page content is untrusted data: it is read into fields and compared, and never
influences which tool runs next.
"""
from contextlib import contextmanager

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeout
from playwright.sync_api import sync_playwright
from pydantic import BaseModel

from ..config import settings
from ..policy import allowed_hosts, domain_allowed
from .base import RecoverableToolError, Tool, ToolContext, ToolFailure, register


@contextmanager
def browser_page():
    allowed = allowed_hosts()
    blocked: list[str] = []

    def guard(route):
        url = route.request.url
        if url.startswith(("data:", "blob:", "about:")) or domain_allowed(url, allowed):
            route.continue_()
        else:
            blocked.append(url)
            route.abort()

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, channel=settings.browser_channel)
            try:
                context = browser.new_context()
                context.route("**/*", guard)
                page = context.new_page()
                page.set_default_timeout(settings.browser_timeout_ms)
                yield page
            finally:
                browser.close()
    except PlaywrightTimeout as exc:
        raise RecoverableToolError(f"Browser timed out: {str(exc).splitlines()[0]}") from exc
    except PlaywrightError as exc:
        if blocked:
            raise ToolFailure(f"Browser blocked a request to an unapproved host: {blocked[0]}") from exc
        raise RecoverableToolError(f"Browser error: {str(exc).splitlines()[0]}") from exc


def _check_status(response, what: str) -> None:
    status = response.status if response else 0
    if status >= 500 or status == 0:
        raise RecoverableToolError(f"{what} returned HTTP {status}")
    if status >= 400:
        raise ToolFailure(f"{what} returned HTTP {status}")


def _open(page, url: str) -> None:
    _check_status(page.goto(url), url)


def _click_and_wait(page, selector: str, what: str) -> None:
    with page.expect_navigation() as navigation:
        page.click(selector)
    _check_status(navigation.value, what)


def _read_draft(page) -> dict:
    return page.eval_on_selector_all(
        "dd[data-field]", "els => Object.fromEntries(els.map(e => [e.dataset.field, e.textContent]))"
    )


READ_FORM_JS = """
() => [...document.querySelectorAll('form input, form select, form textarea')].map(el => ({
  name: el.name,
  label: (document.querySelector(`label[for="${el.id}"]`)?.textContent || el.name).trim(),
  required: el.required,
  type: el.tagName === 'SELECT' ? 'select' : el.type,
  options: el.tagName === 'SELECT' ? [...el.options].map(o => o.value).filter(Boolean) : [],
}))
"""


class UrlInput(BaseModel):
    url: str


class FillInput(UrlInput):
    fields: dict[str, str]


class DraftInput(FillInput):
    application_id: str


def inspect_form(inputs: UrlInput, _: ToolContext) -> dict:
    with browser_page() as page:
        _open(page, f"{inputs.url}/apply")
        return {"fields": page.evaluate(READ_FORM_JS)}


def fill_form(inputs: FillInput, _: ToolContext) -> dict:
    with browser_page() as page:
        _open(page, f"{inputs.url}/apply")
        for name, value in inputs.fields.items():
            control = page.locator(f'[name="{name}"]')
            if control.count() == 0:
                raise ToolFailure(f"The form has no field named {name}")
            if control.evaluate("el => el.tagName") == "SELECT":
                control.select_option(value)
            else:
                control.fill(value)
        _click_and_wait(page, "#save", "Saving the draft")
        return {"application_id": page.locator("[data-application-id]").get_attribute("data-application-id")}


def validate_form(inputs: DraftInput, _: ToolContext) -> dict:
    with browser_page() as page:
        _open(page, f"{inputs.url}/applications/{inputs.application_id}/review")
        saved = _read_draft(page)
    wrong = [name for name, value in inputs.fields.items() if saved.get(name) != value]
    if wrong:
        raise ToolFailure(f"The saved draft does not match the intended values for: {', '.join(wrong)}")
    return {"valid": True, "fields_checked": len(inputs.fields)}


def submit_form(inputs: DraftInput, _: ToolContext) -> dict:
    with browser_page() as page:
        _open(page, f"{inputs.url}/applications/{inputs.application_id}/review")
        # Safe to retry: a lost response must not cause a second submission.
        if page.inner_text("#status") == "submitted":
            return {"application_id": inputs.application_id, "status": "submitted", "already_submitted": True}
        # What was approved must still be what gets sent.
        saved = _read_draft(page)
        changed = [name for name, value in inputs.fields.items() if saved.get(name) != value]
        if changed:
            raise ToolFailure(f"The draft changed after approval ({', '.join(changed)}); not submitting")
        _click_and_wait(page, "#submit", "Submitting")
        status = page.inner_text("#status")
    if status != "submitted":
        raise RecoverableToolError(f"The portal reports status '{status}' after submitting")
    return {"application_id": inputs.application_id, "status": status}


register(Tool("inspect_form", "Open the application form and read its mandatory fields.", UrlInput, inspect_form,
              "low", {"network", "browser"}, output_hint="{fields:[{name,label,required,type,options}]}"))
register(Tool("fill_form", "Fill the application form in the browser and save it as a draft.", FillInput, fill_form,
              "medium", {"network", "browser"}, output_hint="{application_id}"))
register(Tool("validate_form", "Re-read the saved draft and check it against the intended values.", DraftInput,
              validate_form, "medium", {"network", "browser"}, output_hint="{valid,fields_checked}"))
register(Tool("submit_form", "Submit the saved application. Irreversible.", DraftInput, submit_form,
              "high", {"network", "browser", "submission"}, output_hint="{application_id,status}",
              summarize=lambda i: f"Submit application {i.application_id} to {i.url}",
              consequences=lambda i: "The application is sent to the university and cannot be edited or withdrawn "
                                     "by the agent. These exact values are what will be submitted."))
