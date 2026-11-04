"""Tool registry. Tools are only ever executed by engine.invoke_tool, which runs
the policy check first; nothing else in the codebase calls Tool.fn."""
from dataclasses import dataclass, field
from typing import Callable

from pydantic import BaseModel


class RecoverableToolError(Exception):
    """Transient failure (timeout, 5xx): safe to retry."""


class ToolFailure(Exception):
    """Permanent failure: retrying would not help."""


class NeedsInput(Exception):
    """The task cannot continue until a person supplies these fields."""

    def __init__(self, fields: list[dict]):
        super().__init__(f"Missing: {', '.join(f['name'] for f in fields)}")
        self.fields = fields


@dataclass
class ToolContext:
    run_id: str
    owner_id: str
    owner_username: str


@dataclass
class Tool:
    name: str
    description: str
    input_model: type[BaseModel]
    fn: Callable[[BaseModel, ToolContext], dict]
    risk: str | Callable[[BaseModel], str] = "low"
    tags: set[str] = field(default_factory=set)
    output_hint: str = ""
    summarize: Callable[[BaseModel], str] | None = None
    consequences: Callable[[BaseModel], str] | None = None

    def risk_for(self, inputs: BaseModel) -> str:
        return self.risk(inputs) if callable(self.risk) else self.risk


REGISTRY: dict[str, Tool] = {}


def register(tool: Tool) -> None:
    REGISTRY[tool.name] = tool


def catalog() -> list[dict]:
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "risk": "dynamic" if callable(tool.risk) else tool.risk,
            "tags": sorted(tool.tags),
            "inputs": tool.input_model.model_json_schema().get("properties", {}),
            "output": tool.output_hint,
        }
        for tool in REGISTRY.values()
    ]
