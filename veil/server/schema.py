"""Protocol schemas for Veil Agent (Task 1).
Derived directly from shared/protocol.schema.json.
Enforces strict schema validation (extra='forbid') on all models.
"""
from typing import Annotated, Literal, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator


class Node(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: Annotated[str, StringConstraints(max_length=50)]
    tag: Annotated[str, StringConstraints(max_length=20)]
    role: Optional[Annotated[str, StringConstraints(max_length=30)]] = None
    type: Optional[Annotated[str, StringConstraints(max_length=30)]] = None
    label: Annotated[str, StringConstraints(max_length=100)] = ""
    autocomplete: Optional[Annotated[str, StringConstraints(max_length=50)]] = None
    sensitive: bool = False
    bbox: list[int] = Field(..., min_length=4, max_length=4)
    pii: list[Annotated[str, StringConstraints(max_length=30)]] = []
    text: Optional[Annotated[str, StringConstraints(max_length=200)]] = None


class Dom(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: Annotated[str, StringConstraints(max_length=200)]
    title: Annotated[str, StringConstraints(max_length=100)] = ""
    viewport: list[int] = Field(..., min_length=2, max_length=2)
    scrollY: int
    nodes: list[Node] = Field(..., max_length=1000)


class ManifestItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: Annotated[str, StringConstraints(max_length=50)]
    type: Annotated[str, StringConstraints(max_length=50)]
    bbox: list[int] = Field(..., min_length=4, max_length=4)


class ActionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["action"] = "action"
    action: Literal["click", "type", "select", "scroll"]
    target_id: Optional[Annotated[str, StringConstraints(max_length=50)]] = None
    coords: Optional[list[int]] = Field(None, min_length=2, max_length=2)
    value: Optional[Annotated[str, StringConstraints(max_length=200)]] = None
    reason: Annotated[str, StringConstraints(min_length=1, max_length=200)] = "action execution"


class AnswerResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["answer"] = "answer"
    text: Annotated[str, StringConstraints(min_length=1, max_length=2000)]
    reason: Annotated[str, StringConstraints(min_length=1, max_length=200)] = "information answered"

    @property
    def action(self) -> str:
        return "answer"


class AskUserResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["ask_user"] = "ask_user"
    question: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    reason: Annotated[str, StringConstraints(min_length=1, max_length=200)] = "clarification requested"

    @property
    def action(self) -> str:
        return "ask_user"


class DoneResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["done"] = "done"
    reason: Annotated[str, StringConstraints(min_length=1, max_length=200)] = "goal completed"

    @property
    def action(self) -> str:
        return "done"

    @property
    def target_id(self) -> None:
        return None

    @property
    def value(self) -> None:
        return None


class FailResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["fail"] = "fail"
    reason: Annotated[str, StringConstraints(min_length=1, max_length=200)] = "goal cannot be completed"

    @property
    def action(self) -> str:
        return "fail"

    @property
    def target_id(self) -> None:
        return None

    @property
    def value(self) -> None:
        return None


class HistoryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Optional[Annotated[str, StringConstraints(max_length=20)]] = None
    action: Optional[Annotated[str, StringConstraints(max_length=20)]] = None
    target_id: Optional[Annotated[str, StringConstraints(max_length=50)]] = None
    coords: Optional[list[int]] = None
    value: Optional[Annotated[str, StringConstraints(max_length=200)]] = None
    text: Optional[Annotated[str, StringConstraints(max_length=2000)]] = None
    question: Optional[Annotated[str, StringConstraints(max_length=500)]] = None
    reason: Optional[Annotated[str, StringConstraints(max_length=200)]] = ""


class PlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    v: Annotated[str, StringConstraints(max_length=10, pattern=r"^[0-9]+(\.[0-9]+)*$")] = "1.0"
    mode: Literal["Strict", "Balanced"] = "Balanced"
    goal: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    step: int = Field(..., ge=0, le=100)
    history: list[Union[ActionResponse, DoneResponse, FailResponse, AnswerResponse, AskUserResponse, HistoryItem]] = Field(default_factory=list, max_length=8)
    dom: Dom
    image: Optional[Annotated[str, StringConstraints(max_length=2_000_000)]] = None
    manifest: list[ManifestItem] = Field(default_factory=list, max_length=500)
    legend_version: Annotated[str, StringConstraints(max_length=20)] = "1.0"

    @field_validator("history", mode="before")
    @classmethod
    def _unwrap_history(cls, v):
        if isinstance(v, list):
            return [getattr(item, "_response", item) for item in v]
        return v


PlanResponse = Annotated[
    Union[ActionResponse, AnswerResponse, AskUserResponse, DoneResponse, FailResponse],
    Field(discriminator="type")
]


# Backward compatibility constructor
def Action(action: str, **kwargs):
    if action == "done":
        return DoneResponse(reason=kwargs.get("reason", "task completed"))
    elif action == "fail":
        return FailResponse(reason=kwargs.get("reason", "task failed"))
    elif action == "answer":
        return AnswerResponse(text=kwargs.get("text", kwargs.get("value", "")), reason=kwargs.get("reason", "answered"))
    elif action == "ask_user":
        return AskUserResponse(question=kwargs.get("question", kwargs.get("value", "")), reason=kwargs.get("reason", "asking user"))
    else:
        return ActionResponse(action=action, **kwargs)
