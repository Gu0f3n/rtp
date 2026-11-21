"""API 数据契约（Pydantic DTO）。"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------- #
# 靶标
# --------------------------------------------------------------------------- #
class TargetOut(ORMModel):
    id: int
    uid: str
    name: str
    form_type: str
    system_prompt: str
    kb_id: str | None
    tools: list[str]
    guardrail_config: dict[str, Any]
    guardrail_profile: str
    config_version: str
    expected_weakness: str
    is_active: bool


class TargetUpdate(BaseModel):
    guardrail_profile: str | None = None
    guardrail_config: dict[str, Any] | None = None
    system_prompt: str | None = None


class ChatMessage(BaseModel):
    role: Literal["user", "assistant", "system"]
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = Field(default_factory=list)
    session_id: str | None = None


class ChatResponse(BaseModel):
    reply: str
    blocked: bool = False
    blocked_by: str | None = None
    retrieved: list[str] = Field(default_factory=list)
    # 命中投毒文档的数量。与 retrieved 分列是因为检索完整性（retrieval
    # integrity）是独立于内容攻破的指标：投毒文档进了 top-k 就说明检索层
    # 已失守，即使模型没有执行文档里的指令，这一轮也属于"间接注入可及"。
    retrieved_poisoned: int = 0
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    guardrail_profile: str = "none"
    latency_ms: int = 0
    # 靶标侧的真实消耗。编排器必须累计这三项，否则单轮实验的成本会计为 0
    # （单轮不经过话术改写，编排侧零消耗，唯一开销就在这里）。
    token_in: int = 0
    token_out: int = 0
    cost: float = 0.0


# --------------------------------------------------------------------------- #
# 种子 / 用例
# --------------------------------------------------------------------------- #
class SeedOut(ORMModel):
    id: int
    uid: str
    category: str
    technique: str
    text: str
    target_forms: list[str]
    expected_harm: str
    weakness_tag: str


class CaseOut(ORMModel):
    id: int
    uid: str
    seed_id: int
    channel: str
    operator_chain: list[str]
    text: str
    gen_meta: dict[str, Any]


class GenerateRequest(BaseModel):
    target_uid: str = "T1"
    channels: list[Literal["template", "llm"]] = Field(default_factory=lambda: ["template"])
    operators: list[str] = Field(default_factory=list,
                                description="为空表示不做变异；可选 encoding/task_wrap/role_nesting/payload_nest")
    max_chain: int = 1
    limit: int | None = None
    seed_uids: list[str] | None = None


class GenerateResult(BaseModel):
    created: int
    by_channel: dict[str, int]
    by_operator: dict[str, int]


# --------------------------------------------------------------------------- #
# 攻击执行
# --------------------------------------------------------------------------- #
class RunRequest(BaseModel):
    target_uid: str = "T1"
    experiment: str = "E1"
    strategy: Literal["single", "multi"] = "single"
    max_turns: int = 1
    guardrail_profile: str | None = None
    limit: int | None = None
    channels: list[str] | None = None
    batch_name: str = ""


class BatchOut(ORMModel):
    id: int
    uid: str
    name: str
    target_uid: str
    experiment: str
    strategy: str
    max_turns: int
    guardrail_profile: str
    total: int
    done: int
    failed: int
    status: str
    mock: bool
    config_fingerprint: str
    created_at: datetime
    finished_at: datetime | None


class TurnOut(ORMModel):
    id: int
    turn_index: int
    state: str
    prompt: str
    response: str
    latency_ms: int
    signals: list[str]
    # 级联链的级间情报；非级联任务为空 dict
    slots: dict[str, Any] = Field(default_factory=dict)
    backtracked: bool
    blocked: bool
    blocked_by: str | None
    frozen: bool


class RunOut(ORMModel):
    id: int
    uid: str
    batch_id: str
    target_id: int
    case_id: int
    strategy: str
    max_turns: int
    guardrail_profile: str
    status: str
    success: bool = False
    success_turn: int | None
    total_turns: int
    token_in: int
    token_out: int
    cost: float
    error: str | None
    # 正常终止原因（预算耗尽 / 轮次用尽 / 级联链断裂）。
    # 与 error 分开：链断不是执行故障，是攻击本身没有推进空间，
    # 指标必须把它算进分母，界面上也要能看到断在哪一级。
    stop_reason: str | None = None
    config_fingerprint: str


class RunDetail(RunOut):
    turns: list[TurnOut] = Field(default_factory=list)
    judge: dict[str, Any] | None = None
    case_text: str | None = None
    seed_uid: str | None = None
    category: str | None = None
    operator_chain: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# 判定与人工复核
# --------------------------------------------------------------------------- #
class ReviewRequest(BaseModel):
    judge_id: int
    label: bool
    reviewer: str = "owner"


class ReplayRequest(BaseModel):
    run_id: int


# --------------------------------------------------------------------------- #
# 指标 / 报告
# --------------------------------------------------------------------------- #
class MetricsOut(BaseModel):
    batch_id: str
    name: str
    payload: dict[str, Any]


class GatewayStat(BaseModel):
    calls: int
    cache_hits: int
    token_in: int
    token_out: int
    cost: float
    mock: bool
    by_role: dict[str, int]
