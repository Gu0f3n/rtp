"""ORM 模型：八张核心数据表。

表间关系::

    target_app 1---* attack_run *---1 attack_case *---1 attack_seed
    attack_run 1---* attack_turn 1---1 judge_result
    batch 维度上聚合出 guardrail_test 与 metric_snapshot

所有"配置类"实体都带 config_version，实验记录绑定具体版本，
以保证历史结果可精确复现——这是护栏对比实验成立的前提。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[str]: JSON}


# --------------------------------------------------------------------------- #
# 1. 靶标
# --------------------------------------------------------------------------- #
class TargetApp(Base):
    """被测应用。T5 不是独立靶标，而是 T2 的另一套护栏配置（同构对照）。"""

    __tablename__ = "target_app"

    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(32), unique=True)      # T1/T2/T3
    name: Mapped[str] = mapped_column(String(128))
    form_type: Mapped[str] = mapped_column(String(16))             # chat / rag / agent
    system_prompt: Mapped[str] = mapped_column(Text)
    kb_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tools: Mapped[list[str]] = mapped_column(JSON, default=list)
    # {"input_filter": bool, "output_filter": bool, "prompt_hardening": bool}
    guardrail_config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    guardrail_profile: Mapped[str] = mapped_column(String(16), default="none")
    config_version: Mapped[str] = mapped_column(String(32), default="v1")
    expected_weakness: Mapped[str] = mapped_column(Text, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    runs: Mapped[list["AttackRun"]] = relationship(back_populates="target")


# --------------------------------------------------------------------------- #
# 2. 种子用例
# --------------------------------------------------------------------------- #
class AttackSeed(Base):
    __tablename__ = "attack_seed"

    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(32), unique=True)       # S001
    category: Mapped[str] = mapped_column(String(64))               # OWASP 风险类别
    technique: Mapped[str] = mapped_column(String(64))              # 攻击技术
    text: Mapped[str] = mapped_column(Text)
    target_forms: Mapped[list[str]] = mapped_column(JSON, default=list)
    expected_harm: Mapped[str] = mapped_column(Text, default="")
    # 该用例针对的靶标薄弱点标识，用于核对用例覆盖
    weakness_tag: Mapped[str] = mapped_column(String(64), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    cases: Mapped[list["AttackCase"]] = relationship(back_populates="seed")


# --------------------------------------------------------------------------- #
# 3. 变异后的攻击载荷
# --------------------------------------------------------------------------- #
class AttackCase(Base):
    __tablename__ = "attack_case"
    __table_args__ = (UniqueConstraint("uid", name="uq_case_uid"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(48))
    seed_id: Mapped[int] = mapped_column(ForeignKey("attack_seed.id"))
    channel: Mapped[str] = mapped_column(String(16))               # template / llm
    operator_chain: Mapped[list[str]] = mapped_column(JSON, default=list)
    text: Mapped[str] = mapped_column(Text)
    gen_meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    seed: Mapped[AttackSeed] = relationship(back_populates="cases")


# --------------------------------------------------------------------------- #
# 4. 一次完整攻击任务（一个用例 × 一个靶标 × 一个批次）
# --------------------------------------------------------------------------- #
class AttackRun(Base):
    __tablename__ = "attack_run"

    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(48), unique=True)
    batch_id: Mapped[str] = mapped_column(String(48), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("target_app.id"))
    case_id: Mapped[int] = mapped_column(ForeignKey("attack_case.id"))

    strategy: Mapped[str] = mapped_column(String(16), default="single")   # single/multi
    max_turns: Mapped[int] = mapped_column(Integer, default=1)
    guardrail_profile: Mapped[str] = mapped_column(String(16), default="none")

    # 执行生命周期：pending / running / completed / error / skipped
    # 注意：这里只描述"任务跑没跑完"，不描述"攻击成没成功"。
    # 二者混用会让有效样本分母失真（被防住的 run 会被误算作"执行失败"），
    # 因此攻击结果单独用 success 字段表达。
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    success: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    success_turn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_turns: Mapped[int] = mapped_column(Integer, default=0)

    token_in: Mapped[int] = mapped_column(Integer, default=0)
    token_out: Mapped[int] = mapped_column(Integer, default=0)
    cost: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)

    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 正常终止原因（预算耗尽/轮次用尽），与 error 区分：这类 run 结果仍然有效
    stop_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 配置指纹：靶标版本 + 用例集哈希 + 模型名 + 温度，用于保证可复现
    config_fingerprint: Mapped[str] = mapped_column(String(64), default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    target: Mapped[TargetApp] = relationship(back_populates="runs")
    case: Mapped[AttackCase] = relationship()
    turns: Mapped[list["AttackTurn"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="AttackTurn.turn_index")


# --------------------------------------------------------------------------- #
# 5. 逐轮轨迹
# --------------------------------------------------------------------------- #
class AttackTurn(Base):
    """多轮编排的每一轮。

    frozen 标记表示该轮属于"成功路径冻结"出来的可重放轨迹；
    replay_of 指向原始 run，重放时上下文完全给定，因此可稳定复现。
    """

    __tablename__ = "attack_turn"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("attack_run.id"), index=True)
    turn_index: Mapped[int] = mapped_column(Integer)

    state: Mapped[str] = mapped_column(String(24))     # probe/consensus/escalate/attack/confirm
    prompt: Mapped[str] = mapped_column(Text)
    response: Mapped[str] = mapped_column(Text)

    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    # 警觉信号：refusal / warning / topic_shift / counter_question / none
    signals: Mapped[list[str]] = mapped_column(JSON, default=list)
    # 级间情报：级联链每一级的 {"in": 用到的槽位, "out": 缴获的槽位}。
    # 与 signals 是两件事——前者是攻击者的战果，后者是目标的警觉反应，
    # 混在一列里会让"为什么链断了"和"目标什么时候开始防"无法分开统计。
    # 非级联链的 run 该列为空 dict。
    slots: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    backtracked: Mapped[bool] = mapped_column(Boolean, default=False)

    blocked: Mapped[bool] = mapped_column(Boolean, default=False)      # 护栏是否拦截
    blocked_by: Mapped[str | None] = mapped_column(String(32), nullable=True)

    frozen: Mapped[bool] = mapped_column(Boolean, default=False)
    replay_of: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    run: Mapped[AttackRun] = relationship(back_populates="turns")
    judge: Mapped["JudgeResult | None"] = relationship(
        back_populates="turn", cascade="all, delete-orphan", uselist=False)


# --------------------------------------------------------------------------- #
# 6. 判定结果
# --------------------------------------------------------------------------- #
class JudgeResult(Base):
    __tablename__ = "judge_result"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("attack_run.id"), index=True)
    turn_id: Mapped[int] = mapped_column(ForeignKey("attack_turn.id"))

    rule_success: Mapped[bool] = mapped_column(Boolean)
    rule_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    llm_success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    llm_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    llm_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    llm_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    final_success: Mapped[bool] = mapped_column(Boolean)
    conflict: Mapped[bool] = mapped_column(Boolean, default=False)
    need_review: Mapped[bool] = mapped_column(Boolean, default=False)

    # 人工标注（金标准）：E4 实验必须由人工独立完成，不参考模型判定
    review_label: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    reviewer: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    turn: Mapped[AttackTurn] = relationship(back_populates="judge")


# --------------------------------------------------------------------------- #
# 7. 护栏对比结果
# --------------------------------------------------------------------------- #
class GuardrailTest(Base):
    __tablename__ = "guardrail_test"

    id: Mapped[int] = mapped_column(primary_key=True)
    batch_id: Mapped[str] = mapped_column(String(48), index=True)
    target_uid: Mapped[str] = mapped_column(String(32))
    guardrail_profile: Mapped[str] = mapped_column(String(16))

    total_runs: Mapped[int] = mapped_column(Integer, default=0)
    success_runs: Mapped[int] = mapped_column(Integer, default=0)
    asr: Mapped[float] = mapped_column(Float, default=0.0)
    baseline_asr: Mapped[float | None] = mapped_column(Float, nullable=True)
    reduction_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    blocked_turns: Mapped[int] = mapped_column(Integer, default=0)

    config_fingerprint: Mapped[str] = mapped_column(String(64), default="")
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


# --------------------------------------------------------------------------- #
# 8. 指标快照
# --------------------------------------------------------------------------- #
class MetricSnapshot(Base):
    __tablename__ = "metric_snapshot"

    id: Mapped[int] = mapped_column(primary_key=True)
    batch_id: Mapped[str] = mapped_column(String(48), index=True)
    name: Mapped[str] = mapped_column(String(64))       # E1_baseline / E2_turns / ...
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


# --------------------------------------------------------------------------- #
# 9. 批次（执行器的调度单位，断点续跑按批次 + 用例粒度记录）
# --------------------------------------------------------------------------- #
class Batch(Base):
    __tablename__ = "batch"

    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(48), unique=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    target_uid: Mapped[str] = mapped_column(String(32))
    experiment: Mapped[str] = mapped_column(String(32), default="E1")
    strategy: Mapped[str] = mapped_column(String(16), default="single")
    max_turns: Mapped[int] = mapped_column(Integer, default=1)
    guardrail_profile: Mapped[str] = mapped_column(String(16), default="none")
    case_filter: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    total: Mapped[int] = mapped_column(Integer, default=0)
    done: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="pending")

    mock: Mapped[bool] = mapped_column(Boolean, default=False)
    config_fingerprint: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
