"""批次执行、任务详情、人工复核、轨迹重放。"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session, session_scope
from app.models import AttackCase, AttackRun, AttackSeed, AttackTurn, Batch, JudgeResult
from app.runner import executor
from app.schemas import BatchOut, ReplayRequest, ReviewRequest, RunDetail, RunOut, RunRequest, TurnOut

router = APIRouter(prefix="/api", tags=["runs"])

# 同一时刻只允许一个批次在跑，避免 SQLite 写锁竞争与限流叠加
_batch_lock = asyncio.Lock()
_progress: dict[str, dict] = {}


async def _run_in_background(batch_uid: str) -> None:
    if _batch_lock.locked():
        _progress[batch_uid] = {"state": "queued"}
    async with _batch_lock:
        _progress[batch_uid] = {"state": "running", "done": 0}
        try:
            stats = await executor.run_batch(
                batch_uid,
                progress=lambda p: _progress.__setitem__(
                    batch_uid, {"state": "running", **p}))
            _progress[batch_uid] = {"state": "done", "done": stats.done,
                                    "total": stats.total, "breached": stats.success,
                                    "errors": stats.failed}
        except Exception as e:  # noqa: BLE001
            _progress[batch_uid] = {"state": "error", "error": str(e)[:300]}


@router.post("/batches")
async def create_and_run(body: RunRequest, bg: BackgroundTasks,
                         s: AsyncSession = Depends(get_session)):
    """创建批次并后台执行。重复调用会新建批次，不会覆盖历史结果。"""
    try:
        uid = await executor.create_batch(
            target_uid=body.target_uid, experiment=body.experiment,
            strategy=body.strategy, max_turns=body.max_turns,
            guardrail_profile=body.guardrail_profile, limit=body.limit,
            channels=body.channels, name=body.batch_name)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    bg.add_task(_run_in_background, uid)
    return {"batch_id": uid, "status": "started", "mock": True if body else False}


@router.get("/batches", response_model=list[BatchOut])
async def list_batches(limit: int = 30, s: AsyncSession = Depends(get_session)):
    rows = (await s.execute(
        select(Batch).order_by(Batch.id.desc()).limit(limit))).scalars()
    return list(rows)


@router.get("/batches/{uid}")
async def get_batch(uid: str, s: AsyncSession = Depends(get_session)):
    b = (await s.execute(select(Batch).where(Batch.uid == uid))).scalar_one_or_none()
    if not b:
        raise HTTPException(404, "批次不存在")
    counts = (await s.execute(
        select(AttackRun.status, func.count())
        .where(AttackRun.batch_id == uid).group_by(AttackRun.status))).all()
    outcomes = (await s.execute(
        select(AttackRun.success, func.count())
        .where(AttackRun.batch_id == uid, AttackRun.status == "completed")
        .group_by(AttackRun.success))).all()
    return {**BatchOut.model_validate(b).model_dump(),
            "runs_by_status": {k: v for k, v in counts},
            "runs_by_outcome": {"success": dict((k, v) for k, v in outcomes).get(True, 0),
                                "defended": dict((k, v) for k, v in outcomes).get(False, 0)},
            "progress": _progress.get(uid)}


@router.post("/batches/{uid}/resume")
async def resume_batch(uid: str, bg: BackgroundTasks):
    """断点续跑：只执行仍处于 pending 的任务。"""
    bg.add_task(_run_in_background, uid)
    return {"batch_id": uid, "status": "resumed"}


@router.get("/runs")
async def list_runs(batch_id: str | None = None, status: str | None = None,
                    success: bool | None = None,
                    limit: int = 50, offset: int = 0,
                    s: AsyncSession = Depends(get_session)):
    stmt = select(AttackRun).order_by(AttackRun.id)
    if batch_id:
        stmt = stmt.where(AttackRun.batch_id == batch_id)
    if status:
        stmt = stmt.where(AttackRun.status == status)
    if success is not None:
        stmt = stmt.where(AttackRun.success.is_(success))
    total = (await s.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = list((await s.execute(stmt.limit(limit).offset(offset))).scalars())

    # 补 case_uid：演示与排障时需要可读的载荷编号，
    # 直接暴露自增 id 无法让人对上"这是哪一条载荷"。
    case_ids = {r.case_id for r in rows}
    uid_map: dict[int, str] = {}
    if case_ids:
        uid_map = dict((await s.execute(
            select(AttackCase.id, AttackCase.uid)
            .where(AttackCase.id.in_(case_ids)))).all())

    items = []
    for r in rows:
        d = RunOut.model_validate(r).model_dump()
        d["case_uid"] = uid_map.get(r.case_id, "")
        items.append(d)
    return {"total": total, "items": items}


@router.get("/runs/{run_id}", response_model=RunDetail)
async def get_run(run_id: int, s: AsyncSession = Depends(get_session)):
    run = (await s.execute(select(AttackRun).where(AttackRun.id == run_id))).scalar_one_or_none()
    if not run:
        raise HTTPException(404, "任务不存在")
    case = (await s.execute(select(AttackCase).where(AttackCase.id == run.case_id))).scalar_one()
    seed = (await s.execute(select(AttackSeed).where(AttackSeed.id == case.seed_id))).scalar_one()
    turns = list((await s.execute(
        select(AttackTurn).where(AttackTurn.run_id == run_id)
        .order_by(AttackTurn.turn_index))).scalars())

    # 只用 RunOut 校验标量字段：RunDetail 含 turns 关系字段，
    # 直接 model_validate(run) 会在异步上下文触发懒加载（MissingGreenlet）。
    # turns 已在上方显式查询，直接填入即可。
    detail = RunOut.model_validate(run).model_dump()
    detail.update({
        "turns": [TurnOut.model_validate(t).model_dump() for t in turns],
        "case_text": case.text,
        "seed_uid": seed.uid,
        "category": seed.category,
        "operator_chain": case.operator_chain,
    })
    last = (await s.execute(
        select(JudgeResult).join(AttackTurn, AttackTurn.id == JudgeResult.turn_id)
        .where(JudgeResult.run_id == run_id)
        .order_by(AttackTurn.turn_index.desc()).limit(1))).scalar_one_or_none()
    if last:
        detail["judge"] = {
            "id": last.id,
            "rule_success": last.rule_success,
            "rule_evidence": last.rule_evidence,
            "llm_success": last.llm_success,
            "llm_category": last.llm_category,
            "llm_confidence": last.llm_confidence,
            "llm_reason": last.llm_reason,
            "final_success": last.final_success,
            "conflict": last.conflict,
            "need_review": last.need_review,
            "review_label": last.review_label,
        }
    return detail


@router.get("/reviews")
async def list_reviews(limit: int = 100, only_unlabeled: bool = True,
                       s: AsyncSession = Depends(get_session)):
    """待人工复核队列。E4 的金标准就来自这里的人工标注。"""
    stmt = (select(JudgeResult, AttackTurn, AttackRun)
            .join(AttackTurn, AttackTurn.id == JudgeResult.turn_id)
            .join(AttackRun, AttackRun.id == JudgeResult.run_id)
            .where(JudgeResult.need_review.is_(True))
            .order_by(JudgeResult.id))
    if only_unlabeled:
        stmt = stmt.where(JudgeResult.review_label.is_(None))
    rows = (await s.execute(stmt.limit(limit))).all()
    return {"total": len(rows), "items": [{
        "judge_id": j.id,
        "run_id": r.id,
        "batch_id": r.batch_id,
        "turn": t.turn_index,
        "prompt": t.prompt[:600],
        "response": t.response[:1200],
        "rule_success": j.rule_success,
        "rule_evidence": j.rule_evidence,
        "llm_success": j.llm_success,
        "llm_confidence": j.llm_confidence,
        "llm_reason": j.llm_reason,
        "conflict": j.conflict,
        "review_label": j.review_label,
    } for j, t, r in rows]}


@router.post("/reviews")
async def submit_review(body: ReviewRequest, s: AsyncSession = Depends(get_session)):
    """提交人工复核。

    复核结论必须落成**生效结论**，否则人工标注只是给 E4 提供金标准、
    对 ASR 毫无影响——这正是原实现的问题：``review_label`` 从不回写
    ``attack_run.success``，人工点了"非攻破"，指标里那条仍算攻破。

    设计上**不改 ``final_success``**：它必须保持"自动融合结论"的语义，
    否则 E4 会拿被评估对象自己当金标准。这里只刷新 run 的生效状态。
    """
    j = (await s.execute(select(JudgeResult).where(JudgeResult.id == body.judge_id))).scalar_one_or_none()
    if not j:
        raise HTTPException(404, "判定记录不存在")
    j.review_label = body.label
    j.reviewer = body.reviewer
    j.reviewed_at = datetime.now(timezone.utc)

    # 危害分级与生效结论保持自洽：判非攻破就不该留着 disclosure
    ev = dict(j.rule_evidence or {})
    if not body.label and ev.get("severity") not in (None, "none"):
        ev["severity_auto"] = ev.get("severity")
        ev["severity"] = "none"
        ev["severity_override"] = "review"
        j.rule_evidence = ev

    await s.flush()
    await _resync_run(s, j.run_id)
    await s.commit()
    return {"ok": True, "judge_id": j.id, "label": j.review_label}


async def _resync_run(s: AsyncSession, run_id: int) -> None:
    """按"复核优先"重算 run 的生效结论。"""
    run = (await s.execute(select(AttackRun).where(AttackRun.id == run_id))).scalar_one_or_none()
    if run is None:
        return
    rows = (await s.execute(
        select(JudgeResult, AttackTurn.turn_index)
        .join(AttackTurn, AttackTurn.id == JudgeResult.turn_id)
        .where(JudgeResult.run_id == run_id))).all()
    hits = [ti for jr, ti in rows
            if (bool(jr.review_label) if jr.review_label is not None else bool(jr.final_success))]
    run.success = bool(hits)
    run.success_turn = min(hits) if hits else None


@router.post("/runs/{run_id}/replay")
async def replay(run_id: int):
    """冻结轨迹重放：验证成功路径可稳定复现。"""
    try:
        return await executor.replay_run(run_id)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"重放失败：{e}") from e


@router.get("/batches/{uid}/turns")
async def batch_turns(uid: str, limit: int = 200, s: AsyncSession = Depends(get_session)):
    """批次内全部轮次（用于前端时间线展示）。"""
    rows = (await s.execute(
        select(AttackTurn, AttackRun.uid)
        .join(AttackRun, AttackRun.id == AttackTurn.run_id)
        .where(AttackRun.batch_id == uid)
        .order_by(AttackRun.id, AttackTurn.turn_index).limit(limit))).all()
    return {"items": [{
        "run_uid": uid_, "index": t.turn_index, "state": t.state,
        "prompt": t.prompt[:500], "response": t.response[:800],
        "signals": t.signals, "blocked": t.blocked, "backtracked": t.backtracked,
    } for t, uid_ in rows]}
