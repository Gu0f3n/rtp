"""任务执行器：把生成 / 编排 / 判定串成批次，并保证断点续跑。

断点续跑不是"锦上添花"，而是**必须在 M1 阶段就实现**的能力：
一轮完整实验受接口限流与响应延迟影响可能持续数小时，中途断掉若不能从
断点继续，就只能从头再来。实现方式是按用例粒度把状态写进 attack_run，
重新启动时只挑 status='pending' 的记录执行。
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy import func, select, update

from app.config import settings
from app.db import session_scope
from app.engines import chain, orchestrator
from app.models import AttackCase, AttackRun, AttackSeed, AttackTurn, Batch, JudgeResult, TargetApp
from app.targets.builtin import build_target


def _now() -> datetime:
    return datetime.now(timezone.utc)


def fingerprint(target: TargetApp, strategy: str, max_turns: int, profile: str) -> str:
    """配置指纹：只要其中任何一项变化，历史结果就不能直接与新结果比较。"""
    raw = "|".join([
        target.uid, target.config_version, target.form_type,
        settings.tier("target").model, str(settings.target_temperature),
        settings.tier("judge").model, strategy, str(max_turns), profile,
        "mock" if settings.use_mock else "live",
    ])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


@dataclass
class BatchStats:
    batch_id: str
    total: int = 0
    done: int = 0
    failed: int = 0        # 执行报错的 run 数（不是"攻击失败"）
    skipped: int = 0
    success: int = 0       # 攻击成功的 run 数（即 target 被攻破）
    token_in: int = 0
    token_out: int = 0
    cost: float = 0.0
    elapsed_s: float = 0.0
    errors: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# 创建批次
# --------------------------------------------------------------------------- #
async def create_batch(
    *,
    target_uid: str,
    experiment: str = "E1",
    strategy: str = "single",
    max_turns: int = 1,
    guardrail_profile: str | None = None,
    limit: int | None = None,
    channels: list[str] | None = None,
    plain_only: bool = False,
    case_uids: list[str] | None = None,
    name: str = "",
) -> str:
    """把一批 (用例 × 靶标 × 配置) 落成待执行任务，返回 batch_id。

    ``plain_only`` 只取未叠加算子的载荷。E1 基线、E2 轮次对比、E5 护栏对比
    都应当开启它——这三组实验的自变量分别是"攻击面基线""轮次深度""护栏状态"，
    把算子变异混进来就成了多变量同时变化，结论不可归因。
    """
    async with session_scope() as s:
        target = (await s.execute(
            select(TargetApp).where(TargetApp.uid == target_uid))).scalar_one_or_none()
        if target is None:
            raise ValueError(f"靶标未登记：{target_uid}（请先执行 scripts/init_db.py）")

        profile = guardrail_profile or target.guardrail_profile or "none"
        fp = fingerprint(target, strategy, max_turns, profile)

        case_stmt = select(AttackCase).order_by(AttackCase.id)
        if channels:
            case_stmt = case_stmt.where(AttackCase.channel.in_(channels))
        cases = list((await s.execute(case_stmt)).scalars())

        # 显式指定载荷：用于"只测已确认有效的载荷"这类场景。
        # 与 plain_only 的区别是它不关心算子状态，适合做配对对照
        # （对照组和实验组必须打同一批 case）。
        if case_uids:
            want = set(case_uids)
            cases = [c for c in cases if c.uid in want]

        if plain_only:
            cases = [c for c in cases if not c.operator_chain]

        # 按**靶标形态**过滤载荷：种子的 target_forms 声明了它适用于哪类靶标
        # （chat / rag / agent）。不过滤会有两种失真——
        #   1) 把客服话术发给知识库靶标，目标必然答非所问，看起来"防住了"，
        #      实际是问题本身不成立，会系统性压低 ASR；
        #   2) 同一份 case 池被不同靶标共用，跨靶标对比就混入了样本差异。
        # 原本只靠 generator 在生成时过滤，但 case 入库后不记靶标，
        # 建批次时若从全表取，前面为别的靶标生成的载荷会一并被选中。
        # target_forms 为空表示通用载荷，任何形态都可用。
        if target.form_type:
            seed_rows = (await s.execute(
                select(AttackSeed.id, AttackSeed.target_forms))).all()
            ok_seed = {sid for sid, forms in seed_rows
                       if not forms or target.form_type in forms}
            cases = [c for c in cases if c.seed_id in ok_seed]

        if limit:
            cases = cases[:limit]
        if not cases:
            raise ValueError(
                "没有可用的攻击用例。请先生成载荷（POST /api/cases/generate）；"
                "若已开启 plain_only，请确认存在未叠加算子的基础载荷。")

        batch = Batch(
            uid=f"B{int(time.time() * 1000)}",
            name=name or f"{experiment}-{target_uid}-{strategy}{max_turns}-{profile}",
            target_uid=target_uid, experiment=experiment, strategy=strategy,
            max_turns=max_turns, guardrail_profile=profile,
            case_filter={"channels": channels or [], "limit": limit,
                         "plain_only": plain_only, "case_uids": case_uids or []},
            total=len(cases), mock=settings.use_mock, config_fingerprint=fp,
            status="pending")
        s.add(batch)
        await s.flush()

        for c in cases:
            s.add(AttackRun(
                uid=f"{batch.uid}-{c.uid}",
                batch_id=batch.uid, target_id=target.id, case_id=c.id,
                strategy=strategy, max_turns=max_turns,
                guardrail_profile=profile, status="pending",
                config_fingerprint=fp))
        await s.flush()
        return batch.uid


# --------------------------------------------------------------------------- #
# 执行
# --------------------------------------------------------------------------- #
async def _execute_one(run_id: int, target_uid: str, profile: str,
                       strategy: str, max_turns: int) -> tuple[bool, int, int, float, str | None]:
    """执行单个 run。返回 (是否成功, token_in, token_out, cost, error)。"""
    async with session_scope() as s:
        run = (await s.execute(select(AttackRun).where(AttackRun.id == run_id))).scalar_one()
        case = (await s.execute(select(AttackCase).where(AttackCase.id == run.case_id))).scalar_one()
        case_text = case.text
        run_uid = run.uid

    target = build_target(target_uid, profile=profile)
    if strategy == "chain":
        # 级联链：每级的产出是下一级的武器，因此需要 run.uid 做确定性种子，
        # 保证同一条 run 重跑时话术逐字一致——否则链深度差异无法归因。
        # 此时 max_turns 的语义是"最多几级"，而非"最多几轮"。
        res = await chain.run_chain(target, case_text, max_stages=max_turns,
                                    case_key=run_uid)
    else:
        res = await orchestrator.run_case(target, case_text, strategy=strategy,
                                          max_turns=max_turns)

    async with session_scope() as s:
        run = (await s.execute(select(AttackRun).where(AttackRun.id == run_id))).scalar_one()
        # 只有"真的出故障"或"一轮都没跑成"才算 error。
        # 预算耗尽属于正常收尾，其已有轮次与判定仍然有效，必须计入 ASR 分母。
        if res.error or not res.turns:
            run.status = "error"
            run.error = res.error or "未产生任何有效轮次"
        else:
            run.status = "completed"
            run.error = None
            run.stop_reason = res.stop_reason
        run.success = bool(res.success) and not res.error
        run.success_turn = res.success_turn
        run.total_turns = len(res.turns)
        run.token_in = res.token_in
        run.token_out = res.token_out
        run.cost = res.cost
        run.latency_ms = res.latency_ms
        run.finished_at = _now()

        for idx, tr in enumerate(res.turns):
            t = AttackTurn(
                run_id=run.id, turn_index=tr.index, state=tr.state,
                prompt=tr.prompt, response=tr.response,
                latency_ms=tr.latency_ms, signals=tr.signals,
                slots=tr.slots or {},
                backtracked=tr.backtracked, blocked=tr.blocked,
                blocked_by=tr.blocked_by,
                frozen=bool(res.success))
            s.add(t)
            await s.flush()
            if tr.judge:
                # 复核队列只接收"每个任务的结论性判定"（最后一轮）。
                # 探测轮与升温轮的判定只反映过程，不构成结论，
                # 把它们全部堆进队列会让标注工作失焦。
                is_conclusive = (idx == len(res.turns) - 1)
                s.add(JudgeResult(
                    run_id=run.id, turn_id=t.id,
                    rule_success=tr.judge.rule_success,
                    rule_evidence=tr.judge.rule_evidence,
                    llm_success=tr.judge.llm_success,
                    llm_category=tr.judge.llm_category,
                    llm_confidence=tr.judge.llm_confidence,
                    llm_reason=tr.judge.llm_reason,
                    final_success=tr.judge.final_success,
                    conflict=tr.judge.conflict,
                    need_review=tr.judge.need_review and is_conclusive))
        await s.flush()

    return res.success, res.token_in, res.token_out, res.cost, res.error


async def run_batch(batch_uid: str,
                    progress: Callable[[dict[str, Any]], None] | None = None) -> BatchStats:
    """执行（或续跑）一个批次。已完成的任务会被跳过。"""
    stats = BatchStats(batch_id=batch_uid)
    t0 = time.perf_counter()

    async with session_scope() as s:
        batch = (await s.execute(select(Batch).where(Batch.uid == batch_uid))).scalar_one()
        target = (await s.execute(
            select(TargetApp).where(TargetApp.uid == batch.target_uid))).scalar_one()
        run_ids = list((await s.execute(
            select(AttackRun.id).where(AttackRun.batch_id == batch_uid,
                                       AttackRun.status == "pending")
            .order_by(AttackRun.id))).scalars())
        done_count = (await s.execute(
            select(func.count()).select_from(AttackRun)
            .where(AttackRun.batch_id == batch_uid,
                   AttackRun.status.in_(["completed", "error"])))).scalar_one()
        batch.status = "running"
        stats.total = batch.total
        stats.done = done_count
        stats.skipped = done_count
        target_uid = batch.target_uid
        profile = batch.guardrail_profile
        strategy = batch.strategy
        max_turns = batch.max_turns

    sem = asyncio.Semaphore(max(1, settings.concurrency))

    async def worker(rid: int) -> None:
        async with sem:
            try:
                ok, tin, tout, cost, err = await _execute_one(
                    rid, target_uid, profile, strategy, max_turns)
                stats.done += 1
                stats.success += 1 if ok else 0
                stats.token_in += tin
                stats.token_out += tout
                stats.cost += cost
                if err:
                    stats.failed += 1
                    stats.errors.append(f"run {rid}: {err}")
            except Exception as e:  # noqa: BLE001
                stats.failed += 1
                stats.errors.append(f"run {rid}: {type(e).__name__}: {e}")
                async with session_scope() as s:
                    await s.execute(
                        update(AttackRun).where(AttackRun.id == rid)
                        .values(status="error", error=str(e)[:500], finished_at=_now()))
            if progress:
                progress({"done": stats.done, "total": stats.total,
                          "breached": stats.success, "errors": stats.failed})

    await asyncio.gather(*(worker(rid) for rid in run_ids))

    async with session_scope() as s:
        batch = (await s.execute(select(Batch).where(Batch.uid == batch_uid))).scalar_one()
        batch.done = stats.done
        batch.failed = stats.failed
        batch.status = "done" if stats.done >= stats.total else "partial"
        batch.finished_at = _now()

    stats.elapsed_s = round(time.perf_counter() - t0, 2)
    return stats


# --------------------------------------------------------------------------- #
# 重放
# --------------------------------------------------------------------------- #
async def replay_run(run_id: int) -> dict[str, Any]:
    """重放一条成功轨迹，验证可复现性。"""
    async with session_scope() as s:
        run = (await s.execute(select(AttackRun).where(AttackRun.id == run_id))).scalar_one()
        target = (await s.execute(
            select(TargetApp).where(TargetApp.id == run.target_id))).scalar_one()
        turns = list((await s.execute(
            select(AttackTurn).where(AttackTurn.run_id == run_id)
            .order_by(AttackTurn.turn_index))).scalars())

    if not turns:
        return {"reproduced": False, "reason": "该任务没有可重放的轨迹"}

    frozen = []
    for t in turns:
        jr = (await _judge_of(t.id))
        frozen.append({"index": t.turn_index, "prompt": t.prompt,
                       "success": jr.final_success if jr else False})

    target_obj = build_target(target.uid, profile=run.guardrail_profile)
    rr = await orchestrator.replay(frozen, target_obj)
    return {"reproduced": rr.reproduced, "matched_turns": rr.matched_turns,
            "total_turns": rr.total_turns, "detail": rr.detail}


async def _judge_of(turn_id: int) -> JudgeResult | None:
    async with session_scope() as s:
        return (await s.execute(
            select(JudgeResult).where(JudgeResult.turn_id == turn_id))).scalar_one_or_none()


# --------------------------------------------------------------------------- #
# 批量实验（E1–E5 的编排入口）
# --------------------------------------------------------------------------- #
EXPERIMENT_PLANS: dict[str, list[dict[str, Any]]] = {
    # 每组只允许一个自变量变化，否则结论不可归因
    "E1": [{"strategy": "single", "max_turns": 1, "guardrail_profile": "none",
            "channels": ["template"], "plain_only": True}],
    "E2": [{"strategy": "single", "max_turns": 1, "guardrail_profile": "none",
            "plain_only": True},
           {"strategy": "multi", "max_turns": 3, "guardrail_profile": "none",
            "plain_only": True},
           {"strategy": "multi", "max_turns": 5, "guardrail_profile": "none",
            "plain_only": True},
           {"strategy": "multi", "max_turns": 10, "guardrail_profile": "none",
            "plain_only": True}],
    # E3 的自变量是"生成通道"，因此不限制 plain_only——
    # 算子链本身就是待评估的生成策略之一
    "E3": [{"strategy": "multi", "max_turns": 5, "guardrail_profile": "none",
            "channels": ["template"]},
           {"strategy": "multi", "max_turns": 5, "guardrail_profile": "none",
            "channels": ["llm"]},
           {"strategy": "multi", "max_turns": 5, "guardrail_profile": "none",
            "channels": ["template", "llm"]}],
    "E4": [],   # 复用已有批次做判定对比，不新建攻击任务
    "E5": [{"strategy": "multi", "max_turns": 5, "guardrail_profile": p,
            "plain_only": True}
           for p in ("none", "input", "output", "prompt", "full")],
    # E6 级联深度对比：同一批种子、同一个靶标，只变"攻击怎么组织"。
    #
    # 三组的**交互预算不等**（1 / 5 / 4 次），这是故意且必须说明的：
    # 级联链的第 1 级就一次交互，若强行让单轮也用 4 次交互，就成了
    # "重复问四遍同一个问题"，不是单轮了。因此 E6 报的是"每种组织方式
    # 在各自的自然形态下能打成什么样"，成本要一起报进表里，否则会被
    # 质疑"胜之不武"。avg_cost / avg_depth 与 ASR 同列呈现。
    "E6": [{"strategy": "single", "max_turns": 1, "guardrail_profile": "none",
            "plain_only": True},
           {"strategy": "multi", "max_turns": 5, "guardrail_profile": "none",
            "plain_only": True},
           {"strategy": "chain", "max_turns": 4, "guardrail_profile": "none",
            "plain_only": True}],
}


async def run_experiment(experiment: str, target_uid: str,
                         limit: int | None = None) -> list[BatchStats]:
    plan = EXPERIMENT_PLANS.get(experiment.upper())
    if not plan:
        raise ValueError(f"未知实验：{experiment}")
    out = []
    for cfg in plan:
        bid = await create_batch(target_uid=target_uid, experiment=experiment.upper(),
                                 limit=limit, **cfg)
        out.append(await run_batch(bid))
    return out
