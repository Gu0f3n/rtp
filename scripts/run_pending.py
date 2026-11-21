"""限流恢复后的待办实验一键执行。

按优先级执行三组，每组独立汇报，任一组失败不影响后续：

  1) 消融   —— 单载荷 S004-T-task_wrap 在 5 档护栏下各一次
                目的是定位"有效成分是哪一层"。论文 6.7.3(5) 已承诺此实验。
  2) PROBE  —— 12 条算子载荷的加固后一组（原批次因 429 全灭，需重置后续跑）
  3) PLAIN  —— 28 条平铺载荷的加固后一组剩余 23 条（已有 5 条完成）

执行前会自动重置 error 状态的 run 为 pending，并清掉这些 run 残留的
turn / judge 记录——否则续跑会重复写轮次，判定也会重复计入。

用法：
    DB_NAME=rtp_real.db python scripts/run_pending.py            # 全部按顺序跑
    DB_NAME=rtp_real.db python scripts/run_pending.py --only ablate
    DB_NAME=rtp_real.db python scripts/run_pending.py --skip plain
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import delete, func, select, update  # noqa: E402

from app.config import settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.models import AttackRun, AttackTurn, Batch, JudgeResult  # noqa: E402
from app.runner import executor  # noqa: E402

PROBE_BATCH = "B1792920368180"   # 12 条算子载荷，加固后，429 全灭
PLAIN_BATCH = "B1792919573325"   # 28 条平铺载荷，加固后，5 完成 23 待跑
ABLATE_CASE = "S004-T-task_wrap"


async def reset_errors(batch_uid: str) -> int:
    """把 error 的 run 改回 pending，并清掉它们残留的 turn 与 judge。"""
    async with session_scope() as s:
        runs = list((await s.execute(
            select(AttackRun.id).where(AttackRun.batch_id == batch_uid,
                                       AttackRun.status == "error"))).scalars())
        if not runs:
            return 0
        turns = list((await s.execute(
            select(AttackTurn.id).where(AttackTurn.run_id.in_(runs)))).scalars())
        if turns:
            await s.execute(delete(JudgeResult).where(JudgeResult.turn_id.in_(turns)))
            await s.execute(delete(AttackTurn).where(AttackTurn.id.in_(turns)))
        await s.execute(
            update(JudgeResult).where(JudgeResult.run_id.in_(runs))
            .values(rule_success=False, llm_success=False, final_success=False,
                    conflict=False, need_review=False))
        await s.execute(
            update(AttackRun).where(AttackRun.id.in_(runs))
            .values(status="pending", success=False, success_turn=None,
                    total_turns=0, token_in=0, token_out=0, cost=0.0, error=None))
        batch = (await s.execute(
            select(Batch).where(Batch.uid == batch_uid))).scalar_one()
        batch.status = "pending"
        batch.failed = 0
        return len(runs)


async def sync_batch_counters(batch_uid: str) -> None:
    """修正 batch 的 done/failed 统计（历史上有批次中断后未同步）。"""
    async with session_scope() as s:
        completed = (await s.execute(
            select(func.count()).select_from(AttackRun)
            .where(AttackRun.batch_id == batch_uid,
                   AttackRun.status == "completed"))).scalar_one()
        errors = (await s.execute(
            select(func.count()).select_from(AttackRun)
            .where(AttackRun.batch_id == batch_uid,
                   AttackRun.status == "error"))).scalar_one()
        batch = (await s.execute(
            select(Batch).where(Batch.uid == batch_uid))).scalar_one()
        batch.done = int(completed)
        batch.failed = int(errors)


async def run_batch_step(label: str, batch_uid: str) -> dict:
    print(f"\n{'=' * 60}\n[{label}] 批次 {batch_uid}\n{'=' * 60}")
    n = await reset_errors(batch_uid)
    if n:
        print(f"  重置 {n} 条 error 状态为 pending（已清空残留轮次）")

    t0 = time.perf_counter()
    try:
        stats = await executor.run_batch(batch_uid)
    except Exception as e:  # noqa: BLE001
        print(f"  执行中断：{type(e).__name__}: {e}")
        await sync_batch_counters(batch_uid)
        return {"label": label, "batch": batch_uid, "ok": False, "err": str(e)[:120]}

    await sync_batch_counters(batch_uid)
    async with session_scope() as s:
        runs = list((await s.execute(
            select(AttackRun).where(AttackRun.batch_id == batch_uid))).scalars())
        ok = sum(1 for r in runs if r.success)
        err = sum(1 for r in runs if r.status == "error")
        pend = sum(1 for r in runs if r.status == "pending")
        cost = sum(r.cost or 0.0 for r in runs)
    elapsed = time.perf_counter() - t0
    print(f"  完成：攻破 {ok}/{len(runs)}，error {err}，未执行 {pend}，"
          f"累计成本 ¥{cost:.4f}，本轮耗时 {elapsed:.0f}s")
    return {"label": label, "batch": batch_uid, "ok": pend == 0,
            "runs": len(runs), "success": ok, "error": err, "pending": pend,
            "cost": cost, "elapsed": elapsed}


async def run_ablate() -> list[dict]:
    print(f"\n{'=' * 60}\n[消融] 单载荷 {ABLATE_CASE} × 5 档护栏\n{'=' * 60}")
    out = []
    for profile in ["none", "input", "output", "prompt", "full"]:
        try:
            bid = await executor.create_batch(
                target_uid="T1", experiment="ABLATE", strategy="multi",
                max_turns=5, guardrail_profile=profile,
                case_uids=[ABLATE_CASE], name=f"ABLATE-{profile}-{ABLATE_CASE}")
            print(f"\n  -- 档位 {profile} → {bid}")
            t0 = time.perf_counter()
            await executor.run_batch(bid)
            async with session_scope() as s:
                r = (await s.execute(
                    select(AttackRun).where(AttackRun.batch_id == bid))).scalar_one()
                blocked = len(list((await s.execute(
                    select(AttackTurn.id).where(AttackTurn.run_id == r.id,
                                                AttackTurn.blocked.is_(True)))).scalars()))
                turns = len(list((await s.execute(
                    select(AttackTurn.id).where(AttackTurn.run_id == r.id))).scalars()))
            print(f"     攻破={r.success} 成功轮={r.success_turn} 轮次={turns} "
                  f"拦截={blocked} ¥{r.cost:.4f}")
            out.append({"profile": profile, "batch": bid, "success": bool(r.success),
                        "success_turn": r.success_turn, "turns": turns,
                        "blocked": blocked, "cost": r.cost, "ok": True})
        except Exception as e:  # noqa: BLE001
            print(f"     失败：{type(e).__name__}: {e}")
            out.append({"profile": profile, "batch": "-", "success": None,
                        "cost": 0.0, "ok": False, "err": str(e)[:100]})
    return out


def print_ablate(rows: list[dict]) -> None:
    print(f"\n{'=' * 60}\n单载荷护栏消融结果：{ABLATE_CASE}\n{'=' * 60}")
    print(f"{'档位':<10}{'攻破':<8}{'成功轮':<8}{'轮次':<6}{'拦截':<6}{'成本'}")
    print("-" * 52)
    for r in rows:
        if not r.get("ok"):
            print(f"{r['profile']:<10}执行失败")
            continue
        print(f"{r['profile']:<10}{'是' if r['success'] else '否':<8}"
              f"{str(r['success_turn'] or '-'):<8}{r['turns']:<6}"
              f"{r['blocked']:<6}¥{r['cost']:.4f}")
    base = next((r for r in rows if r["profile"] == "none" and r.get("ok")), None)
    if base and base["success"]:
        print("\n判读：")
        for r in rows:
            if r["profile"] == "none" or not r.get("ok"):
                continue
            if not r["success"]:
                how = "过滤器拦截" if r["blocked"] else "模型自行拒绝（过滤器未触发）"
                print(f"  {r['profile']:<8} 攻破被消除，机制为{how}")
            else:
                print(f"  {r['profile']:<8} 仍被攻破，该层对本载荷无效")
    elif base:
        print("\n判读：基线未攻破，本载荷无法用于消融对照。")


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="ablate/probe/plain，逗号分隔")
    ap.add_argument("--skip", default="", help="要跳过的组")
    args = ap.parse_args()

    if settings.use_mock:
        print("!! mock 模式，数据不可用于论文。")
        return 2

    only = {x.strip() for x in args.only.split(",") if x.strip()}
    skip = {x.strip() for x in args.skip.split(",") if x.strip()}
    want = lambda k: (not only or k in only) and k not in skip  # noqa: E731

    print(f"数据库：{settings.__dict__.get('db_name')} | 真实调用：是")
    t_all = time.perf_counter()
    report: dict = {}

    if want("ablate"):
        report["ablate"] = await run_ablate()
        print_ablate(report["ablate"])

    if want("probe"):
        report["probe"] = await run_batch_step("PROBE 算子组加固后", PROBE_BATCH)

    if want("plain"):
        report["plain"] = await run_batch_step("PLAIN 平铺组加固后", PLAIN_BATCH)

    print(f"\n{'=' * 60}\n汇总（总耗时 {time.perf_counter() - t_all:.0f}s）\n{'=' * 60}")
    if "ablate" in report:
        print_ablate(report["ablate"])
    for k in ("probe", "plain"):
        if k in report:
            r = report[k]
            print(f"  {r['label']}: 攻破 {r.get('success', '-')}/{r.get('runs', '-')}，"
                  f"error {r.get('error', '-')}，未执行 {r.get('pending', '-')}，"
                  f"¥{r.get('cost', 0):.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
