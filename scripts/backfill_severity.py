"""为历史判定结果回溯补齐危害分级字段。

背景：severity（危害分级）是后加的，早期记录里只有 success 二态。
若不回溯，E1–E5 的历史数据与新数据口径不一致，报告里会出现
"新批次有分级、旧批次没有"的断层。

**只补 severity 与 recon 两个字段，不改动 success / conflict / need_review。**
这一点是硬约束：判定结论一旦落库并被引用（论文数据、报告、人工标注），
就不能事后重算——那等于篡改实验记录。分级属于"附加标注"，可以补。

用法：
    python scripts/backfill_severity.py [--dry-run]
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select  # noqa: E402

from app.db import engine, session_scope  # noqa: E402
from app.engines.judge import rule_judge  # noqa: E402
from app.models import AttackTurn, JudgeResult  # noqa: E402


async def main(dry_run: bool = False, force: bool = False) -> None:
    rows = None
    async with session_scope() as s:
        res = await s.execute(
            select(JudgeResult.id, JudgeResult.rule_evidence,
                   AttackTurn.response, AttackTurn.prompt)
            .join(AttackTurn, AttackTurn.id == JudgeResult.turn_id))
        rows = res.all()

    stat: dict[str, int] = {}
    changed = 0
    async with session_scope() as s:
        for jid, ev, response, prompt in rows:
            ev = dict(ev or {})
            if "severity" in ev and not force:
                stat["已有分级，跳过"] = stat.get("已有分级，跳过", 0) + 1
                continue
            rv = rule_judge(response or "")
            ev["severity"] = rv.severity
            ev["recon"] = rv.recon
            ev["severity_backfilled"] = True
            # 记录回溯时规则路的结论与当时是否一致，供论文说明使用。
            # 不一致不代表原判定错，而是规则库在两次判定之间发生过扩充。
            ev["recheck_success"] = rv.success
            stat[rv.severity] = stat.get(rv.severity, 0) + 1
            changed += 1
            if not dry_run:
                jr = (await s.execute(
                    select(JudgeResult).where(JudgeResult.id == jid))).scalar_one()
                jr.rule_evidence = ev

    print(f"{'[试运行] ' if dry_run else ''}共 {len(rows)} 条判定记录，"
          f"{'强制重算' if force else '需补'} {changed} 条")
    for k, v in sorted(stat.items(), key=lambda x: -x[1]):
        print(f"  {k:20s} {v}")
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main("--dry-run" in sys.argv, "--force" in sys.argv))
