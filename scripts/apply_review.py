"""把人工复核结论落成生效结论。

## 为什么要这个脚本

系统里存在两个"攻破判定"层：

- ``judge_result.final_success`` —— 规则路 + LLM 路的自动融合结果。
- ``judge_result.review_label``  —— 人工复核给出的金标准。

原实现里，``review_label`` **只被 E4 当金标准用来算 P/R/F1，从不回写**
``attack_run.success``，而 ASR 全部读 ``success``。结果是：人工复核点了
"非攻破"，ASR 里那条仍然算攻破，复核形同虚设。

本脚本不改 ``final_success``（它必须保持"自动融合结论"的语义，否则 E4 会
拿被评估对象自己当标准），而是把"复核优先"的结论写进 ``attack_run.success``
与 ``success_turn``，让所有下游指标（ASR / 配对四格 / 危害分级）自动生效。

## 用法

    # 先看会改什么，不落库
    python scripts/apply_review.py --dry-run

    # 正式回写
    python scripts/apply_review.py

    # 给某条 run 的结论性判定打人工标签（1=攻破 / 0=未攻破），并立即回写
    python scripts/apply_review.py --label-run 34 0 --note "自造 STAR-2026-IN-07"
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from app.db import session_scope  # noqa: E402
from app.models import AttackRun, AttackTurn, JudgeResult  # noqa: E402


def _eff(j: JudgeResult) -> bool:
    """生效结论：有复核用复核，没有才用自动融合。"""
    return bool(j.review_label) if j.review_label is not None else bool(j.final_success)


async def _label_run(run_id: int, label: int, note: str, dry_run: bool = False) -> None:
    """给某 run 的结论性判定打人工标签。"""
    async with session_scope() as s:
        run = (await s.execute(
            select(AttackRun).where(AttackRun.id == run_id))).scalar_one_or_none()
        if run is None:
            print(f"[跳过] run {run_id} 不存在")
            return
        rows = (await s.execute(
            select(JudgeResult, AttackTurn.turn_index)
            .join(AttackTurn, AttackTurn.id == JudgeResult.turn_id)
            .where(JudgeResult.run_id == run_id)
            .order_by(AttackTurn.turn_index.desc()))).all()
        if not rows:
            print(f"[跳过] run {run_id} 没有判定记录")
            return
        # 结论性判定 = 最后一轮
        j, turn_index = rows[0]
        if dry_run:
            print(f"[预演打标] run {run_id} turn {turn_index} 将写入 review_label="
                  f"{int(bool(label))}（原 final_success={int(bool(j.final_success))}）{note}")
            return
        j.review_label = bool(label)
        j.reviewer = "owner"
        j.need_review = True
        ev = dict(j.rule_evidence or {})
        if note:
            ev["review_note"] = note
        # 危害分级必须与生效结论自洽：判非攻破就不能留着 disclosure。
        # 原分级存进 severity_auto 保留证据链，severity 置为 none。
        if not label and ev.get("severity") not in (None, "none"):
            ev["severity_auto"] = ev.get("severity")
            ev["severity"] = "none"
            ev["severity_override"] = "review"
        j.rule_evidence = ev
        print(f"[打标] run {run_id} turn {turn_index} review_label={int(bool(label))}"
              f"（原 final_success={int(bool(j.final_success))}）{note}")


async def _apply(dry_run: bool) -> None:
    async with session_scope() as s:
        # 只处理"有人工复核结论"的 run，其余一律不动
        reviewed_run_ids = list(dict.fromkeys(
            (await s.execute(
                select(JudgeResult.run_id)
                .where(JudgeResult.review_label.is_not(None))
                .order_by(JudgeResult.run_id))).scalars()))
        if not reviewed_run_ids:
            print("没有已复核记录，无需回写")
            return

        changes = []
        for rid in reviewed_run_ids:
            run = (await s.execute(
                select(AttackRun).where(AttackRun.id == rid))).scalar_one_or_none()
            if run is None:
                continue
            rows = (await s.execute(
                select(JudgeResult, AttackTurn.turn_index)
                .join(AttackTurn, AttackTurn.id == JudgeResult.turn_id)
                .where(JudgeResult.run_id == rid)
                .order_by(AttackTurn.turn_index))).all()

            hits = [ti for j, ti in rows if _eff(j)]
            new_success = bool(hits)
            new_turn = min(hits) if hits else None
            old_success = bool(run.success)
            old_turn = run.success_turn

            if new_success == old_success and new_turn == old_turn:
                continue

            changes.append({
                "run": rid, "batch": run.batch_id, "case": run.case_id,
                "old": (old_success, old_turn), "new": (new_success, new_turn),
                "reviewed": [(ti, j.review_label, j.final_success)
                             for j, ti in rows if j.review_label is not None],
            })
            if not dry_run:
                run.success = new_success
                run.success_turn = new_turn

        if not changes:
            print(f"已复核 {len(reviewed_run_ids)} 个 run，结论与现状一致，无需改动")
            return

        print(f"{'[预演] ' if dry_run else ''}共 {len(changes)} 个 run 的生效结论发生变化：\n")
        print(f"{'run':>5} {'batch':>16} {'case':>5}  {'原 success/turn':>17}"
              f"  {'新 success/turn':>17}   复核明细(turn,label,final)")
        print("-" * 100)
        for c in changes:
            o, n = c["old"], c["new"]
            det = " ".join(f"({ti},{int(bool(lb))},{int(bool(fs))})"
                           for ti, lb, fs in c["reviewed"])
            print(f"{c['run']:>5} {c['batch']:>16} {c['case']:>5}  "
                  f"{str(o[0]) + '/' + str(o[1]):>17}  {str(n[0]) + '/' + str(n[1]):>17}   {det}")
        print()
        n_flip = sum(1 for c in changes if c["old"][0] and not c["new"][0])
        n_raise = sum(1 for c in changes if not c["old"][0] and c["new"][0])
        print(f"其中：攻破→未攻破 {n_flip} 条，未攻破→攻破 {n_raise} 条")
        if dry_run:
            print("\n这是预演，未落库。去掉 --dry-run 正式执行。")


async def main() -> None:
    ap = argparse.ArgumentParser(description="把人工复核结论落成生效结论")
    ap.add_argument("--dry-run", action="store_true", help="只打印差异，不落库")
    ap.add_argument("--label-run", type=int, metavar="RUN_ID",
                    help="给指定 run 的结论性判定打人工标签")
    ap.add_argument("--label", type=int, choices=[0, 1], help="配合 --label-run：1=攻破 0=未攻破")
    ap.add_argument("--note", default="", help="复核依据，写进 rule_evidence.review_note")
    args = ap.parse_args()

    if args.label_run is not None:
        if args.label is None:
            ap.error("--label-run 必须配合 --label 0/1")
        await _label_run(args.label_run, args.label, args.note, dry_run=args.dry_run)

    await _apply(args.dry_run)


if __name__ == "__main__":
    asyncio.run(main())
