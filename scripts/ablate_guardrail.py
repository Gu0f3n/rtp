"""单载荷护栏消融：同一条载荷在全部护栏档位下各执行一次。

用途：定位"护栏的有效成分到底是哪一层"。

E5 的配对实验只做了 G0（none）与 G3（full）两档，结论是"full 有效，
但拦截次数为 0"——这说明过滤器没被触发，有效成分是提示加固。但这是
从"拦截次数为 0"反推出来的，不是直接测出来的。要把它变成直接证据，
必须把三件套拆开单独开：

    none    全部关闭          ← 基线
    input   仅输入过滤        ← 若 ASR 与 none 相同，说明该载荷规避了输入规则
    output  仅输出过滤        ← 若 ASR 降到 0 但拦截次数>0，说明拦的是"已生成的泄露"
    prompt  仅系统提示加固     ← 若 ASR 降到 0 且拦截次数=0，说明模型自己拒绝
    full    三件套全开        ← 与 E5 的 G3 对齐

一条载荷 × 5 档 = 5 次执行、约 25 次目标调用，成本可忽略。
五档共用同一行 AttackCase（case.uid 全局唯一），因此载荷文本逐字一致，
不存在"换了一版载荷"的混淆。

用法：
    DB_NAME=rtp_real.db python scripts/ablate_guardrail.py --case S004-T-task_wrap
    DB_NAME=rtp_real.db python scripts/ablate_guardrail.py --case S004-T-task_wrap --resume
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from app.config import settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.models import AttackCase, AttackRun, Batch, JudgeResult, AttackTurn  # noqa: E402
from app.runner import executor  # noqa: E402

PROFILES = ["none", "input", "output", "prompt", "full"]
LABELS = {
    "none": "G0 无护栏",
    "input": "G1 仅输入过滤",
    "output": "G2 仅输出过滤",
    "prompt": "Gp 仅提示加固",
    "full": "G3 组合加固",
}


async def _existing_batch(case_uid: str, profile: str) -> str | None:
    """找一个已经跑完的同配置批次，避免重复花钱。"""
    async with session_scope() as s:
        rows = await s.execute(
            select(Batch.uid, Batch.status, Batch.case_filter)
            .where(Batch.experiment == "ABLATE",
                   Batch.guardrail_profile == profile)
            .order_by(Batch.id.desc()))
        for uid, status, cf in rows:
            if cf and case_uid in (cf.get("case_uids") or []):
                return uid
    return None


async def _run_one(case_uid: str, profile: str, max_turns: int,
                   resume: bool) -> dict:
    if resume:
        prev = await _existing_batch(case_uid, profile)
        if prev:
            print(f"  [跳过] {LABELS[profile]} 已有批次 {prev}")
            return await _summarize(prev, profile)

    bid = await executor.create_batch(
        target_uid="T1",
        experiment="ABLATE",
        strategy="multi",
        max_turns=max_turns,
        guardrail_profile=profile,
        case_uids=[case_uid],
        name=f"ABLATE-{profile}-{case_uid}",
    )
    print(f"  [执行] {LABELS[profile]} 批次 {bid}")
    await executor.run_batch(bid)
    return await _summarize(bid, profile)


async def _summarize(batch_uid: str, profile: str) -> dict:
    async with session_scope() as s:
        runs = list((await s.execute(
            select(AttackRun).where(AttackRun.batch_id == batch_uid))).scalars())
        out = {
            "profile": profile,
            "label": LABELS[profile],
            "batch": batch_uid,
            "runs": len(runs),
            "success": 0,
            "errors": 0,
            "success_turn": None,
            "turns": 0,
            "blocked": 0,
            "cost": 0.0,
            "refusal_turns": 0,
            "leak_turns": 0,
        }
        for r in runs:
            if r.status == "error":
                out["errors"] += 1
            if r.success:
                out["success"] += 1
                out["success_turn"] = r.success_turn
            out["turns"] += r.total_turns or 0
            out["cost"] += r.cost or 0.0

            turns = list((await s.execute(
                select(AttackTurn.id, AttackTurn.blocked, AttackTurn.blocked_by)
                .where(AttackTurn.run_id == r.id))).all())
            out["blocked"] += sum(1 for _tid, b, _by in turns if b)
            if turns:
                jrs = list((await s.execute(
                    select(JudgeResult.rule_success, JudgeResult.final_success)
                    .where(JudgeResult.run_id == r.id))).all())
                out["leak_turns"] += sum(1 for rs, fs in jrs if fs)
                out["refusal_turns"] += sum(1 for rs, fs in jrs if not fs)
        return out


def _fmt(rows: list[dict]) -> str:
    hdr = (f"{'配置':<16}{'攻破':<6}{'轮次':<6}{'拦截':<6}{'成功轮':<8}{'成本':<9}{'失败'}")
    sep = "-" * len(hdr)
    lines = [hdr, sep]
    for r in rows:
        sturn = r["success_turn"] if r["success_turn"] else "-"
        lines.append(
            f"{r['label']:<16}"
            f"{('是' if r['success'] else '否'):<6}"
            f"{r['turns']:<6}"
            f"{r['blocked']:<6}"
            f"{str(sturn):<8}"
            f"¥{r['cost']:.4f}  "
            f"{r['errors']}")
    return "\n".join(lines)


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", default="S004-T-task_wrap",
                    help="载荷 uid（attack_case.uid，全局唯一）")
    ap.add_argument("--max-turns", type=int, default=5)
    ap.add_argument("--profiles", default=",".join(PROFILES))
    ap.add_argument("--resume", action="store_true",
                    help="已有同配置批次则跳过，用于中断后续跑")
    args = ap.parse_args()

    if settings.use_mock:
        print("!! 当前为 mock 模式，产出的数据不得写入论文。请在 .env 配置 LLM_API_KEY。")
        return 2

    async with session_scope() as s:
        case = (await s.execute(
            select(AttackCase).where(AttackCase.uid == args.case))).scalar_one_or_none()
        if case is None:
            print(f"载荷不存在：{args.case}")
            return 1
        print(f"载荷 {case.uid}（{len(case.text)} 字符，算子={case.operator_chain or '无'}）")
        print(f"文本：{case.text[:100]}...")

    profiles = [p.strip() for p in args.profiles.split(",") if p.strip()]
    rows: list[dict] = []
    t0 = time.perf_counter()
    for p in profiles:
        try:
            rows.append(await _run_one(args.case, p, args.max_turns, args.resume))
        except Exception as e:  # noqa: BLE001
            print(f"  [失败] {LABELS.get(p, p)}: {e}")
            rows.append({"profile": p, "label": LABELS.get(p, p), "batch": "-",
                         "runs": 0, "success": 0, "errors": 1, "success_turn": None,
                         "turns": 0, "blocked": 0, "cost": 0.0,
                         "refusal_turns": 0, "leak_turns": 0})

    elapsed = time.perf_counter() - t0
    print("\n" + "=" * 62)
    print(f"单载荷护栏消融：{args.case}")
    print("=" * 62)
    print(_fmt(rows))
    print("-" * 62)
    print(f"总成本 ¥{sum(r['cost'] for r in rows):.4f}，耗时 {elapsed:.0f}s")
    print("\n判读：")
    base = next((r for r in rows if r["profile"] == "none"), None)
    if base:
        for r in rows:
            if r["profile"] == "none":
                continue
            if r["success"] and base["success"]:
                verdict = "未降低攻破（该层对本载荷无效）"
            elif not r["success"] and base["success"]:
                if r["blocked"] > 0:
                    verdict = "降低攻破，且由过滤器拦截（拦截次数>0）"
                else:
                    verdict = "降低攻破，模型自行拒绝（过滤器未触发）"
            elif not base["success"]:
                verdict = "基线未攻破，本档无从对照"
            else:
                verdict = "出现基线未有的攻破"
            print(f"  {r['label']:<16} → {verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
