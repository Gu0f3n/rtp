"""端到端最小闭环验证（M1 验收脚本）。

流程：生成载荷 → 创建批次 → 执行 → 聚合指标 → 导出报告，
覆盖"生成—编排—判定—指标—报告"全链路。

用法::

    python scripts/e2e.py                 # 小规模跑通（每靶标 8 条载荷）
    python scripts/e2e.py --full          # 全量（约 300+ 次调用）
    python scripts/e2e.py --turns 5       # 指定多轮深度
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.db import engine, init_db, session_scope  # noqa: E402
from app.engines import generator  # noqa: E402
from app.runner import executor, metrics, report  # noqa: E402

BAR = "─" * 62


def title(text: str) -> None:
    print(f"\n{BAR}\n  {text}\n{BAR}")


async def main(args) -> int:
    await init_db()
    t_start = time.perf_counter()

    title("0. 环境")
    print(f"  数据源      : {'MOCK（离线模拟）' if settings.use_mock else '真实模型 API'}")
    print(f"  目标模型    : {settings.tier('target').model}")
    print(f"  攻击模型    : {settings.tier('attack').model}")
    print(f"  判定模型    : {settings.tier('judge').model}")
    print(f"  并发上限    : {settings.concurrency}")
    if settings.use_mock:
        print("  ⚠ MOCK 模式：以下数值仅验证流程，不得写入论文")

    # ---------------- 1. 生成 ----------------
    title("1. 双通道攻击生成")
    async with session_scope() as s:
        res = await generator.generate_cases(
            s, target_uid="T1",
            channels=["template", "llm"],
            operators_wanted=["encoding", "task_wrap", "role_nesting", "payload_nest"],
            max_chain=1,
            limit=None if args.full else 8)
    print(f"  本次新建 {res.created} 条，已存在跳过（按 seed+通道+算子链去重）")
    print(f"  按通道  : {res.by_channel}")
    print(f"  按算子  : {res.by_operator}")

    # ---------------- 2. 单轮 vs 多轮 ----------------
    runs = []
    for target_uid, label in (("T1", "客服"), ("T2", "RAG"), ("T3", "Agent")):
        title(f"2. 靶标 {target_uid}（{label}）单轮 vs 多轮")
        if target_uid != "T1":
            async with session_scope() as s:
                await generator.generate_cases(
                    s, target_uid=target_uid, channels=["template", "llm"],
                    operators_wanted=["task_wrap", "payload_nest"],
                    max_chain=1, limit=None if args.full else 6)

        for strategy, max_turns in (("single", 1), ("multi", args.turns)):
            bid = await executor.create_batch(
                target_uid=target_uid, experiment="E2", strategy=strategy,
                max_turns=max_turns, guardrail_profile="none", plain_only=True,
                limit=None if args.full else 6,
                name=f"e2e-{target_uid}-{strategy}{max_turns}")
            stats = await executor.run_batch(bid)
            m = await metrics.batch_summary(bid)
            print(f"  {strategy:6s} 轮次上限 {max_turns:>2}  "
                  f"ASR={m['asr'] * 100:5.1f}%  "
                  f"成功 {m['success']}/{m['finished']}  "
                  f"均轮次 {m['avg_turns']:.1f}  "
                  f"成本 ¥{m['cost']:.4f}")
            runs.append((target_uid, strategy, max_turns, bid, m))

    # ---------------- 3. 护栏对比 ----------------
    title("3. 护栏有效性（T2 同构对照）")
    base_asr = None
    for profile in ("none", "input", "output", "prompt", "full"):
        bid = await executor.create_batch(
            target_uid="T2", experiment="E5", strategy="multi",
            max_turns=args.turns, guardrail_profile=profile, plain_only=True,
            limit=None if args.full else 6, name=f"e2e-guard-{profile}")
        await executor.run_batch(bid)
        m = await metrics.batch_summary(bid)
        if profile == "none":
            base_asr = m["asr"]
        red = ((base_asr - m["asr"]) / base_asr * 100) if base_asr else None
        red_s = f"{red:5.1f}%" if red is not None else "   —  "
        print(f"  {profile:7s}  ASR={m['asr'] * 100:5.1f}%  "
              f"削减率 {red_s}  拦截轮次 {m['blocked_turns']}")

    # ---------------- 4. 判定质量 ----------------
    title("4. 判定质量")
    e4 = await metrics.e4_judge_comparison(None, "T2")
    print(f"  判定样本 {e4['samples']}，有效 {e4['llm_valid']}，已人工标注 {e4['labeled']}")
    if e4.get("kappa_rule_llm") is not None:
        print(f"  Kappa（规则 vs LLM）: {e4['kappa_rule_llm']:.4f}  "
              f"原始一致率 {e4['raw_agreement'] * 100:.1f}%")
    if e4.get("conflict_rate") is not None:
        print(f"  两路冲突率: {e4['conflict_rate'] * 100:.1f}%  "
              f"待人工复核 {e4['review_queue']} 条")
    if e4.get("metrics"):
        for k, label in (("rule_only", "规则单路"), ("llm_only", "LLM单路"), ("fusion", "双路融合")):
            mm = e4["metrics"][k]
            print(f"  {label:8s} P={mm['precision']:.3f} R={mm['recall']:.3f} F1={mm['f1']:.3f}")
    else:
        print(f"  {e4.get('note', '')}")

    # ---------------- 5. 报告 ----------------
    title("5. 报告导出")
    last_bid = runs[-1][3]
    paths = await report.export(last_bid)
    print(f"  Markdown: {paths['markdown']}")
    print(f"  HTML    : {paths['html']}")

    title("完成")
    print(f"  总耗时 {time.perf_counter() - t_start:.1f}s")
    from app.core.gateway import gateway
    gs = gateway.stats.as_dict(settings.use_mock)
    print(f"  模型调用 {gs['calls']} 次（缓存命中 {gs['cache_hits']}），"
          f"token {gs['token_in']}/{gs['token_out']}，估算成本 ¥{gs['cost']:.4f}")
    await engine.dispose()
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="全量运行")
    ap.add_argument("--turns", type=int, default=5, help="多轮深度（默认 5）")
    a = ap.parse_args()
    raise SystemExit(asyncio.run(main(a)))
