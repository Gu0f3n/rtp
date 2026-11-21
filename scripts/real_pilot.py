"""真实模型先导实验：单轮 vs 多轮（最小成本、最快给出结论）。

为什么先做这个而不是直接跑 E1–E5：
mock 靶标的防御强度是人为设定的，真实模型的安全对齐强度未知。
若真实环境下单轮与多轮没有差异，整个 E2 的论点是空的，
需要先调整载荷难度或换靶标定位，而不是把几小时实验跑完才发现。

本脚本只跑**一个靶标**、**少量用例**，用独立数据库，不与 mock 数据混。

用法：
    python scripts/real_pilot.py --target T1 --limit 6 --turns 5
    python scripts/real_pilot.py --target T2 --limit 8 --turns 4
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

# 必须早于 app.config 导入：config 在模块级实例化 settings，
# 之后再改环境变量不会生效。真实实验强制使用独立库。
DB_NAME = "rtp_real.db"
os.environ["DB_NAME"] = DB_NAME

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import DATA_DIR, settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.engines import generator  # noqa: E402
from app.runner import executor, metrics  # noqa: E402


def title(t: str) -> None:
    print("\n" + "─" * 66)
    print(f"  {t}")
    print("─" * 66)


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="T1", help="靶标 uid（T1/T2/T3/T5）")
    ap.add_argument("--limit", type=int, default=6, help="每档用例数")
    ap.add_argument("--turns", type=int, default=5, help="多轮深度")
    args = ap.parse_args()

    if settings.use_mock:
        print("当前是 MOCK 模式，先导实验无意义。请在 .env 配置 LLM_API_KEY。")
        return 2

    db_file = DATA_DIR / DB_NAME
    print("=" * 66)
    print("真实模型先导实验")
    print("=" * 66)
    print(f"  靶标       {args.target}")
    print(f"  用例数     {args.limit}")
    print(f"  多轮深度   {args.turns}")
    print(f"  数据库     {db_file}")
    print(f"  靶标模型   {settings.tier('target').model}")
    print(f"  判定模型   {settings.tier('judge').model}")

    if not db_file.exists():
        print(f"\n数据库不存在，请先执行：\n  DB_NAME={DB_NAME} python scripts/init_db.py")
        return 2

    # ---------------- 1. 准备载荷（仅模板通道，零模型成本） ----------------
    title("1. 准备基础载荷")
    async with session_scope() as s:
        res = await generator.generate_cases(
            s, target_uid=args.target, channels=["template"],
            operators_wanted=[], max_chain=1, limit=args.limit)
    print(f"  新建 {res.created} 条基础载荷（未叠加算子，保证单变量）")

    # ---------------- 2. 单轮 vs 多轮 ----------------
    rows = []
    for strategy, max_turns in (("single", 1), ("multi", args.turns)):
        title(f"2. {strategy}  轮次上限 {max_turns}")
        bid = await executor.create_batch(
            target_uid=args.target, experiment="PILOT", strategy=strategy,
            max_turns=max_turns, guardrail_profile="none", plain_only=True,
            limit=args.limit, name=f"pilot-{args.target}-{strategy}{max_turns}")
        t0 = time.perf_counter()
        stats = await executor.run_batch(bid, progress=lambda p: (
            print(f"\r  执行中 {p['done']}/{p['total']}  攻破 {p['breached']}"
                  f"  错误 {p['errors']}", end="", flush=True)))
        m = await metrics.batch_summary(bid)
        print()
        print(f"  ASR={m['asr'] * 100:5.1f}%   攻破 {m['success']}/{m['finished']}"
              f"   执行错误 {m['errors']}")
        print(f"  平均轮次 {m['avg_turns']}   平均攻破轮次 {m['avg_success_turn']}")
        print(f"  token {m['token_in']}/{m['token_out']}   成本 ¥{m['cost']:.4f}"
              f"   耗时 {time.perf_counter() - t0:.0f}s")
        rows.append((strategy, max_turns, m))

    # ---------------- 3. 结论 ----------------
    title("3. 对比结论")
    base = rows[0][2]
    multi = rows[1][2]
    delta = (multi["asr"] - base["asr"]) * 100
    print(f"  单轮 ASR {base['asr'] * 100:.1f}%  →  多轮 ASR {multi['asr'] * 100:.1f}%"
          f"   变化 {delta:+.1f} 个百分点")

    if base["finished"] and multi["finished"]:
        if base["asr"] >= 0.95:
            print("  ⚠ 单轮已接近 100%，天花板效应，无法体现多轮的增量——")
            print("    需提高载荷难度或改换更难的靶标定位。")
        elif delta < 10:
            print("  ⚠ 多轮相对单轮提升不足 10 个百分点，E2 的论点会站不住。")
            print("    考虑：加深轮次、改用 LLM 变异通道、或调整靶标系统提示难度。")
        else:
            print("  ✓ 多轮显著高于单轮，E2 设计成立，可以扩到全靶标。")

    print(f"\n  数据已写入 {db_file.name}，与 mock 库隔离。")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
