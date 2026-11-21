"""把级联链落库跑一个批次，验证 executor → 数据库 → 指标 的完整链路。

与 pilot_chain.py 的区别：那个只调引擎、不落库；这个走真正的批次执行路径，
因此能验证 slots 是否写进 attack_turn、指标能否聚合、前端能否展示。

跑法：
    PYTHONPATH=. python scripts/pilot_chain_batch.py T2 6
"""
from __future__ import annotations

import asyncio
import json
import sys

from app.db import engine
from app.runner import executor, metrics


async def main(target: str = "T2", limit: int = 6, stages: int = 4) -> None:
    bid = await executor.create_batch(
        target_uid=target, experiment="PILOT", strategy="chain",
        max_turns=stages, guardrail_profile="none", limit=limit,
        plain_only=True, name=f"级联试跑-{target}-{limit}条")
    print(f"批次 {bid}（{limit} 条 × 最多 {stages} 级）")

    stats = await executor.run_batch(bid)
    print(f"完成 {stats.done}/{stats.total}，成功 {stats.success}，"
          f"异常 {stats.failed}，耗时 {stats.elapsed_s}s，¥{stats.cost:.4f}")
    if stats.errors:
        for e in stats.errors[:3]:
            print("  !", e)

    m = await metrics.batch_summary(bid)
    for k in ("total", "finished", "success", "asr", "avg_turns",
              "severity_dist", "recon_rate", "chain"):
        v = m[k]
        print(f"  {k:14s} {json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v}")
    print(f"\n批次号：{bid}（浏览器打开 /?batch={bid} 可看明细）")
    await engine.dispose()


if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else "T2"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    asyncio.run(main(t, n))
