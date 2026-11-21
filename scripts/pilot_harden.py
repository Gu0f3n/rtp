"""加固前后对照试跑。

用法::

    DB_NAME=rtp_real.db PYTHONPATH=. python scripts/pilot_harden.py 6

参数是载荷条数（不传则跑全部可用 plain 载荷）。

两组配置：
    加固前 = T2（guardrail_profile=none）
    加固后 = T5（guardrail_profile=full，输入过滤 + 提示加固 + 输出过滤）

为什么用两个 target_uid 而不是同一个靶标换 profile：T5 在数据库里就是
T2 的加固视图（同代码、同知识库、同模型），分开登记是为了让实验记录
能按靶标归档，也便于论文里直接表述"加固前系统 T2 / 加固后系统 T5"。
配对分析会按靶标实现归一，因此两组仍能正确配上。
"""
from __future__ import annotations

import asyncio
import sys
import time

from app.config import settings
from app.db import engine
from app.runner import executor
from app.runner.metrics import harden_compare


async def run(limit: int | None, target: str = "T2") -> None:
    print(f"mock={settings.use_mock}  target={target}  limit={limit or '全部'}")
    if settings.use_mock:
        print("!! 警告：当前为 mock 模式，结果不能用于论文")

    # T5 是 T2 的加固视图，用它表达"加固后系统"；其余靶标没有别名，
    # 直接在同一靶标上切 profile——两者的配对逻辑一致，因为
    # harden_compare 按靶标实现归一。
    after_uid = "T5" if target == "T2" else target

    t0 = time.time()
    for uid, prof in ((target, "none"), (after_uid, "full")):
        bid = await executor.create_batch(
            target_uid=uid, experiment="E5", strategy="multi",
            max_turns=5, guardrail_profile=prof, plain_only=True, limit=limit,
            name=f"harden-{uid}-{prof}")
        print(f"\n=== {uid}/{prof} 批次 {bid} 开始 ===")
        t1 = time.time()
        stats = await executor.run_batch(bid)
        print(f"{uid}/{prof}: 完成 {stats.done}/{stats.total} 失败 {stats.failed} "
              f"攻破 {stats.success} 耗时 {time.time() - t1:.0f}s "
              f"成本 ¥{stats.cost:.4f}")
        if stats.errors:
            print("  错误样本：", stats.errors[:3])

    print(f"\n总耗时 {time.time() - t0:.0f}s")
    await engine.dispose()


def show(d: dict) -> None:
    print("\n" + "=" * 68)
    if not d.get("comparable"):
        print("不可比：", d.get("reason"))
        return
    c, b, a, e = d["checks"], d["before"], d["after"], d["effect"]
    print(f"配对载荷 {c['paired_cases']} 条 | 载荷集合一致 {c['same_cases']} "
          f"| 真实调用 {c['both_live']}")
    print(f"\n{'':12s}{'加固前':>10s}{'加固后':>10s}")
    print(f"{'批次':12s}{b['batch_id']:>10s}{a['batch_id']:>10s}")
    print(f"{'攻破数':10s}{b['success']:>10d}{a['success']:>10d}")
    print(f"{'完成数':10s}{b['finished']:>10d}{a['finished']:>10d}")
    print(f"{'ASR':11s}{b['asr']:>10.3f}{a['asr']:>10.3f}")
    print(f"{'ASR 95%CI':10s}{str(b['asr_ci']):>10s}{str(a['asr_ci']):>10s}")
    print(f"{'被拦截轮次':8s}{b['blocked_turns']:>10d}{a['blocked_turns']:>10d}")
    print(f"{'平均轮次':9s}{b['avg_turns']:>10.2f}{a['avg_turns']:>10.2f}")
    print(f"{'成本':12s}{b['cost']:>10.4f}{a['cost']:>10.4f}")

    print("\n四格配对：", d["matrix"])
    m = d["mcnemar"]
    print(f"McNemar  b={m['b']} c={m['c']} p={m['p_value']} "
          f"{'显著' if m['significant'] else '不显著'}")
    print("   ", m["note"])

    print(f"\nASR 削减率 {e['reduction_rate']} | 实质泄露 "
          f"{e['substantive_leaks_before']} -> {e['substantive_leaks_after']}")

    if d["leaks"]:
        print(f"\n漏防 {len(d['leaks'])} 条：")
        for x in d["leaks"]:
            print(f"  {x['case_uid']:10s} {x['severity']:11s} "
                  f"{x['category'][:16]:18s} {x['hint']}")
    else:
        print("\n无漏防")


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else None
    tgt = sys.argv[2] if len(sys.argv) > 2 else "T2"
    asyncio.run(run(n, tgt))
    show(asyncio.run(harden_compare(tgt, "E5")))
