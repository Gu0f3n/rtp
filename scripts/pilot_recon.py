"""侦察类攻击专项试跑。

用途：验证 RECON 类种子在真实模型上的表现，以及危害分级是否正确落位。
这类样本的 success 期望是 False（侦察不算攻破），但 severity 期望是 recon
——两者同时成立才说明分级机制工作正常。

用法：
    python scripts/pilot_recon.py [target_uid] [profile] [limit]
    默认：T3、none、全部侦察样本
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select  # noqa: E402

from app.db import engine, session_scope  # noqa: E402
from app.models import AttackCase, AttackSeed, Batch, TargetApp  # noqa: E402
from app.runner import executor  # noqa: E402
from app.runner.metrics import batch_summary  # noqa: E402
from app.targets.seeds_data import SEEDS  # noqa: E402

RECON_CATEGORY = "RECON 攻击面侦察"


async def main(target_uid: str = "T3", profile: str = "none",
               limit: int | None = None) -> None:
    recon_uids = [s.uid for s in SEEDS if s.category == RECON_CATEGORY]
    async with session_scope() as s:
        seed_ids = list((await s.execute(
            select(AttackSeed.id).where(AttackSeed.uid.in_(recon_uids)))).scalars())
        cases = list((await s.execute(
            select(AttackCase).where(AttackCase.seed_id.in_(seed_ids),
                                     AttackCase.channel == "template")
            .order_by(AttackCase.id))).scalars())
        cases = [c for c in cases if not c.operator_chain]
        if limit:
            cases = cases[:limit]
        target = (await s.execute(
            select(TargetApp).where(TargetApp.uid == target_uid))).scalar_one_or_none()
        if target is None:
            print(f"靶标未登记：{target_uid}")
            return
        if not cases:
            print("没有侦察类载荷，请先运行：\n"
                  "  POST /api/cases/generate "
                  '{"target_uid":"T3","channels":["template"],"seed_uids":[...]}')
            return

        # 直接建批次，绕过 create_batch 的全量取数，只跑侦察样本
        import time as _t
        uid = f"BRECON{int(_t.time() * 1000)}"
        s.add(Batch(uid=uid, name=f"RECON-{target_uid}-{profile}",
                    target_uid=target_uid, experiment="RECON",
                    strategy="single", max_turns=1, guardrail_profile=profile,
                    case_filter={"recon_only": True}, total=len(cases),
                    status="pending"))
        await s.flush()
        for c in cases:
            from app.models import AttackRun
            s.add(AttackRun(uid=f"{uid}-{c.uid}", batch_id=uid,
                            target_id=target.id, case_id=c.id,
                            strategy="single", max_turns=1,
                            guardrail_profile=profile, status="pending"))
        await s.flush()

    print(f"批次 {uid} 共 {len(cases)} 条，开始执行…")
    stats = await executor.run_batch(uid)
    print(f"完成：{stats.done} 条，失败 {stats.failed} 条，耗时 {stats.elapsed_s:.1f}s，"
          f"成本 ¥{stats.cost:.4f}")

    p = await batch_summary(uid)
    print("\n--- 结果 ---")
    print(f"ASR         : {p['asr']:.3f}（侦察样本期望 0）")
    print(f"severity 分布: {p['severity_dist']}")
    print(f"侦察率      : {p['recon_rate']:.3f}（期望接近 1）")
    await engine.dispose()


if __name__ == "__main__":
    args = sys.argv[1:]
    asyncio.run(main(args[0] if args else "T3",
                     args[1] if len(args) > 1 else "none",
                     int(args[2]) if len(args) > 2 else None))
