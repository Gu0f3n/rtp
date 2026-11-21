"""快速验证：算子增强载荷能否攻破 T1（临时脚本，验证完即删）。"""
from __future__ import annotations

import asyncio

from app.db import engine
from app.runner import executor

CASES = [f"{s}-T-{o}" for s in ("S041", "S037", "S004")
         for o in ("task_wrap", "pretext", "role_nesting", "payload_nest")]


async def m() -> None:
    bid = await executor.create_batch(
        target_uid="T1", experiment="PROBE", strategy="multi", max_turns=5,
        guardrail_profile="none", case_uids=CASES, name="probe-op-T1-none")
    print("批次", bid, "载荷", len(CASES))
    st = await executor.run_batch(bid)
    print(f"完成 {st.done}/{st.total} 失败 {st.failed} 攻破 {st.success} "
          f"成本 ¥{st.cost:.4f}")
    if st.errors:
        print("错误", st.errors[:2])
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(m())
