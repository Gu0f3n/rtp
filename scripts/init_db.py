"""初始化数据库：建表、登记靶标、导入种子用例。

用法::

    python scripts/init_db.py            # 建库 + 登记（幂等）
    python scripts/init_db.py --reset    # 清空后重建（会删除全部实验数据）
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import delete, select  # noqa: E402

from app.config import settings  # noqa: E402
from app.db import engine, init_db, session_scope  # noqa: E402
from app.models import (  # noqa: E402
    AttackCase, AttackRun, AttackSeed, AttackTurn, Batch, GuardrailTest,
    JudgeResult, MetricSnapshot, TargetApp)
from app.targets import prompts  # noqa: E402
from app.targets.seeds_data import BENIGN_SEEDS, SEEDS  # noqa: E402

TARGETS = [
    {
        "uid": "T1", "name": "对话式客服机器人", "form_type": "chat",
        "system_prompt": prompts.T1_SYSTEM, "kb_id": None, "tools": [],
        "guardrail_profile": "none",
        "expected_weakness": prompts.EXPECTED_WEAKNESS["T1"],
    },
    {
        "uid": "T2", "name": "企业知识库问答（RAG）", "form_type": "rag",
        "system_prompt": prompts.T2_SYSTEM, "kb_id": "yunqi", "tools": [],
        "guardrail_profile": "none",
        "expected_weakness": prompts.EXPECTED_WEAKNESS["T2"],
    },
    {
        "uid": "T3", "name": "智能办公 Agent（工具调用）", "form_type": "agent",
        "system_prompt": prompts.T3_SYSTEM, "kb_id": None,
        "tools": ["read_file", "list_dir", "send_email", "query_db"],
        "guardrail_profile": "none",
        "expected_weakness": prompts.EXPECTED_WEAKNESS["T3"],
    },
    {
        # T5 = T2 的加固配置视图，不是独立实现。登记它是为了让 E5 的实验
        # 记录能直接归档到 target_uid='T5'，代码路径与 T2 完全一致。
        "uid": "T5", "name": "知识库问答（T2 加固版·同构对照）", "form_type": "rag",
        "system_prompt": prompts.T2_HARDENED, "kb_id": "yunqi", "tools": [],
        "guardrail_profile": "full",
        "expected_weakness": "与 T2 同一实现，仅启用全部护栏；用于护栏有效性对照实验。",
    },
]


async def reset_all() -> None:
    async with session_scope() as s:
        for model in (JudgeResult, AttackTurn, AttackRun, AttackCase, AttackSeed,
                      GuardrailTest, MetricSnapshot, Batch, TargetApp):
            await s.execute(delete(model))


async def main(reset: bool = False) -> None:
    await init_db()
    print(f"数据库：{settings.db_url}")

    if reset:
        await reset_all()
        print("已清空全部数据")

    async with session_scope() as s:
        for t in TARGETS:
            exist = (await s.execute(
                select(TargetApp).where(TargetApp.uid == t["uid"]))).scalar_one_or_none()
            if exist:
                # 只更新元信息，不覆盖已有的护栏配置与版本号
                exist.name = t["name"]
                exist.form_type = t["form_type"]
                exist.kb_id = t["kb_id"]
                exist.tools = t["tools"]
                exist.expected_weakness = t["expected_weakness"]
                continue
            s.add(TargetApp(
                uid=t["uid"], name=t["name"], form_type=t["form_type"],
                system_prompt=t["system_prompt"], kb_id=t["kb_id"],
                tools=t["tools"],
                guardrail_profile=t["guardrail_profile"],
                guardrail_config={},
                config_version="v1",
                expected_weakness=t["expected_weakness"]))
        await s.flush()

        added = 0
        # 攻击种子 + 良性对照样本一起入库。良性样本用 BENIGN 类别标记，
        # 生成器会主动排除它们，只在过度防御统计中使用。
        for sd in list(SEEDS) + list(BENIGN_SEEDS):
            exist = (await s.execute(
                select(AttackSeed).where(AttackSeed.uid == sd.uid))).scalar_one_or_none()
            if exist:
                exist.category = sd.category
                exist.technique = sd.technique
                exist.text = sd.text
                exist.target_forms = sd.forms
                exist.expected_harm = sd.harm
                exist.weakness_tag = sd.weakness
                continue
            s.add(AttackSeed(
                uid=sd.uid, category=sd.category, technique=sd.technique,
                text=sd.text, target_forms=sd.forms,
                expected_harm=sd.harm, weakness_tag=sd.weakness))
            added += 1

    async with session_scope() as s:
        n_t = len((await s.execute(select(TargetApp))).scalars().all())
        n_s = len((await s.execute(select(AttackSeed))).scalars().all())
    print(f"靶标 {n_t} 个，种子用例 {n_s} 条（本次新增 {added} 条）")
    if settings.use_mock:
        print("\n[注意] 未配置 API Key，系统将以 MOCK 模式运行。")
        print("       在 .env 中填入 LLM_API_KEY 后即可切换为真实模型调用。")
    await engine.dispose()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true", help="清空全部数据后重建")
    args = ap.parse_args()
    asyncio.run(main(args.reset))
