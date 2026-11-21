"""给 attack_turn 增补 slots 列（级联链的级间情报）。

SQLite 的 ADD COLUMN 无法在一条语句里同时声明"JSON 类型 + 非空 + 默认值"，
因此这里用 ``TEXT DEFAULT '{}'`` 落列——SQLAlchemy 的 JSON 类型读出来时
仍会正常反序列化成 dict，写回时照常序列化。对新库则由 create_all 直接建表。

幂等：列已存在就跳过，可以反复执行。
"""
from __future__ import annotations

import asyncio
import sys

from sqlalchemy import text

from app.db import engine


async def main() -> None:
    async with engine.begin() as conn:
        dialect = conn.dialect.name
        if dialect == "sqlite":
            cols = [r[1] for r in (await conn.execute(
                text("PRAGMA table_info(attack_turn)"))).all()]
            if "slots" in cols:
                print("attack_turn.slots 已存在，跳过")
            else:
                await conn.execute(text(
                    "ALTER TABLE attack_turn ADD COLUMN slots TEXT DEFAULT '{}'"))
                print("已添加 attack_turn.slots")
            # 历史行补空值：默认值只对新增行生效，旧行可能是 NULL
            res = await conn.execute(text(
                "UPDATE attack_turn SET slots = '{}' "
                "WHERE slots IS NULL OR slots = ''"))
            print(f"历史行补空：{res.rowcount}")
        else:
            cols = [r[0] for r in (await conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'attack_turn'"))).all()]
            if "slots" in cols:
                print("attack_turn.slots 已存在，跳过")
            else:
                await conn.execute(text(
                    "ALTER TABLE attack_turn ADD COLUMN slots JSONB DEFAULT '{}'::jsonb"))
                print("已添加 attack_turn.slots")
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
    sys.exit(0)
