"""种子用例与攻击载荷：查询、生成。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.engines import generator
from app.models import AttackCase, AttackSeed
from app.schemas import CaseOut, GenerateRequest, GenerateResult, SeedOut

router = APIRouter(prefix="/api", tags=["cases"])


@router.get("/seeds", response_model=list[SeedOut])
async def list_seeds(category: str | None = None, s: AsyncSession = Depends(get_session)):
    stmt = select(AttackSeed).where(AttackSeed.is_active.is_(True)).order_by(AttackSeed.uid)
    if category:
        stmt = stmt.where(AttackSeed.category == category)
    return list((await s.execute(stmt)).scalars())


@router.get("/seeds/stats")
async def seed_stats(s: AsyncSession = Depends(get_session)):
    rows = (await s.execute(
        select(AttackSeed.category, AttackSeed.technique, func.count())
        .where(AttackSeed.is_active.is_(True))
        .group_by(AttackSeed.category, AttackSeed.technique))).all()
    cats: dict[str, int] = {}
    techs: dict[str, int] = {}
    for cat, tech, n in rows:
        cats[cat] = cats.get(cat, 0) + n
        techs[tech] = techs.get(tech, 0) + n
    return {"by_category": cats, "by_technique": techs,
            "total": sum(cats.values())}


@router.get("/cases")
async def list_cases(channel: str | None = None, limit: int = 50, offset: int = 0,
                     s: AsyncSession = Depends(get_session)):
    stmt = select(AttackCase).order_by(AttackCase.id)
    if channel:
        stmt = stmt.where(AttackCase.channel == channel)
    total = (await s.execute(
        select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = list((await s.execute(stmt.limit(limit).offset(offset))).scalars())
    return {"total": total, "items": [CaseOut.model_validate(r).model_dump() for r in rows]}


@router.get("/cases/{case_id}")
async def get_case(case_id: int, s: AsyncSession = Depends(get_session)):
    c = (await s.execute(select(AttackCase).where(AttackCase.id == case_id))).scalar_one_or_none()
    if not c:
        raise HTTPException(404, "用例不存在")
    return CaseOut.model_validate(c).model_dump()


@router.post("/cases/generate", response_model=GenerateResult)
async def generate(body: GenerateRequest, s: AsyncSession = Depends(get_session)):
    """生成攻击载荷。

    ``channels`` 控制走哪条通道，``operators`` 控制是否叠加算子链。
    E3 消融实验就是靠这两个参数组合出"仅模板 / 仅变异 / 双通道"三组对照。
    """
    if not body.channels:
        raise HTTPException(400, "至少选择一个生成通道")
    res = await generator.generate_cases(
        s, target_uid=body.target_uid, channels=body.channels,
        operators_wanted=body.operators, max_chain=body.max_chain,
        limit=body.limit, seed_uids=body.seed_uids)
    await s.commit()
    return res


@router.delete("/cases")
async def clear_cases(channel: str | None = None, s: AsyncSession = Depends(get_session)):
    stmt = select(AttackCase)
    if channel:
        stmt = stmt.where(AttackCase.channel == channel)
    rows = list((await s.execute(stmt)).scalars())
    for r in rows:
        await s.delete(r)
    await s.commit()
    return {"deleted": len(rows)}
