"""靶标接口：登记信息、护栏配置、在线对话试打、知识库查看。"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.engines import guardrail, operators
from app.models import TargetApp
from app.schemas import ChatRequest, ChatResponse, TargetOut, TargetUpdate
from app.targets import prompts
from app.targets.builtin import build_target
from app.targets.retriever import get_retriever

router = APIRouter(prefix="/api/targets", tags=["targets"])


@router.get("", response_model=list[TargetOut])
async def list_targets(s: AsyncSession = Depends(get_session)):
    rows = (await s.execute(select(TargetApp).order_by(TargetApp.uid))).scalars()
    return list(rows)


@router.get("/profiles")
async def list_profiles():
    """护栏档位与算子清单（前端下拉用）。"""
    return {
        "guardrails": [
            {"key": k, "label": guardrail.PROFILE_LABELS[k], "config": v}
            for k, v in guardrail.PROFILES.items()
        ],
        "operators": operators.OPERATOR_LIST,
        "states": [
            {"key": "probe", "label": "探测边界"},
            {"key": "consensus", "label": "建立共识"},
            {"key": "escalate", "label": "逐级升温"},
            {"key": "attack", "label": "实施攻击"},
            {"key": "confirm", "label": "结果确认"},
        ],
    }


@router.get("/{uid}", response_model=TargetOut)
async def get_target(uid: str, s: AsyncSession = Depends(get_session)):
    t = (await s.execute(select(TargetApp).where(TargetApp.uid == uid))).scalar_one_or_none()
    if not t:
        raise HTTPException(404, f"靶标不存在：{uid}")
    return t


@router.patch("/{uid}", response_model=TargetOut)
async def update_target(uid: str, body: TargetUpdate, s: AsyncSession = Depends(get_session)):
    t = (await s.execute(select(TargetApp).where(TargetApp.uid == uid))).scalar_one_or_none()
    if not t:
        raise HTTPException(404, f"靶标不存在：{uid}")
    if body.guardrail_profile:
        t.guardrail_profile = body.guardrail_profile
        t.guardrail_config = guardrail.resolve_profile(body.guardrail_profile)
    if body.guardrail_config is not None:
        t.guardrail_config = body.guardrail_config
    if body.system_prompt is not None:
        t.system_prompt = body.system_prompt
    # 配置变更即产生新版本号，历史实验记录绑定旧版本，避免配置漂移污染对比
    t.config_version = f"v{int(t.config_version.lstrip('v') or 1) + 1}"
    await s.commit()
    await s.refresh(t)
    return t


@router.get("/{uid}/prompt")
async def get_prompt(uid: str, hardened: bool = False):
    if uid not in ("T1", "T2", "T3"):
        raise HTTPException(404, "未知靶标")
    text = prompts.get_prompt(uid, hardened=hardened)
    return {"uid": uid, "hardened": hardened,
            "prompt": text, "system_prompt": text,
            "expected_weakness": prompts.EXPECTED_WEAKNESS.get(uid, "")}


@router.get("/{uid}/kb")
async def get_kb(uid: str, q: str = "", top_k: int = 10):
    """查看知识库文档与检索结果（用于演示间接提示注入）。"""
    if uid not in ("T2", "T5"):
        raise HTTPException(400, "仅 RAG 类靶标有知识库")
    r = get_retriever()
    docs = [{"doc_id": d.doc_id, "title": d.title, "sensitive": d.sensitive,
             "poisoned": d.poisoned, "preview": d.text[:200]} for d in r.docs]
    hits = []
    if q:
        hits = [{"doc_id": h.doc_id, "title": h.title, "score": round(h.score, 3),
                 "sensitive": h.sensitive, "poisoned": h.poisoned,
                 "text": h.text[:1200]} for h in r.search(q, top_k=top_k)]
    return {"docs": docs, "hits": hits}


@router.post("/{uid}/chat", response_model=ChatResponse)
async def chat(uid: str, body: ChatRequest, s: AsyncSession = Depends(get_session)):
    """直接与靶标对话，用于演示与手工验证。"""
    t = (await s.execute(select(TargetApp).where(TargetApp.uid == uid))).scalar_one_or_none()
    profile = t.guardrail_profile if t else "none"
    target = build_target(uid, profile=profile, system_prompt=t.system_prompt if t else None)
    return await target.chat(body.message, body.history)
