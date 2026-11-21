"""AI 安全标准对齐接口。

三个端点分别回答三个不同的问题，不要混用：

- ``/standards``  —— 标准本身长什么样（静态知识，供前端渲染知识图谱）
- ``/coverage``   —— 我的测试**覆盖了哪些风险、打出了什么结果**（实时计算）
- ``/compliance`` —— 按国标阈值**够不够格**（把 ASR 换算成合规判定）

``/coverage`` 必须实时算而不是写死：覆盖率和 ASR 随实验推进而变化，
写死的数字在答辩现场被追问一句"这是什么时候的数据"就露馅了。
"""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.config import DATA_DIR
from app.db import session_scope
from app.knowledge import standards as std
from app.models import AttackCase, AttackRun, AttackSeed, Batch

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])

# 靶标编号 → 形态，与生成器里的映射保持一致
FORM_OF = {"T1": "chat", "T2": "rag", "T3": "agent", "T5": "rag"}

# 良性对照实测结果的落盘位置（由 scripts/benign_probe.py 生成）
BENIGN_RESULT = DATA_DIR / "benign_result.json"


def _local(ts: datetime | None) -> str:
    """UTC → 本地时区展示。报告里出现过 8 小时偏差，这里统一处理。"""
    if ts is None:
        return ""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone().strftime("%Y-%m-%d %H:%M")


# --------------------------------------------------------------------------- #
# 一、标准知识
# --------------------------------------------------------------------------- #
@router.get("/standards")
async def standards() -> dict[str, Any]:
    """三套标准的完整结构化数据 + 靶标风险画像 + 算子分层说明。"""
    return {
        "owasp": [asdict(r) for r in std.OWASP_LLM_2025],
        "atlas": [asdict(t) for t in std.ATLAS_TECHNIQUES],
        "mitigations": std.ATLAS_MITIGATIONS,
        "gb": [asdict(g) for g in std.GB_THRESHOLDS],
        "gb_standard": std.GB_STANDARD,
        "targets": std.TARGET_RISK_PROFILE,
        "operator_layers": std.OPERATOR_LAYER_NOTE,
        "meta": {
            "owasp_total": len(std.OWASP_LLM_2025),
            "owasp_in_scope": sum(1 for r in std.OWASP_LLM_2025 if r.in_scope),
            "atlas_total": len(std.ATLAS_TECHNIQUES),
            "gb_measurable": sum(1 for g in std.GB_THRESHOLDS if g.measurable),
        },
    }


# --------------------------------------------------------------------------- #
# 二、覆盖矩阵（实时）
# --------------------------------------------------------------------------- #
@router.get("/coverage")
async def coverage(target: str | None = Query(None, description="按靶标过滤，留空为全库")) -> dict[str, Any]:
    """每个 OWASP 条目在本实验中的覆盖与实测结果。

    覆盖度用三个层次表达，缺一不可：

    1. ``seeds``  —— 题库里有没有针对它的样本（**有没有测**）
    2. ``runs``   —— 有没有真跑过（**测没测到**）
    3. ``asr``    —— 跑出来的失败率（**测出来多严重**）

    只有第一层有数字就说"已覆盖"，是纸面覆盖。评审最常戳的就是这个。
    """
    form = FORM_OF.get((target or "").upper())

    async with session_scope() as s:
        # 种子维度：按形态过滤。注意良性样本单列，不进攻击覆盖统计。
        stmt = select(AttackSeed.category, func.count()).group_by(AttackSeed.category)
        seed_rows = (await s.execute(stmt)).all()

        # run 维度：join 到 batch 才能按靶标过滤
        run_stmt = (
            select(AttackSeed.category, AttackSeed.technique,
                   AttackRun.status, AttackRun.success)
            .join(AttackCase, AttackCase.seed_id == AttackSeed.id)
            .join(AttackRun, AttackRun.case_id == AttackCase.id)
            .join(Batch, Batch.uid == AttackRun.batch_id)
        )
        if target:
            run_stmt = run_stmt.where(Batch.target_uid == target.upper())
        run_rows = (await s.execute(run_stmt)).all()

        # 种子明细里取"适用形态"与"技术"，用于按靶标折算可用题量
        seed_detail = (await s.execute(
            select(AttackSeed.uid, AttackSeed.category, AttackSeed.target_forms,
                   AttackSeed.weakness_tag, AttackSeed.technique))).all()

    # 按形态折算每个类别实际可用的种子数
    seed_by_cat: dict[str, int] = {}
    seed_by_tech: dict[str, int] = {}
    for uid, cat, forms, _wk, tech in seed_detail:
        if form and forms and form not in forms:
            continue
        seed_by_cat[cat] = seed_by_cat.get(cat, 0) + 1
        seed_by_tech[tech] = seed_by_tech.get(tech, 0) + 1
    if not form:
        seed_by_cat = {c: n for c, n in seed_rows}

    # 弱点标签覆盖：预期薄弱点是否都有对应用例
    weaknesses = sorted({wk for _u, cat, _f, wk, _t in seed_detail
                         if wk and wk != "benign" and (not form or not _f or form in _f)})

    run_by_cat: dict[str, dict[str, int]] = {}
    run_by_tech: dict[str, dict[str, int]] = {}

    def _acc(bucket: dict[str, dict[str, int]], key: str, status: str, success: bool) -> None:
        d = bucket.setdefault(key, {"total": 0, "finished": 0, "success": 0, "error": 0})
        d["total"] += 1
        if status == "completed":
            d["finished"] += 1
            if success:
                d["success"] += 1
        elif status == "error":
            d["error"] += 1

    for cat, tech, status, success in run_rows:
        _acc(run_by_cat, cat, status, success)
        _acc(run_by_tech, tech, status, success)

    items: list[dict[str, Any]] = []
    for risk in std.OWASP_LLM_2025:
        cat_hits = [c for c in seed_by_cat if std.category_to_owasp(c) == risk.rid]
        seeds_n = sum(seed_by_cat[c] for c in cat_hits)
        agg = {"total": 0, "finished": 0, "success": 0, "error": 0}
        for c in cat_hits:
            for k, v in run_by_cat.get(c, {}).items():
                agg[k] += v

        # 由特定 technique 支撑的条目（如 LLM08 由 RAG 投毒用例支撑）
        extra = std.RISK_TECHNIQUE_SUPPORT.get(risk.rid, [])
        tech_seeds = sum(seed_by_tech.get(t, 0) for t in extra)
        if tech_seeds:
            seeds_n += tech_seeds
            for t in extra:
                for k, v in run_by_tech.get(t, {}).items():
                    agg[k] += v

        items.append({
            "rid": risk.rid,
            "name": risk.name,
            "name_en": risk.name_en,
            "in_scope": risk.in_scope,
            "seeds": seeds_n,
            "runs": agg["total"],
            "finished": agg["finished"],
            "success": agg["success"],
            "errors": agg["error"],
            "asr": round(agg["success"] / agg["finished"], 4) if agg["finished"] else None,
            # 纸面覆盖 vs 实测覆盖：有题目但没跑过的，单独标出来
            "paper_only": seeds_n > 0 and agg["finished"] == 0,
            "categories": cat_hits,
            "techniques": extra,
            "atlas": risk.atlas,
        })

    covered = sum(1 for i in items if i["seeds"] > 0)
    measured = sum(1 for i in items if (i["finished"] or 0) > 0)
    return {
        "target": target or "ALL",
        "items": items,
        "weaknesses": weaknesses,
        "summary": {
            "risks_total": len(items),
            "risks_with_seeds": covered,
            "risks_measured": measured,
            "seeds_total": sum(seed_by_cat.values()),
            "runs_total": sum(v["total"] for v in run_by_cat.values()),
        },
    }


# --------------------------------------------------------------------------- #
# 三、国标合规对照
# --------------------------------------------------------------------------- #
def _benign_result() -> dict[str, Any] | None:
    if not BENIGN_RESULT.exists():
        return None
    try:
        return json.loads(BENIGN_RESULT.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


@router.get("/compliance")
async def compliance(target: str | None = None) -> dict[str, Any]:
    """把实测指标换算成 GB/T 45654-2025 的达标判定。

    刻意不做"总体达标/不达标"的一言堂结论。国标是分层要求的，
    一个本科规模的平台不可能满足全部条款，逐条给出"达标 / 未达标 / 无数据"
    并说明依据，比给一个笼统的合格章更有说服力。
    """
    form = FORM_OF.get((target or "").upper())
    tgt = (target or "").upper()

    async with session_scope() as s:
        run_stmt = (
            select(AttackRun.status, AttackRun.success)
            .join(AttackCase, AttackCase.id == AttackRun.case_id)
            .join(AttackSeed, AttackSeed.id == AttackCase.seed_id)
            .join(Batch, Batch.uid == AttackRun.batch_id)
            .where(AttackSeed.category != "BENIGN 良性对照")
        )
        if tgt:
            run_stmt = run_stmt.where(Batch.target_uid == tgt)
        rows = (await s.execute(run_stmt)).all()

    finished = [r for r in rows if r.status == "completed"]
    success = sum(1 for r in finished if r.success)
    asr = (success / len(finished)) if finished else None

    benign = _benign_result()
    # mock 模式跑出来的过度防御率不得进入合规判定：
    # 那是模拟器自己的行为，与被测模型的真实表现无关。
    benign_usable = bool(benign) and benign.get("mode") != "mock"
    over_rate: float | None = None
    benign_n = 0
    if benign_usable:
        # 若指定了靶标，取该靶标的实测；否则取全部合计
        if tgt and tgt in (benign.get("targets") or {}):
            d = benign["targets"][tgt]
            benign_n = d.get("total", 0)
            over_rate = d.get("rate")
        elif benign.get("overall"):
            benign_n = benign["overall"].get("total", 0)
            over_rate = benign["overall"].get("rate")

    def judge(key: str, actual: float | None, op: str, thr: float) -> bool | None:
        if actual is None:
            return None
        return actual >= thr if op == ">=" else actual <= thr

    items: list[dict[str, Any]] = []
    for g in std.GB_THRESHOLDS:
        if g.key in ("defense_rate", "safe_content_rate"):
            # 两条同源于 ASR，只是表述方向不同：一条说"挡住了多少"，
            # 一条说"合格内容占多少"。国标把它们分列，是给不同责任方看的。
            actual = (1 - asr) if asr is not None else None
            n = len(finished)
        elif g.key == "over_refusal_rate":
            actual, n = over_rate, benign_n
        else:
            actual, n = None, 0

        items.append({
            "key": g.key,
            "name": g.name,
            "op": g.op,
            "threshold": g.value,
            "clause": g.clause,
            "measurable": g.measurable,
            "mapping": g.mapping,
            "actual": None if actual is None else round(actual, 4),
            "samples": n,
            # 不可实测的项一律返回 None，不返回 False——
            # "没测"和"没达标"是两件性质完全不同的事
            "pass": judge(g.key, actual, g.op, g.value) if g.measurable else None,
        })

    passed = sum(1 for i in items if i["pass"] is True)
    return {
        "standard": f"{std.GB_STANDARD['code']} {std.GB_STANDARD['name']}",
        "published": std.GB_STANDARD["published"],
        "effective": std.GB_STANDARD["effective"],
        "target": tgt or "ALL",
        "form": form,
        "items": items,
        "summary": {
            "measured": sum(1 for i in items if i["pass"] is not None),
            "passed": passed,
            "failed": sum(1 for i in items if i["pass"] is False),
            "no_data": sum(1 for i in items if i["pass"] is None),
        },
        "benign_probe": {
            "available": benign_usable,
            "mode": (benign or {}).get("mode", ""),
            "generated_at": (benign or {}).get("generated_at", ""),
            "note": ("过度防御率需运行 scripts/benign_probe.py 实测后才有数据"
                     if not benign
                     else "已有 mock 模式的探测结果，不能用于合规判定，请以真实模型重跑"
                     if not benign_usable else "已取用真实探测结果"),
        },
        "disclaimer": (
            "本表仅对照国标中可由黑盒对抗测试直接判定的量化条款。"
            "训练数据安全、数据标注、模型备案等条款需开发侧与合规侧材料，"
            "不在自动化红队测试的能力范围内。"
        ),
    }
