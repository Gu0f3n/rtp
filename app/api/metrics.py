"""指标、报告与实验编排接口。"""
from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.gateway import gateway
from app.db import get_session
from app.runner import executor, metrics as metrics_mod, report

router = APIRouter(prefix="/api", tags=["metrics"])


@router.get("/metrics/overview")
async def overview():
    from app.config import settings
    return {**await metrics_mod.overview(),
            "gateway": gateway.stats.as_dict(settings.use_mock),
            "mock": settings.use_mock}


@router.get("/metrics/batch/{uid}")
async def batch_metrics(uid: str, persist: bool = False):
    data = await metrics_mod.batch_summary(uid)
    if persist:
        await metrics_mod.save_snapshot(uid, f"batch_{uid}", data)
    return data


@router.get("/metrics/e2")
async def e2(target: str = "T1", experiment: str = "E2"):
    return await metrics_mod.e2_curve(target, experiment)


@router.get("/metrics/e4")
async def e4(batch: str | None = None, target: str = "T1"):
    return await metrics_mod.e4_judge_comparison(batch, target)


@router.get("/metrics/e5")
async def e5(target: str = "T2", experiment: str = "E5", persist: bool = False):
    if persist:
        return await metrics_mod.persist_guardrail(target, experiment)
    return await metrics_mod.e5_guardrail(target, experiment)


@router.get("/metrics/harden")
async def harden(target: str = "T2", experiment: str = "E5"):
    """加固前后配对对照：同一靶标在 profile=none 与 full 下的逐条比较。

    与 /metrics/e5 的区别：e5 给出五档配置的总体 ASR 与逐层边际贡献，
    本接口只取两端（未加固 / 全加固），但按 case 逐条配对，并给出
    McNemar 检验与 Wilson 区间——用于论证"下降是否显著"，
    而不只是"数字变小了"。
    """
    return await metrics_mod.harden_compare(target, experiment)


@router.get("/metrics/e6")
async def e6(target: str = "T2", experiment: str = "E6"):
    """单轮 / 多轮 / 级联三种攻击组织方式的对比。"""
    return await metrics_mod.e6_chain_compare(target, experiment)


@router.get("/report/{uid}")
async def report_json(uid: str):
    try:
        return await report.payload(uid)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"报告生成失败：{e}") from e


@router.post("/report/{uid}/export")
async def report_export(uid: str):
    try:
        return await report.export(uid)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"报告导出失败：{e}") from e


@router.get("/report/{uid}/file")
async def report_file(uid: str, fmt: str = "html"):
    """直接返回报告文件，便于浏览器打开或打印为 PDF。"""
    from pathlib import Path

    from fastapi.responses import FileResponse

    from app.config import REPORT_DIR
    p = Path(REPORT_DIR) / f"{uid}.{'md' if fmt == 'md' else 'html'}"
    if not p.exists():
        await report.export(uid)
    if not p.exists():
        raise HTTPException(404, "报告文件不存在")
    return FileResponse(str(p), media_type="text/markdown; charset=utf-8"
                        if fmt == "md" else "text/html; charset=utf-8")


@router.get("/gateway/stat")
async def gateway_stat():
    from app.config import settings
    return gateway.stats.as_dict(settings.use_mock)


@router.post("/gateway/reset")
async def gateway_reset():
    gateway.reset_stats()
    return {"ok": True}


# --------------------------------------------------------------------------- #
# 实验编排（E1–E5）
# --------------------------------------------------------------------------- #
async def _run_experiment(exp: str, target: str, limit: int | None) -> None:
    try:
        await executor.run_experiment(exp, target, limit)
    except Exception:  # noqa: BLE001
        pass


@router.post("/experiments/{name}")
async def run_experiment(name: str, bg: BackgroundTasks, target: str = "T1",
                         limit: int | None = None):
    """一键跑整组实验（后台执行）。

    E1 基线 / E2 轮次对比 / E3 生成消融 / E5 护栏对比 / E6 组织方式对比
    会各自建多个批次。E4 复用已有批次的判定结果，不新建任务。
    """
    exp = name.upper()
    if exp not in executor.EXPERIMENT_PLANS:
        raise HTTPException(400, f"未知实验：{name}（可选 E1/E2/E3/E5/E6）")
    if exp == "E4":
        return await metrics_mod.e4_judge_comparison(None, target)
    bg.add_task(_run_experiment, exp, target, limit)
    return {"experiment": exp, "target": target,
            "batches": len(executor.EXPERIMENT_PLANS[exp]), "status": "started"}
