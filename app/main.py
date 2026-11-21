"""FastAPI 应用装配。"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import cases, knowledge, metrics, runs, targets
from app.config import BASE_DIR, settings
from app.core.gateway import gateway
from app.db import init_db

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("rtp")

WEB_DIR = Path(BASE_DIR) / "web"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    log.info("数据库就绪：%s", settings.db_url)
    if settings.use_mock:
        log.warning("当前处于 MOCK 模式（未配置 API Key）。"
                    "所有响应由本地模拟产生，数据不得写入论文。")
    else:
        log.info("模型网关：%s，目标档=%s，判定档=%s", settings.llm_base_url,
                 settings.tier("target").model, settings.tier("judge").model)
    yield
    await gateway.aclose()


app = FastAPI(
    title="大模型应用自动化红队测试平台",
    description="面向大模型应用的自动化红队测试：双通道生成 · 多轮编排 · 双路判定 · 护栏量化",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

app.include_router(targets.router)
app.include_router(cases.router)
app.include_router(runs.router)
app.include_router(metrics.router)
app.include_router(knowledge.router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "mock": settings.use_mock,
            "concurrency": settings.concurrency,
            "models": {"target": settings.tier("target").model,
                       "attack": settings.tier("attack").model,
                       "judge": settings.tier("judge").model}}


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    @app.get("/")
    async def index():
        return FileResponse(str(WEB_DIR / "index.html"))
