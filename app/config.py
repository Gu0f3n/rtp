"""全局配置。

所有可调参数集中在此，通过环境变量或 .env 覆盖。设计上遵循两条原则：

1. 三级模型分离——目标模型（靶标）、攻击模型（生成/编排）、判定模型（评审）
   各自独立配置，可以指向不同供应商、不同档位的模型，这是成本控制的核心。
2. 无密钥可运行——未配置 API Key 时自动降级为本地 mock，保证系统在任何
   环境下都能完整跑通，便于开发调试与离线演示。
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
CACHE_DIR = DATA_DIR / "llm_cache"
REPORT_DIR = DATA_DIR / "reports"
KB_DIR = BASE_DIR / "app" / "targets" / "kb"


class ModelTier(BaseSettings):
    """单个模型档位的配置。

    base_url / api_key 留空则继承全局配置，因此可以把某一档单独指向
    另一家供应商（例如判定档用免费模型、靶标档用商用模型）。
    """

    model: str = "gpt-4o-mini"
    # 每百万 token 价格（人民币），仅用于成本估算，不影响调用
    price_in: float = 1.0
    price_out: float = 2.0
    base_url: str = ""
    api_key: str = ""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
    )

    app_name: str = "LLM Red Teaming Platform"
    debug: bool = True

    # ---------- 数据库 ----------
    # db_url 写死绝对路径，避免受启动时工作目录影响。
    # 想换库（例如真实实验与 mock 演示分离）请改 db_name，不要动 db_url。
    db_name: str = "rtp.db"
    db_url: str = f"sqlite+aiosqlite:///{(DATA_DIR / 'rtp.db').as_posix()}"

    # ---------- 模型网关 ----------
    # 默认指向本地 CC Proxy（OpenAI 兼容反代），上游 api.commandcode.ai。
    # 代理本身不落密钥，必须在每个请求的 Authorization: Bearer <key> 头里带上，
    # 因此 llm_api_key 为空时 use_mock 自动为 True。
    llm_base_url: str = "http://127.0.0.1:3050/v1"
    llm_api_key: str = ""
    llm_timeout: float = 120.0
    llm_max_retries: int = 3
    # 单次响应 token 上限的安全阀。推理模型（deepseek-v4 系列）会先产出思维链，
    # 额度给小了会把预算全烧在思考上、正文为空，因此截断后按此上限重试。
    max_tokens_ceiling: int = 4096
    # 各角色单次调用的 max_tokens 基线。推理模型需留足余量，否则正文被饿死。
    #
    # target/attack 用 3072：deepseek-v4 的思维链实测可占到 3000+ token，
    # 给 1024 时正文会返回空、该样本直接记 error。实测 12 条里有 1 条这样丢掉，
    # 而丢样本的代价不只是这次调用——它在批次里留下一个 error，让 ASR 的分母
    # 少一条，等于把一次失败悄悄算成了"未攻破"。
    # judge 用 flash 且只需输出短 JSON，1024 足够。
    max_tokens_target: int = 3072
    max_tokens_attack: int = 3072
    max_tokens_judge: int = 1024

    # 三级路由：靶标侧要真实反映风险，用较高质量模型；
    # 攻击侧用中档模型控制生成成本；判定侧用最低档模型。
    # 注意：price_* 仅用于成本估算，与渠道实际计费无关，需按实际单价填写。
    tier_target: ModelTier = Field(default_factory=lambda: ModelTier(
        model="deepseek/deepseek-v4-pro", price_in=1.0, price_out=2.0))
    tier_attack: ModelTier = Field(default_factory=lambda: ModelTier(
        model="deepseek/deepseek-v4-pro", price_in=1.0, price_out=2.0))
    tier_judge: ModelTier = Field(default_factory=lambda: ModelTier(
        model="deepseek/deepseek-v4-flash", price_in=1.0, price_out=2.0))

    target_temperature: float = 0.7
    attack_temperature: float = 1.0
    judge_temperature: float = 0.0

    # ---------- 运行时 ----------
    # auto: 无 key 时自动 mock；on: 强制 mock；off: 强制真实调用
    mock_mode: Literal["auto", "on", "off"] = "auto"
    concurrency: int = 4
    request_interval: float = 0.0  # 每次调用之间的最小间隔（秒），用于限流保护

    # ---------- 缓存 ----------
    cache_enabled: bool = True

    # ---------- 编排默认值 ----------
    default_max_turns: int = 5
    hard_max_turns: int = 10
    # 单用例 token 上限。推理模型（deepseek-v4）每轮同时产出思维链与正文，
    # 实测 5 轮约 1.2 万 token，因此 6000 会误伤正常用例。
    # 这里只作为"失控保护"，不是常态约束。
    turn_token_budget: int = 40000

    # ---------- 护栏 ----------
    default_guardrail_profile: str = "none"

    @property
    def use_mock(self) -> bool:
        if self.mock_mode == "on":
            return True
        if self.mock_mode == "off":
            return False
        return not self.llm_api_key.strip()

    def tier(self, role: str) -> ModelTier:
        t = {"target": self.tier_target,
             "attack": self.tier_attack,
             "judge": self.tier_judge}[role]
        if not t.base_url:
            t.base_url = self.llm_base_url
        if not t.api_key:
            t.api_key = self.llm_api_key
        return t


@lru_cache
def get_settings() -> Settings:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    s = Settings()
    # 只给 db_name 时按项目 data/ 目录派生绝对路径；
    # 显式给了 DB_URL 则尊重用户配置（便于接 PostgreSQL）。
    import os as _os
    if not _os.getenv("DB_URL"):
        s.db_url = f"sqlite+aiosqlite:///{(DATA_DIR / s.db_name).as_posix()}"
    return s


settings = get_settings()
