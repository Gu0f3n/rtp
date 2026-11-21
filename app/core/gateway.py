"""模型网关：三级路由 + 磁盘缓存 + 重试 + 成本核算 + mock 降级。

设计要点：

1. **三级路由**：target / attack / judge 三个角色各自绑定模型档位。
   靶标侧用较高质量模型以保证结论代表性；攻击侧用中档模型控制生成成本；
   判定侧用最低档（甚至免费）模型。这一层是成本能压到百元以内的关键。

2. **缓存分层**：攻击生成与判定结果可缓存（同输入同输出不影响结论），
   靶标响应默认不缓存（要保留真实随机性，否则 E2 的重复实验会失真）。

3. **mock 降级**：无 API Key 时自动走本地 mock，调用方通过 mock_handler
   注入该角色的模拟逻辑，网关本身不关心 mock 语义。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx

from app.config import CACHE_DIR, settings
from app.core import mock_llm


class LLMError(RuntimeError):
    pass


@dataclass
class LLMResponse:
    text: str
    token_in: int = 0
    token_out: int = 0
    cost: float = 0.0
    latency_ms: int = 0
    cached: bool = False
    mock: bool = False
    model: str = ""
    tool_calls: list[dict[str, Any]] | None = None
    # 推理模型（如 deepseek-v4）会先输出思维链再输出正文。
    # reasoning_tokens 计入 completion_tokens（真实计费），单独记录便于成本归因。
    reasoning_tokens: int = 0
    # 被 max_tokens 截断。截断的靶标回答不可直接当作"拒答"参与判定。
    truncated: bool = False


@dataclass
class GatewayStats:
    calls: int = 0
    cache_hits: int = 0
    failures: int = 0
    token_in: int = 0
    token_out: int = 0
    cost: float = 0.0
    by_role: dict[str, int] = field(default_factory=dict)

    def as_dict(self, mock: bool) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "cache_hits": self.cache_hits,
            "failures": self.failures,
            "token_in": self.token_in,
            "token_out": self.token_out,
            "cost": round(self.cost, 4),
            "mock": mock,
            "by_role": dict(self.by_role),
        }


def estimate_tokens(text: str) -> int:
    """粗略估算 token 数：中文约 1 字 1 token，英文约 4 字符 1 token。

    仅用于成本估算与预算控制，精度不影响功能。
    """
    cn = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
    other = len(text) - cn
    return max(1, cn + other // 4)


class Gateway:
    """进程内单例。"""

    def __init__(self) -> None:
        self.stats = GatewayStats()
        self._lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(settings.concurrency)
        self._client: httpx.AsyncClient | None = None
        self._last_call = 0.0

    # ------------------------------------------------------------------ #
    # 内部工具
    # ------------------------------------------------------------------ #
    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=settings.llm_timeout)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _cache_path(self, key: str) -> Path:
        return CACHE_DIR / f"{key}.json"

    @staticmethod
    def _cache_key(role: str, model: str, temperature: float,
                   messages: list[dict[str, str]]) -> str:
        raw = json.dumps({"r": role, "m": model, "t": temperature, "msgs": messages},
                         ensure_ascii=False, sort_keys=True)
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()

    async def _record(self, role: str, resp: LLMResponse) -> None:
        async with self._lock:
            self.stats.calls += 1
            self.stats.by_role[role] = self.stats.by_role.get(role, 0) + 1
            if resp.cached:
                self.stats.cache_hits += 1
            self.stats.token_in += resp.token_in
            self.stats.token_out += resp.token_out
            self.stats.cost += resp.cost

    def _price(self, role: str, tin: int, tout: int) -> float:
        tier = settings.tier(role)
        return (tin * tier.price_in + tout * tier.price_out) / 1_000_000

    # ------------------------------------------------------------------ #
    # 主入口
    # ------------------------------------------------------------------ #
    async def chat(
        self,
        messages: list[dict[str, str]],
        *,
        role: str = "target",
        temperature: float | None = None,
        use_cache: bool = False,
        mock_handler: Callable[[], mock_llm.MockResult] | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        tier = settings.tier(role)
        temp = {"target": settings.target_temperature,
                "attack": settings.attack_temperature,
                "judge": settings.judge_temperature}[role] if temperature is None else temperature
        model = tier.model
        # 推理模型必须显式给足预算：额度不足时会先烧完思维链、正文为空。
        # 未指定时按角色取基线，而不是交给上游默认值（上游默认可能偏小）。
        if max_tokens is None:
            max_tokens = {"target": settings.max_tokens_target,
                          "attack": settings.max_tokens_attack,
                          "judge": settings.max_tokens_judge}.get(role, 1024)

        # ---- mock 分支 ----
        if settings.use_mock:
            handler = mock_handler or (lambda: mock_llm.MockResult(
                text="[mock] 未提供该角色的模拟逻辑"))
            result = handler()
            prompt_text = "".join(m.get("content", "") for m in messages)
            tin, tout = estimate_tokens(prompt_text), estimate_tokens(result.text)
            resp = LLMResponse(
                text=result.text, token_in=tin, token_out=tout,
                cost=self._price(role, tin, tout), latency_ms=0,
                mock=True, model=f"mock:{role}",
                tool_calls=result.tool_calls)
            await self._record(role, resp)
            return resp

        # ---- 缓存分支 ----
        ck = self._cache_key(role, model, temp, messages)
        if use_cache and settings.cache_enabled:
            p = self._cache_path(ck)
            if p.exists():
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                    resp = LLMResponse(
                        text=data["text"], token_in=data.get("token_in", 0),
                        token_out=data.get("token_out", 0),
                        cost=data.get("cost", 0.0), cached=True, model=model,
                        tool_calls=data.get("tool_calls"))
                    await self._record(role, resp)
                    return resp
                except Exception:  # noqa: BLE001
                    p.unlink(missing_ok=True)

        # ---- 真实调用 ----
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temp,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        headers = {"Content-Type": "application/json"}
        if tier.api_key:
            headers["Authorization"] = f"Bearer {tier.api_key}"

        url = tier.base_url.rstrip("/") + "/chat/completions"
        last_err: Exception | None = None
        t0 = time.perf_counter()

        for attempt in range(settings.llm_max_retries):
            try:
                async with self._sem:
                    if settings.request_interval:
                        wait = settings.request_interval - (time.perf_counter() - self._last_call)
                        if wait > 0:
                            await asyncio.sleep(wait)
                    r = await self.client.post(url, json=payload, headers=headers)
                    self._last_call = time.perf_counter()
                if r.status_code == 429:
                    await asyncio.sleep(2 ** attempt)
                    last_err = LLMError("429 rate limited")
                    continue
                r.raise_for_status()
                data = r.json()

                choice = data["choices"][0]
                msg = choice.get("message") or {}
                # 只取 content：reasoning_content 是思维链，绝不能混进靶标回答，
                # 否则等于把模型的内心戏当成对外输出，判定会全盘失真。
                text = msg.get("content") or ""
                finish = choice.get("finish_reason")
                usage = data.get("usage") or {}
                tin = usage.get("prompt_tokens") or estimate_tokens(
                    "".join(m.get("content", "") for m in messages))
                tout = usage.get("completion_tokens") or estimate_tokens(text)
                reasoning = (usage.get("completion_tokens_details") or {}).get(
                    "reasoning_tokens") or 0

                # 推理模型在 token 预算不足时会把额度全烧在思维链上，
                # content 变成 null。此时若按空字符串返回，上层会误判为"靶标拒答"，
                # 进而把一次截断记成一次防御成功，系统性低估 ASR。
                # 因此截断且无正文一律视为调用失败，交由重试或记 error。
                if finish == "length" and not text.strip():
                    last_err = LLMError(
                        f"响应被截断：max_tokens={max_tokens} 不足以容纳思考过程"
                        f"（推理已消耗 {tout} tokens），未产出正文")
                    if attempt < settings.llm_max_retries - 1:
                        payload["max_tokens"] = min(
                            settings.max_tokens_ceiling,
                            max(512, int((max_tokens or 256) * 3)))
                        await asyncio.sleep(1.0)
                        continue
                    break

                resp = LLMResponse(
                    text=text, token_in=tin, token_out=tout,
                    cost=self._price(role, tin, tout),
                    latency_ms=int((time.perf_counter() - t0) * 1000),
                    model=model, tool_calls=msg.get("tool_calls"),
                    reasoning_tokens=reasoning,
                    truncated=(finish == "length"))

                if use_cache and settings.cache_enabled:
                    try:
                        self._cache_path(ck).write_text(json.dumps({
                            "text": resp.text, "token_in": tin, "token_out": tout,
                            "cost": resp.cost, "tool_calls": resp.tool_calls,
                            "reasoning_tokens": reasoning,
                        }, ensure_ascii=False), encoding="utf-8")
                    except OSError:
                        pass

                await self._record(role, resp)
                return resp

            except Exception as e:  # noqa: BLE001
                last_err = e
                if attempt < settings.llm_max_retries - 1:
                    await asyncio.sleep(1.5 * (attempt + 1))

        async with self._lock:
            self.stats.failures += 1
        raise LLMError(f"调用失败（role={role}, model={model}）: {last_err}")

    # ------------------------------------------------------------------ #
    def reset_stats(self) -> None:
        self.stats = GatewayStats()


gateway = Gateway()


async def call_with_mock(
    messages: list[dict[str, str]],
    *,
    role: str,
    mock_handler: Callable[[], mock_llm.MockResult],
    temperature: float | None = None,
    use_cache: bool = False,
) -> LLMResponse:
    """语法糖：把 mock_handler 直接包进 gateway.chat。"""
    return await gateway.chat(messages, role=role, temperature=temperature,
                              use_cache=use_cache, mock_handler=mock_handler)
