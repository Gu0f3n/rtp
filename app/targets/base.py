"""靶标基类：统一的对话接口 + 护栏中间件挂载点。

一次 chat 调用的固定流水线::

    输入护栏 → （RAG 检索 / 工具上下文）→ 组装 messages → 模型调用
             → （工具调用循环）→ 输出护栏 → 返回

护栏在这里以"中间件"形式介入，靶标业务代码（提示词、检索、工具）
完全不感知护栏的存在——这正是 T2 与 T5 能保持同构的原因。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from app.config import settings
from app.core import mock_llm
from app.core.gateway import gateway
from app.engines import guardrail
from app.schemas import ChatMessage, ChatResponse
from app.targets import prompts, tools

# 单次对话允许的工具往返轮数。
#
# 这个数字是**成本与能力的折中**：每多一轮就多一次模型调用（token 与延迟
# 都翻倍），但没有上限则模型可能陷入自我循环。经验值取 4——足以完成
# 「看目录 → 读文件 → 执行动作 → 总结」的典型办公链路，又不会让一次
# 对话烧掉过多预算。
#
# 注意：轮数耗尽是**正常终止**，不是错误。原先硬编码 2 轮会丢掉最后一帧
# 模型刚输出的工具调用，导致「回复里说已经发送、实际没有执行」的静默不一致，
# 攻击判定与审计都会因此失真。
MAX_TOOL_ROUNDS = 4


@dataclass
class TargetState:
    """一次会话的可变状态（护栏配置在会话开始时固定）。"""

    profile: str = "none"
    retrieved: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    blocked: bool = False
    blocked_by: str | None = None


class BaseTarget:
    uid: str = "T?"
    name: str = "靶标"
    form_type: str = "chat"
    kb_id: str | None = None

    def __init__(self, profile: str = "none", system_prompt: str | None = None):
        self.profile = profile
        self._prompt_override = system_prompt
        self._cfg = guardrail.resolve_profile(profile)

    # ------------------------------------------------------------------ #
    # 可覆盖的钩子
    # ------------------------------------------------------------------ #
    def system_prompt(self, context: str = "") -> str:
        if self._prompt_override:
            return self._prompt_override
        if self._cfg["prompt_hardening"]:
            return prompts.get_prompt(self.uid, hardened=True, context=context)
        return prompts.get_prompt(self.uid, hardened=False, context=context)

    def build_context(self, message: str) -> tuple[str, list[dict[str, Any]]]:
        """返回 (注入到提示中的上下文, 检索元信息)。"""
        return "", []

    def pre_tool_context(self) -> str:
        return ""

    # ------------------------------------------------------------------ #
    # 主流程
    # ------------------------------------------------------------------ #
    async def chat(self, message: str, history: list[ChatMessage] | None = None,
                   profile: str | None = None) -> ChatResponse:
        t0 = time.perf_counter()
        if profile is not None and profile != self.profile:
            self.profile = profile
            self._cfg = guardrail.resolve_profile(profile)

        history = history or []
        state = TargetState(profile=self.profile)

        # ---- 1. 输入护栏 ----
        verdict = guardrail.check_input(message, self._cfg["input_filter"])
        if verdict.blocked:
            return ChatResponse(
                reply=verdict.text, blocked=True, blocked_by=f"input:{','.join(verdict.labels)}",
                guardrail_profile=self.profile,
                latency_ms=int((time.perf_counter() - t0) * 1000))

        # ---- 2. 上下文（RAG / 工具说明）----
        context, retrieved = self.build_context(message)
        state.retrieved = retrieved
        extra = self.pre_tool_context()
        if extra:
            context = (context + "\n" + extra).strip() if context else extra

        # ---- 3. 组装 messages ----
        msgs: list[dict[str, str]] = [
            {"role": "system", "content": self.system_prompt(context)}
        ]
        for h in history:
            if h.role == "system":
                continue
            msgs.append({"role": h.role, "content": h.content})
        msgs.append({"role": "user", "content": message})

        # ---- 4. 模型调用 ----
        resp = await gateway.chat(
            msgs, role="target",
            mock_handler=lambda: mock_llm.mock_target(
                msgs, self.uid, [r["text"] for r in retrieved],
                hardened=self._cfg["prompt_hardening"]),
            use_cache=False,
        )
        reply = resp.text
        tok_in, tok_out, cost = resp.token_in, resp.token_out, resp.cost

        # ---- 5. 工具循环（仅 Agent 形态）----
        if self.form_type == "agent":
            reply, extra = await self._tool_loop(msgs, reply, resp.tool_calls, state)
            tok_in += extra[0]
            tok_out += extra[1]
            cost += extra[2]

        # ---- 6. 输出护栏 ----
        ov = guardrail.check_output(reply, self._cfg["output_filter"])
        if ov.blocked:
            state.blocked = True
            state.blocked_by = f"output:{','.join(ov.labels)}"
            reply = ov.text

        return ChatResponse(
            reply=reply,
            blocked=state.blocked,
            blocked_by=state.blocked_by,
            retrieved=[r["doc_id"] for r in retrieved],
            retrieved_poisoned=sum(1 for r in retrieved if r.get("poisoned")),
            tool_calls=state.tool_calls,
            guardrail_profile=self.profile,
            latency_ms=int((time.perf_counter() - t0) * 1000),
            token_in=tok_in,
            token_out=tok_out,
            cost=cost,
        )

    # ------------------------------------------------------------------ #
    async def _tool_loop(self, msgs: list[dict[str, str]], reply: str,
                         native_calls: list[dict[str, Any]] | None,
                         state: TargetState) -> tuple[str, tuple[int, int, float]]:
        """执行工具调用并把结果回灌给模型。

        最多两轮，避免模型陷入无限调用。所有工具都是模拟实现。
        返回 (回复, (token_in, token_out, cost))——回灌调用同样消耗 token，
        必须回传给上层累计，否则 Agent 类靶标的成本会被低估。
        """
        tok = [0, 0, 0.0]
        calls: list[tuple[str, dict[str, Any]]] = []
        if native_calls:
            for c in native_calls:
                fn = (c.get("function") or {})
                name = fn.get("name") or c.get("name")
                args = fn.get("arguments") or c.get("args") or {}
                if isinstance(args, str):
                    import json
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                if name in tools.TOOLS:
                    calls.append((name, args))
        if not calls:
            calls = tools.parse_tool_calls(reply)

        # mock 模式：结构化 tool_calls 已由 mock 给出，结果直接体现在响应里，
        # 不再二次调用模型（保持 mock 行为可预测）
        if settings.use_mock and native_calls:
            for name, args in calls:
                r = tools.invoke(name, args)
                state.tool_calls.append({
                    "name": name, "args": args, "ok": r.ok,
                    "privileged": r.privileged, "output": r.output[:400]})
            return reply, (0, 0, 0.0)

        for _round in range(MAX_TOOL_ROUNDS):
            if not calls:
                break
            results = []
            for name, args in calls:
                r = tools.invoke(name, args)
                state.tool_calls.append({
                    "name": name, "args": args, "ok": r.ok,
                    "privileged": r.privileged, "output": r.output[:400]})
                results.append(f"[{name}] {r.output}")

            tool_msg = "工具执行结果：\n" + "\n".join(results)
            msgs2 = msgs + [
                {"role": "assistant", "content": reply},
                {"role": "user", "content": tool_msg + "\n\n请基于以上工具结果直接回答用户。"},
            ]
            resp2 = await gateway.chat(
                msgs2, role="target",
                mock_handler=lambda: mock_llm.mock_target(
                    msgs2, self.uid, [], hardened=self._cfg["prompt_hardening"]),
                use_cache=False)
            reply = resp2.text
            tok[0] += resp2.token_in
            tok[1] += resp2.token_out
            tok[2] += resp2.cost
            calls = tools.parse_tool_calls(reply)

        # 兜底：轮数耗尽时，上一帧模型刚输出的调用还没有被执行。
        # 直接丢弃会出现「回复里写了已执行、实际没执行」的静默不一致，
        # 使得 privilege 统计漏计、判定器误判为攻破。这里就地执行并如实登记。
        if calls:
            for name, args in calls:
                r = tools.invoke(name, args)
                state.tool_calls.append({
                    "name": name, "args": args, "ok": r.ok,
                    "privileged": r.privileged, "output": r.output[:400]})
        return reply, (tok[0], tok[1], tok[2])
