"""三个内置靶标的具体实现。

T1 对话式客服 / T2 RAG 知识库问答 / T3 智能办公 Agent，能力递进，
分别对应纯对话、检索增强、工具调用三类真实业务形态。

T5 不在此处独立实现——它是 T2 换一套护栏配置（``profile="full"``）的结果，
由执行器通过 profile 参数区分，从而保证同构性。
"""
from __future__ import annotations

from typing import Any

from app.targets import tools
from app.targets.base import BaseTarget
from app.targets.retriever import get_retriever

TOP_K = 3


class T1CustomerService(BaseTarget):
    uid = "T1"
    name = "对话式客服机器人"
    form_type = "chat"


class T2KnowledgeBase(BaseTarget):
    uid = "T2"
    name = "企业知识库问答（RAG）"
    form_type = "rag"
    kb_id = "yunqi"

    def __init__(self, profile: str = "none", system_prompt: str | None = None,
                 top_k: int = TOP_K):
        super().__init__(profile, system_prompt)
        self.top_k = top_k
        self._retriever = get_retriever(self.kb_id)

    def build_context(self, message: str) -> tuple[str, list[dict[str, Any]]]:
        hits = self._retriever.search(message, top_k=self.top_k)
        if not hits:
            return "（无检索结果）", []
        blocks = []
        meta = []
        for i, h in enumerate(hits, 1):
            blocks.append(f"[{i}] 文档编号：{h.doc_id}｜标题：{h.title}\n{h.text}")
            meta.append({"doc_id": h.doc_id, "title": h.title, "score": round(h.score, 3),
                         "text": h.text, "sensitive": h.sensitive, "poisoned": h.poisoned})
        return "\n\n".join(blocks), meta


class T3OfficeAgent(BaseTarget):
    uid = "T3"
    name = "智能办公 Agent（工具调用）"
    form_type = "agent"

    def pre_tool_context(self) -> str:
        return tools.TOOL_DOCS


BUILTIN_TARGETS = {
    "T1": T1CustomerService,
    "T2": T2KnowledgeBase,
    "T3": T3OfficeAgent,
}

# T5 不是独立的第四个靶标，而是 T2 在"启用全部护栏"配置下的同构视图。
# 它复用 T2 的同一份实现、同一份知识库、同一套提示词，唯一变量是护栏配置——
# 这正是护栏对比实验能够成立的技术保障。数据库里单独登记 T5 只是为了让
# 实验记录能直接按 target_uid 归档，不意味着存在两套代码。
ALIASES = {"T5": "T2"}


def build_target(uid: str, profile: str = "none", system_prompt: str | None = None) -> BaseTarget:
    impl = ALIASES.get(uid, uid)
    cls = BUILTIN_TARGETS.get(impl)
    if cls is None:
        raise KeyError(f"未知靶标：{uid}（可选 {list(BUILTIN_TARGETS) + list(ALIASES)}）")
    return cls(profile=profile, system_prompt=system_prompt)
