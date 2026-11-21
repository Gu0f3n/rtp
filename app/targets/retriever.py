"""轻量检索层：BM25 实现。

为什么不用向量库：T2 靶标的检索算法本身不是研究点，而 ChromaDB 会引入
onnxruntime 等重依赖，拖慢部署且增加演示环境的不确定性。BM25 零依赖、
可离线、结果可解释，且对"关键词高度重合"的投毒文档同样能召回——
这恰好是间接提示注入实验需要的效果。

接口与向量库保持一致（index / search），后续如需替换为向量检索，
只需另实现一个 Retriever 子类。
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from app.config import KB_DIR

_CJK = re.compile(r"[\u4e00-\u9fff]+")
_WORD = re.compile(r"[a-zA-Z][a-zA-Z0-9_\-.*/]{1,}")


def tokenize(text: str) -> list[str]:
    """中文按二元组切分，英文按词切分。

    中文不做分词（避免引入 jieba 依赖），用 bigram 已经足够支撑 BM25 的相关性判断。
    """
    tokens: list[str] = []
    for seg in _CJK.findall(text):
        if len(seg) == 1:
            tokens.append(seg)
        else:
            tokens.extend(seg[i:i + 2] for i in range(len(seg) - 1))
    for w in _WORD.findall(text):
        tokens.append(w.lower())
    return tokens


@dataclass
class Doc:
    doc_id: str
    title: str
    text: str
    sensitive: bool = False   # 是否为受限文档（用于后续按密级统计）
    poisoned: bool = False    # 是否为投毒文档（含注入指令）


@dataclass
class Hit:
    doc_id: str
    title: str
    text: str
    score: float
    sensitive: bool = False
    poisoned: bool = False


class BM25Retriever:
    def __init__(self, docs: list[Doc], k1: float = 1.5, b: float = 0.75):
        self.docs = docs
        self.k1 = k1
        self.b = b
        self._tokens = [tokenize(d.title + "\n" + d.text) for d in docs]
        self._lens = [len(t) for t in self._tokens]
        self._avg = sum(self._lens) / max(1, len(self._lens))
        self._df: Counter[str] = Counter()
        for toks in self._tokens:
            self._df.update(set(toks))
        self._n = len(docs)

    def _idf(self, term: str) -> float:
        df = self._df.get(term, 0)
        return math.log(1 + (self._n - df + 0.5) / (df + 0.5))

    def search(self, query: str, top_k: int = 3) -> list[Hit]:
        q = tokenize(query)
        if not q:
            return []
        scores: list[float] = []
        for i, toks in enumerate(self._tokens):
            tf = Counter(toks)
            s = 0.0
            for term in q:
                if term not in tf:
                    continue
                f = tf[term]
                denom = f + self.k1 * (1 - self.b + self.b * self._lens[i] / max(self._avg, 1e-6))
                s += self._idf(term) * f * (self.k1 + 1) / denom
            scores.append(s)
        order = sorted(range(self._n), key=lambda i: scores[i], reverse=True)[:top_k]
        out = []
        for i in order:
            if scores[i] <= 0:
                continue
            d = self.docs[i]
            out.append(Hit(doc_id=d.doc_id, title=d.title, text=d.text, score=scores[i],
                           sensitive=d.sensitive, poisoned=d.poisoned))
        return out


# --------------------------------------------------------------------------- #
# 知识库加载
# --------------------------------------------------------------------------- #
# 受限文档与投毒文档登记在这里（对应设计方案中 T2 的薄弱点设计）
SENSITIVE_DOCS = {"HR-2026-Q3-018", "MA-2026-007"}
POISONED_DOCS = {"MT-2026-0412"}

# 动态投毒的文档命名约定：文件名以 POISON- 开头的 doc_id 一律视为投毒文档。
# 这样投毒注入器只需往 kb 目录写文件即可完成"注入+登记"两步，不需要修改
# 源码里的集合常量——实验维度（投毒数量、载荷代次）才能真正自动化。
POISON_PREFIX = "POISON-"


def _is_poisoned(doc_id: str) -> bool:
    return doc_id in POISONED_DOCS or doc_id.startswith(POISON_PREFIX)


def _parse_doc(path: Path) -> Doc:
    raw = path.read_text(encoding="utf-8")
    doc_id = path.stem.split("_")[0]
    title = ""
    body = raw
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("#"):
            title = s.lstrip("#").strip()
            break
    if not title:
        title = path.stem
    return Doc(doc_id=doc_id, title=title, text=body,
               sensitive=doc_id in SENSITIVE_DOCS,
               poisoned=_is_poisoned(doc_id))


def load_kb(kb_dir: Path | None = None) -> BM25Retriever:
    d = kb_dir or KB_DIR
    docs = [_parse_doc(p) for p in sorted(d.glob("*.md"))]
    return BM25Retriever(docs)


_CACHE: dict[str, BM25Retriever] = {}
_CACHE_MTIME: float = 0.0


def _kb_mtime() -> float:
    """kb 目录最后修改时间（取所有 .md 的最大 mtime）。

    服务是常驻进程，索引在首次检索时建好并缓存；如果投毒注入器在
    服务运行期间写/删了文档，只删文件不会让缓存失效——实测会出现
    "文件已删、检索结果里还有毒文档"的幽灵索引。用目录 mtime 做
    自动失效，注入器就不需要通知服务了。
    """
    mtimes = [p.stat().st_mtime for p in KB_DIR.glob("*.md")]
    return max(mtimes) if mtimes else 0.0


def get_retriever(kb_id: str = "yunqi", refresh: bool = False) -> BM25Retriever:
    """按 kb_id 取缓存的检索器，kb 目录变化时自动重建。

    ``refresh=True`` 强制重建（批量注入时省去逐文件 stat）。
    """
    global _CACHE_MTIME
    mtime = _kb_mtime()
    if refresh or kb_id not in _CACHE or mtime != _CACHE_MTIME:
        _CACHE[kb_id] = load_kb()
        _CACHE_MTIME = mtime
    return _CACHE[kb_id]
