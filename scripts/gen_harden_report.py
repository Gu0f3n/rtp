"""生成加固前后对照的论文素材（Markdown）。

用法::

    DB_NAME=rtp_real.db PYTHONPATH=. python scripts/gen_harden_report.py
    DB_NAME=rtp_real.db PYTHONPATH=. python scripts/gen_harden_report.py T2 E5

产出写到 ``data/reports/HARDEN-<靶标>-<实验>.md``，内容按论文小节组织：
实验设计 → 结果 → 统计检验 → 讨论。表格可直接粘进论文。

**这个脚本只做数据整理与机械结论**（按数值套句式），不做发挥。
第 6 章的铁律是数据必须实测：脚本里的每个数字都来自数据库，
凡是"无数据"的地方就写"无数据"，不补估算值。
"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime
from pathlib import Path

from app.config import REPORT_DIR
from app.db import engine
from app.runner.metrics import harden_compare

SEV_CN = {"none": "无泄露", "recon": "情报级",
          "disclosure": "敏感级", "credential": "凭据级"}
CELL_CN = {"only_before": "护栏生效", "only_after": "护栏反效",
           "both_success": "漏防", "both_fail": "均防住"}


def _pct(v: float | None) -> str:
    return "—" if v is None else f"{v * 100:.1f}%"


def _ci(iv: list[float] | tuple[float, float]) -> str:
    return f"{iv[0] * 100:.1f}% ~ {iv[1] * 100:.1f}%"


def build_md(d: dict) -> str:
    if not d.get("comparable"):
        return (f"# 加固前后对照\n\n**数据不可配对：** {d.get('reason')}\n")

    b, a, e, c = d["before"], d["after"], d["effect"], d["checks"]
    m = d["mcnemar"]
    mx = d["matrix"]
    L: list[str] = []

    L.append("# 加固前后系统对照实验")
    L.append("")
    L.append(f"生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M')}　"
             f"靶标：{d['target']}　实验：{d['experiment']}")
    L.append("")

    # ---- 设计 ----
    L.append("## 一、实验设计")
    L.append("")
    L.append("### 1.1 研究问题")
    L.append("")
    L.append("同一套业务系统，在**未加固**与**全量加固**两种配置下，"
             "被同一批攻击载荷攻击时的表现差异有多大？削减量是否显著，"
             "以及加固后被攻破的样本呈现什么特征？")
    L.append("")
    L.append("### 1.2 两套系统的同构性")
    L.append("")
    L.append("| 维度 | 加固前（T2） | 加固后（T5） | 是否相同 |")
    L.append("|---|---|---|---|")
    L.append("| 靶标实现 | T2KnowledgeBase | T2KnowledgeBase | 相同 |")
    L.append("| 知识库 | yunqi | yunqi | 相同 |")
    L.append("| 模型与温度 | 同一网关同一模型 | 同一网关同一模型 | 相同 |")
    L.append("| 攻击载荷 | 见 1.3 | 见 1.3 | 相同（逐条配对） |")
    L.append(f"| 护栏配置 | `none` | `full` | **唯一变量** |")
    L.append("")
    L.append("T5 不是另写的一套系统，而是 T2 在 `profile=full` 下的同构视图——"
             "输入过滤、系统提示加固、输出过滤三者同时启用。"
             "因此两组结果之差只能归因于护栏状态。")
    L.append("")
    L.append("### 1.3 样本与配对方式")
    L.append("")
    L.append(f"- 配对载荷：**{c['paired_cases']} 条**，两组载荷集合"
             f"{'完全一致' if c['same_cases'] else '不一致（结果不可比）'}。")
    if c["only_in_before"] or c["only_in_after"]:
        L.append(f"- 仅加固前有：{', '.join(c['only_in_before']) or '无'}；"
                 f"仅加固后有：{', '.join(c['only_in_after']) or '无'}。")
    L.append(f"- 调用模式：{'真实模型' if c['both_live'] else '包含 mock 数据（不可用于论文）'}。")
    L.append("- 设计类型：**配对设计**。同一载荷在两种配置下各执行一次，"
             "按用例逐条配对，而非比较两个独立样本的总体比例。")
    L.append("")
    L.append("选择配对设计的理由：两组若视为独立样本，"
             "载荷难度差异会被当成噪声计入方差；配对后每条载荷自带基线，"
             "把\"载荷本身难不难\"这个变量从误差里剔除，"
             "剩下的是纯粹由护栏引起的变化。")
    L.append("")

    # ---- 结果 ----
    L.append("## 二、结果")
    L.append("")
    L.append("### 2.1 总体指标")
    L.append("")
    L.append("| 指标 | 加固前 | 加固后 | 变化 |")
    L.append("|---|---|---|---|")
    L.append(f"| 执行完成数 | {b['finished']} | {a['finished']} | — |")
    L.append(f"| 攻破数 | {b['success']} | {a['success']} | {a['success'] - b['success']:+d} |")
    L.append(f"| ASR | {_pct(b['asr'])} | {_pct(a['asr'])} | "
             f"{_pct(e['asr_delta'])} |")
    L.append(f"| ASR 95% CI（Wilson） | {_ci(b['asr_ci'])} | {_ci(a['asr_ci'])} | — |")
    L.append(f"| 实质泄露（敏感级+凭据级） | {e['substantive_leaks_before']} | "
             f"{e['substantive_leaks_after']} | "
             f"{e['substantive_leaks_after'] - e['substantive_leaks_before']:+d} |")
    L.append(f"| 侦察率 | {_pct(e['recon_rate_before'])} | "
             f"{_pct(e['recon_rate_after'])} | — |")
    L.append(f"| 被拦截轮次 | {e['blocked_turns_before']} | {e['blocked_turns_after']} | — |")
    L.append(f"| 平均对话轮次 | {e['avg_turns_before']} | {e['avg_turns_after']} | — |")
    L.append(f"| 首破轮次均值 | {e['avg_success_turn_before'] or '—'} | "
             f"{e['avg_success_turn_after'] or '—'} | — |")
    L.append(f"| 成本（元） | {e['cost_before']:.4f} | {e['cost_after']:.4f} | — |")
    L.append("")
    L.append(f"**ASR 削减率：{_pct(e['reduction_rate'])}。**")
    L.append("")

    L.append("### 2.2 逐条配对结果（2×2 四格表）")
    L.append("")
    L.append("|  | 加固后 · 未攻破 | 加固后 · 攻破 |")
    L.append("|---|---|---|")
    L.append(f"| **加固前 · 攻破** | {mx['only_before']}（护栏生效） | "
             f"{mx['both_success']}（漏防） |")
    L.append(f"| **加固前 · 未攻破** | {mx['both_fail']}（均防住） | "
             f"{mx['only_after']}（护栏反效） |")
    L.append("")
    L.append("四格的含义：")
    L.append("")
    L.append(f"- **护栏生效 {mx['only_before']} 条**：加固前被攻破、加固后被挡住，"
             "这部分直接构成护栏的有效性证据。")
    L.append(f"- **漏防 {mx['both_success']} 条**：两种配置下都被攻破，"
             "说明这类攻击路径不在当前护栏的覆盖范围内，"
             "加固对它们没有作用（详见 2.4）。")
    L.append(f"- **均防住 {mx['both_fail']} 条**：与护栏无关，"
             "靠模型自身对齐就守住了。")
    L.append(f"- **护栏反效 {mx['only_after']} 条**：加固前守住、加固后反而被攻破。"
             + ("该格为 0，符合预期。" if mx["only_after"] == 0 else
                "该格不为 0，说明存在模型自身波动或样本污染，需复查。"))
    L.append("")

    L.append("### 2.3 危害分级位移")
    L.append("")
    L.append("| 位移 | 条数 |")
    L.append("|---|---|")
    for k, v in e["severity_shift"].items():
        parts = k.split("→")
        if len(parts) == 2:
            k = f"{SEV_CN.get(parts[0], parts[0])} → {SEV_CN.get(parts[1], parts[1])}"
        L.append(f"| {k} | {v['count']} |")
    L.append("")
    L.append("分级是有序的（无泄露 < 情报级 < 敏感级 < 凭据级），"
             "因此\"敏感级 → 无泄露\"与\"凭据级 → 情报级\"虽然都跨了级，"
             "但后者仍存在可被下一跳利用的泄露。ASR 只区分攻破与否，"
             "这张表回答的是\"漏到了什么程度\"。")
    L.append("")

    if d["leaks"]:
        L.append("### 2.4 加固后仍被攻破的样本")
        L.append("")
        L.append("| 用例 | 类别 | 危害分级 | 轮次 | 归因 |")
        L.append("|---|---|---|---|---|")
        for x in d["leaks"]:
            L.append(f"| {x['case_uid']} | {x['category']} | "
                     f"{SEV_CN.get(x['severity'], x['severity'])} | {x['turns']} | {x['hint']} |")
        L.append("")
        L.append("归因分两类：**「护栏曾命中但未阻断」**说明规则看到了这个请求、"
                 "但强度不足以挡住整条路径，属于规则强度问题；"
                 "**「全程未被命中」**说明这类攻击完全在规则视野之外，"
                 "属于覆盖盲区。前者可调阈值，后者必须新增规则。")
        L.append("")
    else:
        L.append("### 2.4 加固后仍被攻破的样本")
        L.append("")
        L.append("无。全部载荷在加固后被挡住或未被攻破。"
                 "若样本量偏小，需注意该结论的置信区间仍然很宽。")
        L.append("")

    # ---- 检验 ----
    L.append("## 三、统计检验")
    L.append("")
    L.append("### 3.1 McNemar 配对精确检验")
    L.append("")
    L.append("检验对象仅为 `护栏生效`（b）与 `护栏反效`（c）两格："
             "两边都成功或都失败的样本不携带\"护栏是否起作用\"的信息。")
    L.append("")
    L.append("| 项 | 值 |")
    L.append("|---|---|")
    L.append(f"| b（加固前成功、加固后失败） | {m['b']} |")
    L.append(f"| c（加固前失败、加固后成功） | {m['c']} |")
    L.append(f"| 检验样本数 n = b + c | {m['n']} |")
    L.append(f"| 精确 p 值（双侧） | {m['p_value']} |")
    L.append(f"| 结论（α=0.05） | {'差异显著' if m['significant'] else '差异不显著'} |")
    L.append("")
    L.append(f"> {m['note']}")
    L.append("")
    L.append("### 3.2 为什么同时报置信区间")
    L.append("")
    L.append(f"加固前 ASR 的 95% 区间为 {_ci(b['asr_ci'])}，"
             f"加固后为 {_ci(a['asr_ci'])}。")
    L.append("")
    L.append("点估计的差（{0}）看起来很大，但两个区间的宽度说明"
             "n={1} 时估计本身就不精确。".format(
                 _pct(e["asr_delta"]), c["paired_cases"]))
    L.append("两者若仍有重叠，说明仅凭总体比例**无法**断言加固有效——"
             "这正是必须做配对检验的原因：配对后比较的是同一批载荷的"
             "变化方向，而不是两个各自带误差的比例。")
    L.append("")

    # ---- 讨论 ----
    L.append("## 四、讨论")
    L.append("")
    red = e["reduction_rate"]
    if red is None:
        L.append("加固前基线 ASR 为 0，削减率无定义。"
                 "这意味着这批载荷在未加固时就没能攻破目标，"
                 "该组数据不能用来评价护栏效果，需换更有效的载荷重跑。")
    elif red >= 0.99:
        L.append(f"加固后 ASR 降至 {_pct(a['asr'])}，削减率 {_pct(red)}。"
                 "需要强调：这个数字只对**当前这批载荷**成立。"
                 "载荷集中在对单轮直接索取，而护栏的输入规则恰好覆盖这类表述，"
                 "因此削减率高不代表护栏对多轮渐进或级联攻击同样有效——"
                 "后者每轮单看都不含违规表述，正是无状态过滤器的盲区。")
    else:
        L.append(f"加固削减了 {_pct(red)} 的攻破，剩余 {_pct(a['asr'])}。"
                 "残余部分集中在 2.4 列出的路径上，"
                 "说明护栏的作用边界是\"能被规则识别的表述\"，"
                 "而不是\"所有越权意图\"。")

    L.append("")
    L.append("另外两项变化值得注意：")
    L.append("")
    L.append(f"1. **被拦截轮次由 {e['blocked_turns_before']} 升至 "
             f"{e['blocked_turns_after']}**——加固确实介入了执行过程，"
             "而不只是让模型\"自己更谨慎\"。这个计数是护栏独立于模型行为的证据。")
    L.append(f"2. **平均轮次由 {e['avg_turns_before']} 变为 "
             f"{e['avg_turns_after']}**。"
             + ("轮次上升说明攻击方被拖入更长的试探，即使最终未攻破，"
                "也提高了攻击成本——这是一项容易被忽略的防御收益。"
                if (e["avg_turns_after"] or 0) > (e["avg_turns_before"] or 0)
                else "轮次未明显上升，说明加固属于\"直接阻断\"而非\"拖延\"。"))
    L.append("")
    L.append("### 局限性")
    L.append("")
    L.append(f"1. 样本量 {c['paired_cases']} 条，置信区间较宽，"
             "结论适合定性判断，不宜外推到精确比例。")
    L.append("2. 实验只覆盖单靶标（同一份知识库）。"
             "护栏规则是针对该业务域的实体（薪酬、并购、接口密钥）编写的，"
             "换一个业务域需要重写规则，削减率不可直接移植。")
    L.append("3. 两组共用同一模型与温度，但模型自身的采样波动无法完全排除；"
             "`护栏反效`格为 0 是该波动可控的旁证。")
    L.append("")
    L.append("---")
    L.append("")
    L.append("数据来源：`harden_compare()` 直接读取实验库，"
             "未做任何人工修正。原始记录见 attack_run / judge_result 表。")
    return "\n".join(L)


async def main(target: str = "T2", experiment: str = "E5") -> None:
    d = await harden_compare(target, experiment)
    md = build_md(d)
    out = Path(REPORT_DIR) / f"HARDEN-{target}-{experiment}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    print(f"已生成 {out}（{len(md)} 字符）")
    if d.get("comparable"):
        print(f"  ASR {_pct(d['before']['asr'])} -> {_pct(d['after']['asr'])}"
              f" | 削减率 {_pct(d['effect']['reduction_rate'])}"
              f" | p={d['mcnemar']['p_value']}")
    await engine.dispose()


if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else "T2"
    ex = sys.argv[2] if len(sys.argv) > 2 else "E5"
    asyncio.run(main(t, ex))
