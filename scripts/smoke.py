"""八页签全接口冒烟测试：逐一验证 Web 控制台每个页签依赖的 API。

用法：python scripts/smoke.py [base_url]
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8017"

PASS, FAIL = [], []


def get(path: str, **params) -> tuple[bool, object]:
    url = BASE + path
    if params:
        url += "?" + "&".join(f"{k}={v}" for k, v in params.items())
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            raw = r.read().decode("utf-8")
            try:
                return True, json.loads(raw)
            except json.JSONDecodeError:
                return True, raw[:200]
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:200]}"
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def check(tab: str, name: str, path: str, must: list[str] | None = None, **params) -> None:
    ok, data = get(path, **params)
    if not ok:
        FAIL.append(f"[{tab}] {name} -> {data}")
        print(f"  ✗ {name}: {data}")
        return
    if must:
        text = json.dumps(data, ensure_ascii=False) if not isinstance(data, str) else data
        missing = [k for k in must if k not in text]
        if missing:
            FAIL.append(f"[{tab}] {name} 缺少字段 {missing}")
            print(f"  ✗ {name}: 缺少字段 {missing}")
            return
    PASS.append(f"[{tab}] {name}")
    print(f"  ✓ {name}")


print("=" * 62)
print(f"冒烟测试 {BASE}")
print("=" * 62)

# ---- 页签 1：总览 ----
print("\n[1] 总览")
check("总览", "指标总览", "/api/metrics/overview",
      ["breached", "defended", "runs_by_status", "total_cost"])
check("总览", "网关统计", "/api/gateway/stat", ["calls", "mock"])

# ---- 页签 2：靶标试打 ----
print("\n[2] 靶标试打")
check("靶标", "靶标列表", "/api/targets", ["T1", "T2", "T3", "T5"])
check("靶标", "护栏档位", "/api/targets/profiles", ["none", "input", "output", "prompt", "full"])
check("靶标", "T2 系统提示", "/api/targets/T2/prompt", ["system_prompt"])
check("靶标", "T2 知识库", "/api/targets/T2/kb")

# ---- 页签 3：攻击用例 ----
print("\n[3] 攻击用例")
check("用例", "种子列表", "/api/seeds", ["LLM01"])
check("用例", "种子统计", "/api/seeds/stats", ["by_category", "by_technique"])
check("用例", "用例列表", "/api/cases", ["channel", "text"])

# ---- 页签 4：攻击任务 ----
print("\n[4] 攻击任务")
ok, batches = get("/api/batches")
if ok and batches:
    check("任务", "批次列表", "/api/batches", ["uid"])
    first = batches[0]["uid"]
    check("任务", f"批次详情 {first}", f"/api/batches/{first}",
          ["runs_by_status", "runs_by_outcome"])
    check("任务", "批次轮次轨迹", f"/api/batches/{first}/turns", ["items", "state"])
    check("任务", "任务列表", "/api/runs", ["total", "items", "success", "case_uid"])
    ok2, runs = get("/api/runs", limit=1)
    if ok2 and runs.get("items"):
        rid = runs["items"][0]["id"]
        check("任务", f"任务详情 #{rid}", f"/api/runs/{rid}",
              ["turns", "judge", "case_text"])
else:
    FAIL.append("[任务] 无批次可测")
    print("  ! 库中无批次，跳过任务详情测试")

# ---- 页签 5：实验分析 ----
print("\n[5] 实验分析")
check("分析", "E2 轮次曲线 T1", "/api/metrics/e2", target="T1")
check("分析", "E2 轮次曲线 T2", "/api/metrics/e2", target="T2")
check("分析", "E5 护栏对比", "/api/metrics/e5", target="T2")
check("分析", "E4 判定对比", "/api/metrics/e4", target="T2")

# ---- 页签 6：标准对齐 ----
print("\n[6] 标准对齐")
check("标准", "三套标准数据", "/api/knowledge/standards",
      ["LLM01", "AML.T0051", "GB/T 45654", "in_scope", "maturity"])
check("标准", "OWASP 覆盖矩阵", "/api/knowledge/coverage",
      ["items", "summary", "paper_only", "seeds", "asr"])
check("标准", "国标合规对照", "/api/knowledge/compliance",
      ["items", "summary", "over_refusal_rate", "disclaimer"])
check("标准", "按靶标覆盖", "/api/knowledge/coverage", target="T2")

# ---- 页签 7：人工复核 ----
print("\n[7] 人工复核")
check("复核", "复核队列", "/api/reviews", ["total", "items"])

# ---- 页签 8：测评报告 ----
print("\n[8] 测评报告")
ok, batches = get("/api/batches")
if ok and batches:
    bug = batches[-1]["uid"]
    check("报告", f"报告 JSON {bug}", f"/api/report/{bug}", ["summary", "samples"])
    check("报告", f"报告导出 {bug}", f"/api/report/{bug}/file", ["html"])

# ---- 前端静态资源（缺失会白屏，且必须全本地，离线可演示）----
print("\n[0] 前端静态资源")
for asset in ("/", "/static/app.js", "/static/style.css",
              "/static/vendor/vue.global.prod.js", "/static/vendor/echarts.min.js"):
    ok, data = get(asset)
    if ok:
        PASS.append(f"[静态] {asset}")
        print(f"  ✓ {asset}")
    else:
        FAIL.append(f"[静态] {asset} -> {data}")
        print(f"  ✗ {asset}: {data}")

print("\n" + "=" * 62)
print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
if FAIL:
    print("-" * 62)
    for f in FAIL:
        print("  ✗", f)
    sys.exit(1)
print("全部通过")
