"""真实链路连通性探针。

在跑任何正式实验之前先用它确认三件事：
1. 本地代理可达、路径拼接正确（/v1/chat/completions）
2. 三级模型（target / attack / judge）各自都能出结果，不是只有一档通
3. 单次调用延迟与 token 消耗量级，用于校准限流与预算

用法：
    python scripts/probe.py
    python scripts/probe.py --model deepseek/deepseek-v4-flash   # 只测指定模型
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings
from app.core.gateway import gateway


async def probe(role: str, tier) -> bool:
    name = f"{role:6s} {tier.model}"
    t0 = time.perf_counter()
    try:
        r = await gateway.chat(
            [{"role": "user", "content": "只回复两个字：收到"}],
            role=role, temperature=0.0, use_cache=False, max_tokens=512)
    except Exception as e:  # noqa: BLE001
        print(f"  ✗ {name}  {type(e).__name__}: {str(e)[:200]}")
        return False
    ms = int((time.perf_counter() - t0) * 1000)
    if not r.text.strip():
        print(f"  ✗ {name}  {ms}ms  正文为空（推理可能烧光了 token 预算）")
        return False
    preview = r.text.strip().replace("\n", " ")[:40]
    think = f" 推理{r.reasoning_tokens}t" if r.reasoning_tokens else ""
    trunc = "  ⚠截断" if r.truncated else ""
    print(f"  ✓ {name}  {ms}ms  in={r.token_in} out={r.token_out}{think}  「{preview}」{trunc}")
    return True


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", help="只测这一个模型（覆盖三级路由）")
    args = ap.parse_args()

    print("=" * 66)
    print("真实链路探针")
    print("=" * 66)
    print(f"  网关地址   {settings.llm_base_url}")
    print(f"  密钥       {'已配置 ' + settings.llm_api_key[:6] + '…' if settings.llm_api_key else '未配置'}")
    print(f"  运行模式   {'MOCK（不会产生真实调用）' if settings.use_mock else 'REAL'}")

    if settings.use_mock:
        print("\n未配置密钥，链路无法验证。请在 rtp/.env 中填写 LLM_API_KEY 后重试。")
        print("该代理不落密钥，必须每个请求带 Authorization: Bearer <key>。")
        return 2

    roles = ["target", "attack", "judge"]
    if args.model:
        for r in roles:
            settings.tier(r).model = args.model

    print("\n逐档探测：")
    results = [await probe(r, settings.tier(r)) for r in roles]

    s = gateway.stats
    print("\n本次消耗：")
    print(f"  调用 {s.calls} 次，失败 {s.failures} 次")
    print(f"  token {s.token_in}/{s.token_out}，估算 ¥{s.as_dict(settings.use_mock)['cost']:.6f}")

    ok = all(results)
    print("\n" + ("全部通过，可以跑正式实验。" if ok else "存在失败档位，先修通再跑实验。"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
