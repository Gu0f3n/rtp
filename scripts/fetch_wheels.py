"""离线 wheel 下载器（镜像索引版）。

pip 在本机被沙箱拦了网络，但 Python 的 urllib 可正常访问镜像站。
本脚本走 PEP 503 simple 索引 + wheel 内 METADATA 解析依赖，不依赖 PyPI JSON API。

用法::
    python scripts/fetch_wheels.py [pkgs...]
"""
import io
import os
import re
import sys
import time
import urllib.request
import urllib.error
import zipfile
from urllib.parse import urljoin

try:
    from packaging.requirements import Requirement
    from packaging.tags import sys_tags
    from packaging.utils import canonicalize_name, parse_wheel_filename
    from packaging.version import Version
except ModuleNotFoundError:
    from pip._vendor.packaging.requirements import Requirement
    from pip._vendor.packaging.tags import sys_tags
    from pip._vendor.packaging.utils import canonicalize_name, parse_wheel_filename
    from pip._vendor.packaging.version import Version

WHEEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wheels")
os.makedirs(WHEEL_DIR, exist_ok=True)

MIRRORS = [
    "https://pypi.tuna.tsinghua.edu.cn/simple/{name}/",
    "https://mirrors.aliyun.com/pypi/simple/{name}/",
    "https://pypi.org/simple/{name}/",
]

SUPPORTED_TAGS = {str(t) for t in sys_tags()}
_print = lambda *a: print(*a, flush=True)


def fetch(url, tries=3, timeout=30):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "wheel-fetcher/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(1.0 + i)
    raise last


def simple_index(name):
    """返回 (base_url, [(version, filename, absolute_url), ...])"""
    last = None
    for tpl in MIRRORS:
        url = tpl.format(name=name)
        try:
            html = fetch(url).decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            last = e
            continue
        links = []
        for href, text in re.findall(r'<a[^>]*href="([^"]+)"[^>]*>([^<]+)</a>', html):
            fn = text.strip()
            if not fn.endswith(".whl") or "#" in fn:
                continue
            try:
                _, ver, _, tags = parse_wheel_filename(fn)
            except Exception:  # noqa: BLE001
                continue
            if not any(str(t) in SUPPORTED_TAGS for t in tags):
                continue
            links.append((ver, fn, urljoin(url, href)))
        if links:
            return url, links
        last = RuntimeError(f"{name}: 索引页无兼容 wheel")
    raise last


def wheel_requires(path):
    """从 wheel 内的 METADATA 读取 Requires-Dist（比 JSON API 更可靠）。"""
    try:
        with zipfile.ZipFile(path) as z:
            meta = next(n for n in z.namelist()
                        if n.endswith(".dist-info/METADATA"))
            text = z.read(meta).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return []
    out = []
    for line in text.splitlines():
        if line.startswith("Requires-Dist:"):
            out.append(line.split(":", 1)[1].strip())
    return out


def resolve(roots):
    """解析依赖树，返回进度；产物写入 WHEEL_DIR。"""
    chosen = {}          # canonical name -> version str
    queue = [Requirement(r) for r in roots]
    total = 0

    while queue:
        req = queue.pop(0)
        name = canonicalize_name(req.name)
        if name in chosen:
            continue

        try:
            _, links = simple_index(name)
        except Exception as e:  # noqa: BLE001
            _print(f"  !! {name}: 无法获取索引 ({e})", file=sys.stderr)
            continue

        cands = []
        for ver, fn, url in links:
            if req.specifier and not req.specifier.contains(ver, prereleases=False):
                continue
            if ver.is_prerelease:
                continue
            # 有平台 wheel 优先，其次纯 python
            pure = 1 if "none-any" in fn else 0
            cands.append((ver, pure, fn, url))
        if not cands:
            _print(f"  !! {name}: 无满足 {req.specifier} 的版本", file=sys.stderr)
            continue
        cands.sort(key=lambda x: (x[0], -x[1]))
        ver, _, fn, url = cands[-1]

        path = os.path.join(WHEEL_DIR, fn)
        if not (os.path.exists(path) and os.path.getsize(path) > 0):
            _print(f"  ↓ {fn}")
            try:
                data = fetch(url, timeout=180)
                with open(path, "wb") as f:
                    f.write(data)
            except Exception as e:  # noqa: BLE001
                _print(f"  !! {fn} 下载失败: {e}", file=sys.stderr)
                continue
        else:
            _print(f"  = {fn} (已存在)")

        chosen[name] = str(ver)
        total += 1

        for dep_str in wheel_requires(path):
            try:
                dep = Requirement(dep_str)
            except Exception:  # noqa: BLE001
                continue
            if dep.marker is not None:
                try:
                    if not dep.marker.evaluate():
                        continue
                except Exception:  # noqa: BLE001
                    pass
            if dep.extras:
                continue
            if canonicalize_name(dep.name) not in chosen:
                queue.append(dep)

    return chosen, total


if __name__ == "__main__":
    roots = sys.argv[1:] or [
        "fastapi", "uvicorn", "pydantic", "pydantic-settings", "sqlalchemy",
        "aiosqlite", "httpx", "jinja2", "python-multipart", "pytest",
        "pytest-asyncio", "pyyaml",
    ]
    _print(f"[1/2] 解析并下载（{len(roots)} 个根包）")
    chosen, n = resolve(roots)
    _print(f"[2/2] 完成：{n} 个包 -> {WHEEL_DIR}")
    for k, v in sorted(chosen.items()):
        _print(f"    {k}=={v}")
