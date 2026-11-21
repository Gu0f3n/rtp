# rtp — 面向大模型应用的自动化红队测试平台

> 别人测模型会不会被越狱，rtp 测 **Agent 会不会被劫持**。

rtp 是一个开箱即用的 LLM 应用安全测试平台：对**自建靶标应用**（对话客服 / RAG 知识库 / 工具 Agent）执行自动化红队测试，用双路交叉判定（规则 + LLM）给出可复现的攻击成功率与危害分级。

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
![Mock](https://img.shields.io/badge/Offline-Mock%20Mode-orange)

**为什么不是又一个 Prompt Fuzz 工具？** 现有开源工具大多把"模型"当被测对象，拿一堆越狱模板轰炸裸模型。rtp 的立场不同：真实危害发生在**应用层**——RAG 知识库被投毒、Agent 工具被滥用、系统提示被套取。rtp 把"带业务上下文的靶标应用"当被测对象，测的是护栏、检索链路、工具权限这些真实防线。

## 核心能力

### 1. 三类靶标形态（T1/T2/T3）

| 靶标 | 形态 | 模拟的真实防线 |
|---|---|---|
| T1 对话式客服 | chat | 系统提示约束、输出过滤 |
| T2 RAG 知识库 | rag | BM25 检索链路、知识库访问控制 |
| T3 办公 Agent | agent | 文件读取、邮件外发、数据库查询的工具权限 |

T5 = T2 + 全护栏配置的同构视图，专为"护栏前后对照"实验设计。

### 2. 攻击载荷库（覆盖 OWASP LLM Top 10）

- **提示注入**：直接注入 / 角色扮演 / 逻辑绑架 / 虚构包装
- **间接注入 + RAG 动态投毒**：三代载荷（PoisonedRAG 直白指令 → ToxicRAG 知识更新叙事 → InceptionRAG 休眠段落），支持 query 锚定与投毒密度扫描
- **成本放大攻击**（LLM10）：ThinkTrap 思维链绑架 / RECUR 递归自问 / OverThink 伪严谨诱导
- **攻击面侦察**：工具枚举、文档目录、组件指纹（单独计 `recon_rate`，不与 ASR 混算）
- **系统提示套取、越权工具调用、不当输出** 等共 80+ 种子

### 3. 三种攻击组织方式

单轮直取 / 多轮渐进（probe → consensus → escalate → attack，带回溯）/ 级联扩权（recon → pivot → exploit → verify，级间规则提取器）。

### 4. 双路交叉判定（C3）

- **规则路**：零成本、确定性，带危害分级轴 `none < recon < disclosure < credential`
- **LLM 路**：语义理解，能识别"拒绝时复述敏感词是防御不是泄露"
- 冲突不自动裁决 → 标记人工复核，报告 Kappa 系数与冲突率
- 特化证据维度：`amplification`（成本放大形态学证据）、投毒检索完整性

### 5. 指标体系

ASR（攻击成功率）、recon_rate（侦察率）、amp_rate（成本放大率）、severity 分布、McNemar 精确检验、Wilson 区间、护栏逐层边际贡献、国标 GB/T 45654-2025 合规对照。

## 快速开始

```bash
# 1. 安装（Python 3.10+）
pip install -r requirements.txt

# 2. 配置
cp .env.example .env
# 编辑 .env：填 LLM_BASE_URL / LLM_API_KEY，或留空 key 直接体验 mock 模式

# 3. 初始化
python scripts/init_db.py

# 4. 启动
python -m uvicorn app.main:app --host 127.0.0.1 --port 8017

# 5. 打开 http://127.0.0.1:8017 （演示账号 admin / rtp2026）
```

**没有 API Key 也能跑**：`MOCK_MODE=on` 走内置模拟器，全部功能可离线体验（产出数据仅供演示，不具实验效力）。

### 一分钟体验 RAG 投毒

```bash
# 注入 2 篇 ToxicRAG 式投毒文档（锚定"薪酬 职级"主题）
python scripts/poison_kb.py --inject --gen 2 -n 2 --anchor "薪酬 职级 等级"

# 零模型调用检索探针：看投毒文档如何挤占检索位
python scripts/poison_probe.py --sweep

# 清除投毒，恢复干净库
python scripts/poison_kb.py --clean
```

服务运行中注入/清除即时生效（检索索引按 KB 目录 mtime 自动失效）。

## 项目结构

```
rtp/
├── app/
│   ├── targets/        # 三类靶标实现 + 种子库（80+ 载荷）+ BM25 检索器
│   ├── engines/        # 生成器 / 编排器 / 级联链 / 双路判定器
│   ├── runner/         # 批次执行与指标计算
│   ├── api/            # FastAPI 路由（靶标交互 / 实验 / 指标 / 报告）
│   ├── knowledge/      # OWASP / MITRE ATLAS / 国标结构化数据
│   └── core/           # 模型网关（缓存/限流/mock）与模拟器
├── scripts/            # 实验与运维脚本（投毒注入器、探针、复核回写等）
├── web/                # 前端（暗色主题仪表盘）
└── data/               # 运行时生成（不入库）
```

## 威胁覆盖矩阵（OWASP LLM Top 10）

| OWASP 条目 | 覆盖状态 | 实现方式 |
|---|---|---|
| LLM01 提示注入 | ✅ 实测 | 直接/间接注入、逻辑绑架、RAG 投毒触发 |
| LLM02 敏感信息泄露 | ✅ 实测 | 薪酬/成本/并购题材靶标 + 值感知判定 |
| LLM05 不当输出处理 | ✅ 实测 | XSS/格式注入载荷 |
| LLM06 过度代理 | ✅ 实测 | 工具滥用、外发、删除类载荷（T3） |
| LLM07 系统提示泄露 | ✅ 实测 | 复述诱导 + 特征串判定 |
| LLM08 检索弱点 | ✅ 实测 | 三代 RAG 投毒 + query 锚定 + 检索位次控制 |
| LLM10 无界消费 | ✅ 实测 | 成本放大三手法 + amplification 证据维度 |
| LLM03 训练数据 | ⚠️ 部分覆盖 | 仅检索层模拟投毒 |
| LLM04 服务滥用 | ❌ 不在范围 | 属容量治理 |
| LLM09 虚假信息 | ❌ 不在范围 | 需领域事实基准 |

实时覆盖数据由 `/api/knowledge/coverage` 接口计算（含"纸面覆盖 vs 实测覆盖"区分）。

## 方法论声明（伦理边界）

- 所有靶标为**自建模拟应用**，不针对任何真实系统
- "工具执行"为模拟实现（`FAKE_FS` / 模拟邮件），论文语境即"受控模拟执行"
- 机密值全部虚构；手机号等样例数据已脱敏
- 平台仅通过标准 OpenAI 兼容 API 调用模型，不做任何模型逆向

## 已知边界（诚实清单）

- 检索器是 BM25（中文 bigram），非向量检索——这是刻意选择：零依赖、结果可解释，且 BM25 对关键词重合型投毒的脆弱性正是可复现的实验点
- 护栏为 6 条输入正则 + 6 条输出正则，无模型调用——有效防线实测是系统提示加固而非过滤器（见实验结论）
- 登录为前端门禁（演示凭据），API 无鉴权，请勿直接暴露公网
- SQLite 单文件存储，适合单机实验，非生产部署方案

## License

MIT
