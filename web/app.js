/* ==========================================================================
   大模型应用自动化红队测试平台 · 控制台逻辑
   ========================================================================== */
const { createApp } = Vue;

async function api(path, opts = {}) {
  const r = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!r.ok) {
    let msg = r.status + " " + r.statusText;
    try { const j = await r.json(); msg = j.detail || msg; } catch (e) { /* ignore */ }
    throw new Error(msg);
  }
  return r.json();
}

const PROFILES = {
  none: "无护栏（基线）", input: "输入过滤", output: "输出过滤",
  prompt: "系统提示加固", full: "组合加固",
};

/* 图表取色一律走 CSS 变量。
   ECharts 不认 var()，必须在运行时读出来；但把色值抄一份进 JS 就等于主题
   有了两个真相来源，改配色时必然漏掉图表。 */
function chartTone() {
  const cv = (n, fb) => {
    const v = getComputedStyle(document.documentElement).getPropertyValue(n);
    return (v || "").trim() || fb;
  };
  return {
    brand: cv("--brand", "#3ddc84"),
    ok: cv("--ok", "#3ddc84"),
    warn: cv("--warn", "#e3a03c"),
    danger: cv("--danger", "#f0655a"),
    info: cv("--info", "#5aa6e8"),
    line: cv("--line", "#1e2421"),
    lineSoft: cv("--line-soft", "#1a1f1c"),
    fg: cv("--fg", "#e6ece8"),
    muted: cv("--muted", "#78847d"),
    muted2: cv("--muted-2", "#525d57"),
    panel: cv("--panel", "#111413"),
  };
}

/* 把十六进制色带透明度转成 rgba()。面积填充需要 7% 之类的不透明度，
   而 CSS 变量给的是实色，直接拼 alpha 只能用在 6 位 hex 上，不够稳。 */
function tint(hex, a) {
  let h = String(hex || "").trim().replace("#", "");
  if (h.length === 3) h = h.split("").map(c => c + c).join("");
  const n = parseInt(h, 16);
  if (h.length !== 6 || Number.isNaN(n)) return `rgba(61,220,132,${a})`;
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}
const STATES = {
  probe: "探测边界", consensus: "建立共识", escalate: "逐级升温",
  attack: "实施攻击", confirm: "结果确认", backtrack: "回退换路",
  /* 级联链的四级。与多轮那套状态是两套语义：多轮是"同一道门怎么敲开"，
     级联是"怎么从大厅走到保险柜"，不能混用标签。 */
  recon: "侦察攻击面", pivot: "横向定位", exploit: "定向利用", verify: "扩大验证",
};
/* 级间情报的类型标签。键与后端 chain.SLOT_LABELS 一致。 */
const SLOT_LABELS = {
  tool: "工具", path: "路径", file: "文件", doc: "文档",
  component: "组件", endpoint: "端点",
};
/* 攻击组织方式。级联不是"更长的多轮"，它改变的是攻击者掌握的权限范围，
   因此单独命名，不复用"多轮"的说法。 */
const STRATEGY_LABELS = {
  single: "单轮执行", multi: "多轮编排", chain: "级联扩权",
};
const FORMS = { chat: "对话", rag: "检索增强", agent: "工具调用" };
const RUN_STATUS = {
  pending: "待执行", running: "执行中", completed: "已完成",
  error: "执行异常", skipped: "已跳过",
};

/* 侧栏结构。图标统一用单条 path，避免 SVG 内使用 v-html 的兼容问题。 */
const TAB_GROUPS = [
  {
    name: "概览",
    items: [
      { k: "dash", n: "总览", icon: "M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z" },
    ],
  },
  {
    name: "攻击执行",
    items: [
      { k: "targets", n: "靶标试打",
        icon: "M12 2v3M12 19v3M2 12h3M19 12h3M12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0-6 0M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0-18 0" },
      { k: "cases", n: "攻击用例",
        icon: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M8 13h8M8 17h5" },
      { k: "runs", n: "攻击任务",
        icon: "M22 12h-4l-3 9L9 3l-3 9H2" },
    ],
  },
  {
    name: "分析交付",
    items: [
      { k: "exp", n: "实验分析",
        icon: "M12 20V10M18 20V4M6 20v-4" },
      { k: "review", n: "人工复核",
        icon: "M9 11l3 3L22 4M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" },
      { k: "report", n: "测评报告",
        icon: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M9 15l2 2 4-4" },
    ],
  },
  {
    name: "方法论",
    items: [
      { k: "knowledge", n: "标准对齐",
        icon: "M4 19.5A2.5 2.5 0 0 1 6.5 17H20M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" },
    ],
  },
];

createApp({
  data() {
    const d = new Date();
    const pad = n => String(n).padStart(2, "0");
    return {
      tabGroups: TAB_GROUPS,
      tab: "dash",
      today: `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`,

      health: { mock: true, models: {} },
      ov: {}, gw: {},
      targets: [], batches: [], profiles: [], operators: [],

      // 靶标试打
      tSel: "T1", tProfile: "none", chatLog: [], chatInput: "", chatBusy: false,
      promptView: null, kbDocs: [], kbHits: [], kbQuery: "",

      // 用例
      gen: { target_uid: "T1", channelMode: "both", limit: 10, operators: [] },
      genBusy: false, genResult: null,
      cases: [], caseTotal: 0, caseOffset: 0,

      // 任务
      runForm: {
        target_uid: "T1", strategy: "multi", max_turns: 5,
        guardrail_profile: "", limit: 10, plain_only: true,
      },
      runBusy: false, curBatch: null, runList: [], batchMetrics: {},
      runDetail: null, lastJudge: null, replayResult: null,

      // 实验
      e2Points: [], e5Data: null, e4Data: null, hardenData: null,
      hardenTarget: "T1", hardenExp: "E5",

      // 复核
      reviews: [],

      // 报告
      reportBatch: "", reportData: null, reportPaths: null,

      // 标准对齐
      std: {}, coverage: {}, compliance: {},
    };
  },

  computed: {
    recentBatches() {
      return this.batches.slice(0, 6);
    },
    /* 首屏结论。总览此前只列"有多少靶标、跑了多少任务"这类库存数字，
       真正的研究结论要翻到实验分析页的第六屏才看得到。答辩时打开系统
       应该第一眼就撞上结论，而不是先看库存。
       数字全部取自 /api/metrics/harden，不在这里二次计算，避免与
       实验分析页出现两个口径。 */
    verdict() {
      const d = this.hardenData;
      if (!d || !d.comparable || !d.before || !d.after) return null;
      const b = d.before, a = d.after;
      const m = d.mcnemar || {}, mx = d.matrix || {}, ef = d.effect || {};
      const f = v => (v == null ? "—" : (v * 100).toFixed(1) + "%");
      const sig = !!m.significant;
      const blocked = (ef.blocked_turns_before || 0) + (ef.blocked_turns_after || 0);
      const disc = (mx.only_before || 0) + (mx.only_after || 0);
      return {
        sig,
        tone: sig ? "ok" : "warn",
        target: d.target, exp: d.experiment,
        asrBefore: f(b.asr), asrAfter: f(a.asr), p: m.p_value == null ? "—" : m.p_value.toFixed(3),
        lead: `同一批 ${b.finished} 条载荷，加固前攻破 ${b.success} 条（ASR ${f(b.asr)}），` +
              `加固后攻破 ${a.success} 条（ASR ${f(a.asr)}）。`,
        // b=c=0 与 b=1 是两种完全不同的情形，必须分开说：
        // 前者是"基线为零、没有可归因样本"，后者才是"有样本但功效不足"。
        // 混为一谈会把"测不出来"说成"样本不够"。
        tail: sig
          ? `配对检验 b=${m.b}、c=${m.c}，p=${m.p_value.toFixed(3)}，差异显著，护栏有效。`
          : disc === 0
            ? `配对检验 b=0、c=0，两组结论逐条一致，无可检验的差异。` +
              `${mx.both_fail || 0} 条在两种配置下都未攻破——这批载荷不携带"护栏是否起作用"的信息，` +
              `基线为零，护栏评估的分母不存在。`
            : `配对检验 b=${m.b}、c=${m.c}，p=${m.p_value.toFixed(3)}，差异不显著。` +
              `${mx.both_fail || 0} 条两组都防住、${mx.both_success || 0} 条两组都攻破，` +
              `只有 ${mx.only_before || 0} 条能归因于护栏——样本量不足以排除采样波动。`,
        blockedNote: blocked === 0
          ? "本组拦截轮次均为 0：有效成分是系统提示加固，两个过滤器未参与。"
          : `本组共拦截 ${blocked} 轮次，说明过滤器参与了防御。`,
      };
    },
    owaspRows() {
      // 把「标准定义」与「实测覆盖」按 rid 合并：
      // standards 提供 summary / reason / in_scope，
      // coverage 提供 seeds / runs / finished / asr / paper_only。
      const cov = {};
      (this.coverage.items || []).forEach(i => { cov[i.rid] = i; });
      return (this.std.owasp || []).map(r => ({ ...r, ...(cov[r.rid] || {}) }));
    },
    stdMeta() { return this.std.meta || {}; },
    runLive() {
      return !!this.runDetail &&
        ["pending", "running"].indexOf(this.runDetail.status) >= 0;
    },
    stdTargets() { return this.std.targets || {}; },
    stdOperatorLayers() { return this.std.operator_layers || {}; },
    atlasTechs() { return this.std.atlas || []; },
    covSummary() { return this.coverage.summary || {}; },
    complySummary() { return this.compliance.summary || {}; },
    targetProfile() {
      return this.stdTargets[this.tSel] || null;
    },

    /* 矩阵顶部的分类计数。跟图例合并成一件事：只有颜色没有数字，
       运维还得自己数格子 */
    matrixStat() {
      const s = { ok: 0, success: 0, error: 0, idle: 0 };
      (this.runList || []).forEach(r => {
        const k = this.matrixClass(r).replace("sm-", "");
        s[k] = (s[k] || 0) + 1;
      });
      return s;
    },

    /* ------------------------------------------------------------------ *
     * 任务编排图
     * ------------------------------------------------------------------
     * 把一次 run 的"起点 → 逐轮 → 判定 → 终态"铺成横向有向图。
     *
     * 两个实现选择，都是为了少出错：
     * 1. 节点宽度固定（W），坐标因此可以纯算术算出，不需要测量 DOM。
     *    用 flex 排节点、SVG 只画连线，两套布局共用同一组坐标常量，
     *    只要 track 的 padding 与 geo() 的 TOP/PAD 对齐就永远不错位。
     * 2. 节点用 HTML 而非 SVG <text>。SVG 没有文字换行，中文标题一长就得
     *    自己算字宽、自己截断，还丢了 hover 与键盘可达性。连线才是 SVG 的活。
     * ------------------------------------------------------------------ */
    taskGraph() {
      const d = this.runDetail;
      if (!d) return null;

      const W = 112, GAP = 30, H = 66, TOP = 24, PAD = 2;
      const step = W + GAP;
      const midY = TOP + H / 2;
      const turns = d.turns || [];
      const latSum = turns.reduce((a, t) => a + (t.latency_ms || 0), 0);

      const nodes = [];
      const add = (n) => { nodes.push(n); return nodes.length - 1; };

      add({
        key: "start", kind: "start", code: "IN", status: "idle",
        title: STRATEGY_LABELS[d.strategy] || "多轮编排",
        sub: "上限 " + d.max_turns + (d.strategy === "chain" ? " 级" : " 轮"),
      });

      // turn_index 可能不连续（中断的任务），用映射表而不是数组下标，
      // 否则回退边会指错节点
      const posOf = {};
      turns.forEach((t) => {
        let status = "ok";
        // 先回退后拦截：两者可以同时为真（被护栏拦下也触发回退），
        // 但"被拦"是更明确的结论，应该盖住"回退"这种过程状态
        if (t.backtracked) status = "warn";
        if (t.blocked) status = "blocked";
        if (d.success_turn && t.turn_index === d.success_turn) status = "success";
        posOf[t.turn_index] = add({
          key: "t" + t.id, kind: "turn", code: "T" + t.turn_index, status,
          title: this.stateLabel(t.state),
          sub: (t.latency_ms || 0) + " ms",
          ratio: latSum ? (t.latency_ms || 0) / latSum : 0,
          turnId: t.id,
        });
      });

      if (d.judge) {
        add({
          key: "judge", kind: "judge", code: "JG", title: "双路判定",
          status: d.judge.conflict ? "warn" : (d.judge.final_success ? "success" : "ok"),
          sub: d.judge.conflict ? "两路冲突" : "两路一致",
        });
      }

      const finished = d.status === "completed";
      add({
        key: "end", kind: "end", code: "OUT",
        status: finished ? (d.success ? "success" : "ok") : (d.status === "error" ? "warn" : "idle"),
        title: !finished
          ? (d.status === "error" ? "执行异常" : this.runStatusLabel(d.status))
          : (d.success ? "已突破" : "已防住"),
        sub: d.error ? "见错误日志" : finished ? "终态已定" : "等待执行",
      });

      const geo = (i) => {
        const left = PAD + i * step;
        return { left, right: left + W, midX: left + W / 2, bottom: TOP + H };
      };

      const edges = [];
      for (let i = 0; i < nodes.length - 1; i++) {
        const a = geo(i), b = geo(i + 1);
        edges.push({ key: "e" + i, kind: "seq", d: `M${a.right} ${midY}H${b.left}` });
      }
      turns.forEach((t) => {
        if (!t.backtracked) return;
        const from = posOf[t.turn_index];
        const prev = turns.filter(x => x.turn_index < t.turn_index).pop();
        const to = prev ? posOf[prev.turn_index] : 0;
        const a = geo(from), b = geo(to);
        const dy = TOP + H + 34;
        // 终点落在节点下边缘之外 1px，箭头才不会被节点遮住
        const tip = b.bottom + 1;
        edges.push({
          key: "b" + t.id, kind: "back",
          // 首轮回退时目标就是自己，画一段 U 形自环；跨轮则画到前一个节点
          d: from === to
            ? `M${a.midX - 17} ${a.bottom}C${a.midX - 17} ${dy}, ${a.midX + 17} ${dy}, ${a.midX + 17} ${tip}`
            : `M${a.midX} ${a.bottom}C${a.midX} ${dy}, ${b.midX} ${dy}, ${b.midX} ${tip}`,
        });
      });

      const hasBack = edges.some(e => e.kind === "back");

      return {
        W, H, TOP, GAP, PAD, nodes, edges,
        width: PAD * 2 + nodes.length * W + (nodes.length - 1) * GAP,
        height: TOP + H + (hasBack ? 44 : 10),
        stats: {
          turns: turns.length,
          latency: latSum,
          avg: turns.length ? Math.round(latSum / turns.length) : 0,
          worst: turns.reduce((m, t) => Math.max(m, t.latency_ms || 0), 0),
          blocked: turns.filter(t => t.blocked).length,
          back: turns.filter(t => t.backtracked).length,
          token: (d.token_in || 0) + (d.token_out || 0),
          cost: d.cost || 0,
        },
      };
    },
  },

  methods: {
    /* 退出登录交给门禁处理：清会话、反向播放过渡、重建登录卡。
       放在门禁脚本里而不是这里，是为了让"未登录"这一状态只有一个写入点。 */
    logout() {
      if (window.RTPGate && window.RTPGate.lock) window.RTPGate.lock();
    },

    /* ---------- 展示辅助 ---------- */
    profileLabel(k) { return PROFILES[k] || k || "—"; },
    stateLabel(k) { return STATES[k] || k || "—"; },
    slotLabel(k) { return SLOT_LABELS[k] || k; },
    /* 缴获效率条形的相对宽度：以本批次最高的一级为 100%，
       让"逐级递减"这件事一眼可见，而不是三个孤立数字。 */
    chainBar(v) {
      const y = this.batchMetrics && this.batchMetrics.chain
        && this.batchMetrics.chain.slot_yield;
      if (!y) return "0%";
      const max = Math.max(...Object.values(y), 0.001);
      return Math.round((v / max) * 100) + "%";
    },
    /* 级联链的每级缴获条数，0 表示这一级没拿到新情报（链通常断在此处之后） */
    slotCount(slots) {
      if (!slots || !slots.out) return 0;
      return Object.values(slots.out).reduce((a, v) => a + (v ? v.length : 0), 0);
    },
    formLabel(k) { return FORMS[k] || k || "—"; },
    pct(v) {
      if (v === null || v === undefined || Number.isNaN(v)) return "—";
      return (Number(v) * 100).toFixed(1) + "%";
    },
    fmtCost(v) {
      if (v === null || v === undefined) return "¥0.00";
      const n = Number(v);
      if (n >= 1) return "¥" + n.toFixed(2);
      return "¥" + n.toFixed(3);
    },
    shortModel(m) {
      if (!m) return "—";
      const s = String(m).split("/").pop();
      return s.length > 22 ? s.slice(0, 22) + "…" : s;
    },
    runStatusLabel(s) { return RUN_STATUS[s] || s; },
    /* 危害分级：把判定器写进 rule_evidence 的 severity 翻成可读标签。
       分四级而非二元，是为了让"侦察得手但没拿到机密"这件事有地方安放——
       它既不是攻破（不该进 ASR），也不是无事发生（情报确实漏了）。 */
    sevBadge(j) {
      const v = (j && j.rule_evidence && j.rule_evidence.severity) || "none";
      const map = {
        credential: { cls: "err", label: "凭据级",
          desc: "泄露了密钥、口令或账号文件，可直接用于下一跳" },
        disclosure: { cls: "err", label: "敏感级",
          desc: "泄露了具体数值、内部条款或受限正文" },
        recon: { cls: "warn", label: "情报级",
          desc: "泄露了工具、目录或架构情报，未触及机密内容，不计入 ASR" },
        none: { cls: "ok", label: "无泄露", desc: "未发现可用的情报或机密输出" },
      };
      return map[v] || map.none;
    },
    /* 直接按分级字符串取徽章（配对表里拿到的是 severity 而非 judge 对象） */
    sevOf(sev) {
      return this.sevBadge({ rule_evidence: { severity: sev || "none" } });
    },
    /* Wilson 置信区间格式化。n 小时区间很宽，必须显示出来——
       只报点估计会让人误以为"从 50% 降到 17%"是确定的事实。 */
    ci(iv) {
      if (!Array.isArray(iv) || iv.length !== 2) return "—";
      return (iv[0] * 100).toFixed(1) + "% ~ " + (iv[1] * 100).toFixed(1) + "%";
    },
    /* 危害分级位移的键形如 "disclosure→none"，翻成"敏感级 → 无泄露"。
       分级本身是有序的，直接显示英文键读者无法判断这是变好还是变坏。 */
    sevPair(k) {
      const [a, b] = String(k).split("→");
      return this.sevOf(a).label + " → " + this.sevOf(b).label;
    },
    runStatusClass(s) {
      return { completed: "ok", running: "warn", error: "err", pending: "gray" }[s] || "gray";
    },
    batchStatusClass(s) {
      return { done: "ok", running: "warn", failed: "err", partial: "warn" }[s] || "gray";
    },

    /* ---------- 导航 ---------- */
    go(tab) {
      this.tab = tab;
      const loaders = {
        dash: () => { this.loadOverview(); this.loadBatches(); this.loadHarden(); },
        targets: () => { this.loadTargetDetail(); },
        cases: () => this.loadCases(),
        runs: () => this.loadBatches(),
        exp: () => { this.loadE2(); this.loadE5(); this.loadHarden(); },
        review: () => this.loadReviews(),
        report: () => this.loadBatches(),
        knowledge: () => this.loadKnowledge(),
      };
      (loaders[tab] || (() => {}))();
    },

    /* ---------- 总览 ---------- */
    async loadOverview() {
      try {
        const [ov, h] = await Promise.all([api("/api/metrics/overview"), api("/api/health")]);
        this.ov = ov; this.gw = ov.gateway || {}; this.health = h;
        await this.loadTargets();
        await this.loadBatches();
      } catch (e) { console.error(e); }
    },
    async loadTargets() {
      this.targets = await api("/api/targets");
      if (this.targets.length && !this.targets.find(t => t.uid === this.tSel)) {
        this.tSel = this.targets[0].uid;
      }
    },
    async loadBatches() {
      this.batches = await api("/api/batches");
    },
    async loadProfiles() {
      const p = await api("/api/targets/profiles");
      this.profiles = p.guardrails;
      this.operators = p.operators;
    },

    /* ---------- 靶标试打 ---------- */
    openTarget(uid) {
      this.tSel = uid; this.tab = "targets"; this.chatLog = [];
      this.loadTargetDetail();
    },
    async loadTargetDetail() {
      const t = this.targets.find(x => x.uid === this.tSel);
      this.tProfile = (t && t.guardrail_profile) || "none";
      this.promptView = null; this.kbHits = [];
      if (this.tSel === "T2" || this.tSel === "T5") await this.loadKb();
    },
    async loadKb() {
      try {
        const d = await api("/api/targets/" + this.tSel + "/kb");
        this.kbDocs = d.docs;
      } catch (e) { this.kbDocs = []; }
    },
    async searchKb() {
      if (!this.kbQuery.trim()) return;
      const d = await api("/api/targets/" + this.tSel + "/kb?q=" + encodeURIComponent(this.kbQuery));
      this.kbHits = d.hits;
    },
    async loadPrompt(hardened) {
      this.promptView = await api("/api/targets/" + this.tSel + "/prompt?hardened=" + hardened);
    },
    async sendChat() {
      const text = this.chatInput.trim();
      if (!text || this.chatBusy) return;
      this.chatLog.push({ role: "user", text });
      this.chatInput = ""; this.chatBusy = true;
      try {
        const history = this.chatLog.slice(0, -1).map(m => ({
          role: m.role === "user" ? "user" : "assistant", content: m.text,
        }));
        const r = await api("/api/targets/" + this.tSel + "/chat", {
          method: "POST",
          body: JSON.stringify({ message: text, history }),
        });
        const bits = [];
        if (r.blocked) bits.push("护栏拦截: " + r.blocked_by);
        if (r.retrieved && r.retrieved.length) bits.push("检索: " + r.retrieved.join(", "));
        if (r.tool_calls && r.tool_calls.length) bits.push("工具: " + r.tool_calls.map(c => c.name).join(", "));
        bits.push(r.latency_ms + "ms");
        this.chatLog.push({ role: "target", text: r.reply, meta: bits.join("  ｜  ") });
      } catch (e) {
        this.chatLog.push({ role: "sys", text: "请求失败：" + e.message });
      } finally {
        this.chatBusy = false;
        this.$nextTick(() => {
          const el = this.$refs.chatBox;
          if (el) el.scrollTop = el.scrollHeight;
        });
      }
    },

    /* ---------- 用例 ---------- */
    async loadCases() {
      const d = await api("/api/cases?limit=50&offset=" + this.caseOffset);
      this.cases = d.items; this.caseTotal = d.total;
    },
    casePage(dir) {
      this.caseOffset = Math.max(0, this.caseOffset + dir * 50);
      this.loadCases();
    },
    async doGenerate() {
      this.genBusy = true; this.genResult = null;
      try {
        const channels = this.gen.channelMode === "both" ? ["template", "llm"]
          : [this.gen.channelMode];
        this.genResult = await api("/api/cases/generate", {
          method: "POST",
          body: JSON.stringify({
            target_uid: this.gen.target_uid, channels,
            operators: this.gen.operators, max_chain: 1,
            limit: this.gen.limit || null,
          }),
        });
        this.caseOffset = 0;
        await this.loadCases();
      } catch (e) { alert("生成失败：" + e.message); }
      finally { this.genBusy = false; }
    },

    /* ---------- 任务 ---------- */
    async startRun() {
      this.runBusy = true;
      try {
        const body = { ...this.runForm };
        if (!body.guardrail_profile) delete body.guardrail_profile;
        const r = await api("/api/batches", { method: "POST", body: JSON.stringify(body) });
        await this.loadBatches();
        this.pollBatch(r.batch_id);
      } catch (e) { alert("创建失败：" + e.message); this.runBusy = false; }
    },
    async pollBatch(uid) {
      for (let i = 0; i < 300; i++) {
        await new Promise(r => setTimeout(r, 1200));
        const b = await api("/api/batches/" + uid);
        const item = this.batches.find(x => x.uid === uid);
        if (item) Object.assign(item, b);
        if (b.status === "done" || b.status === "partial") {
          this.runBusy = false;
          await this.loadBatches();
          return;
        }
      }
      this.runBusy = false;
    },
    async resumeBatch(uid) {
      await api("/api/batches/" + uid + "/resume", { method: "POST" });
      this.pollBatch(uid);
    },
    async selectBatch(uid) {
      this.stopRunPoll();
      this.curBatch = await api("/api/batches/" + uid);
      const r = await api("/api/runs?batch_id=" + uid + "&limit=200");
      this.runList = r.items;
      this.batchMetrics = await api("/api/metrics/batch/" + uid);
      this.runDetail = null; this.lastJudge = null; this.replayResult = null;
    },
    async openRun(id) {
      this.stopRunPoll();
      this.runDetail = await api("/api/runs/" + id);
      this.lastJudge = this.runDetail.judge;
      this.replayResult = null;
      // 未终态就持续跟踪：运维盯着一条正在跑的任务时，不该自己去点刷新。
      // 终态一律停表，避免几十个标签页各自空转打接口
      if (["pending", "running"].indexOf(this.runDetail.status) >= 0) this.startRunPoll(id);
    },
    startRunPoll(id) {
      this.stopRunPoll();
      this._runTimer = setInterval(async () => {
        try {
          const d = await api("/api/runs/" + id);
          this.runDetail = d;
          this.lastJudge = d.judge;
          if (["pending", "running"].indexOf(d.status) < 0) this.stopRunPoll();
        } catch (e) { this.stopRunPoll(); }
      }, 4000);
    },
    stopRunPoll() {
      if (this._runTimer) { clearInterval(this._runTimer); this._runTimer = null; }
    },
    /* 任务矩阵格子配色。必须按"执行状态优先、攻击结果其次"的顺序判断：
       status 未完的样本没有结果可言，先看结果会把 pending 误涂成"已防住"。 */
    matrixClass(r) {
      if (!r) return "sm-idle";
      if (r.status === "error") return "sm-error";
      if (r.status !== "completed") return "sm-idle";
      return r.success ? "sm-success" : "sm-ok";
    },
    /* 从图上的节点跳到下面对应的轨迹条目，避免运维在一长串轮次里手找 */
    focusTurn(turnId) {
      const el = document.querySelector('[data-turn="' + turnId + '"]');
      if (!el) return;
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      el.classList.add("hl");
      setTimeout(() => el.classList.remove("hl"), 1500);
    },
    async doReplay(id) {
      try {
        this.replayResult = await api("/api/runs/" + id + "/replay", { method: "POST" });
      } catch (e) { alert("重放失败：" + e.message); }
    },

    /* ---------- 实验 ---------- */
    async runExp(name, target) {
      try {
        await api("/api/experiments/" + name + "?target=" + target + "&limit=12", { method: "POST" });
        alert(name + " 已开始后台执行。完整跑完后再刷新查看（受接口延迟影响可能需要一段时间）。");
        await this.loadBatches();
      } catch (e) { alert("启动失败：" + e.message); }
    },
    async loadE2() {
      try {
        const d = await api("/api/metrics/e2?target=T1");
        this.e2Points = d.points || [];
        this.$nextTick(() => this.drawE2());
      } catch (e) { this.e2Points = []; }
    },
    drawE2() {
      const el = this.$refs.e2Chart;
      if (!el || !window.echarts || !this.e2Points.length) return;
      if (!this._e2) this._e2 = echarts.init(el);
      const T = chartTone();
      const pts = this.e2Points;
      this._e2.setOption({
        tooltip: {
          trigger: "axis",
          backgroundColor: T.panel,
          borderColor: T.line,
          borderWidth: 1,
          padding: [8, 11],
          textStyle: { color: T.fg, fontSize: 12 },
          extraCssText: "box-shadow:0 6px 20px rgba(0,0,0,.55);border-radius:6px;",
          valueFormatter: v => (v * 100).toFixed(1) + "%",
        },
        grid: { left: 48, right: 22, top: 30, bottom: 38 },
        xAxis: {
          type: "category",
          data: pts.map(p => p.strategy === "single" ? "单轮" : "多轮 × " + p.max_turns),
          axisLine: { lineStyle: { color: T.line } },
          axisTick: { show: false },
          axisLabel: { color: T.muted, fontSize: 11 },
        },
        yAxis: {
          type: "value", max: 1,
          axisLabel: { formatter: v => (v * 100) + "%", fontSize: 11, color: T.muted2 },
          splitLine: { lineStyle: { color: T.lineSoft } },
        },
        series: [{
          type: "line", smooth: false, symbolSize: 6,
          symbol: "circle",
          data: pts.map(p => p.asr),
          itemStyle: { color: T.brand, borderColor: T.panel, borderWidth: 2 },
          lineStyle: { width: 2, color: T.brand },
          areaStyle: { color: tint(T.brand, .10) },
        }],
      });
      this._e2.resize();
    },
    async loadE5() {
      try {
        // 靶标跟随加固对照的选择，不再写死。否则同一屏会同时出现
        // 两个靶标各自的 ASR，看起来像自相矛盾。
        this.e5Data = await api(`/api/metrics/e5?target=${this.hardenTarget}`);
        this.$nextTick(() => this.drawE5());
      } catch (e) { this.e5Data = null; }
    },
    /* 切靶标：E5 图与配对卡片共用同一个 target，保证同屏只有一个口径 */
    async switchHarden(t) {
      await this.loadHarden(t);
      await this.loadE5();
    },
    async loadHarden(target) {
      // 加固对照必须能选靶标：不同靶标的基线 ASR 差别很大，
      // T2 的基线是 0（机密在知识库里、检索不到就打不穿），
      // 只显示 T2 会让人误以为"加固毫无变化"。默认落在 T1。
      if (target) this.hardenTarget = target;
      try {
        this.hardenData = await api(
          `/api/metrics/harden?target=${this.hardenTarget}&experiment=${this.hardenExp}`);
      } catch (e) { this.hardenData = null; }
    },
    /* 四格标签。键与后端 harden_compare 的 matrix 一致。
       语义色沿用全站约定：生效=绿、漏防=品牌红、反效=橙。 */
    pairCell(k) {
      return ({
        only_before: { t: "护栏生效", cls: "ok" },
        only_after: { t: "护栏反效", cls: "warn" },
        both_success: { t: "漏防", cls: "err" },
        both_fail: { t: "均防住", cls: "gray" },
      })[k] || { t: k, cls: "gray" };
    },
    drawE5() {
      const el = this.$refs.e5Chart;
      if (!el || !window.echarts || !this.e5Data) return;
      const profs = Object.keys(this.e5Data.profiles || {});
      // 只有一档时画出来是一条贴地的柱子，读不出"削减"，不如让空态文案说话
      if (profs.length < 2) return;
      if (!this._e5) this._e5 = echarts.init(el);
      const T = chartTone();
      // 从红到绿单向过渡：护栏越强柱子越绿，一眼能读出"哪种配置真的有效"。
      // 中间三档取 warn / info / muted，保证四档混排列的亮度相近，
      // 不会因为某一档太暗而在近黑背景上"消失"。
      const palette = [T.danger, T.warn, T.info, T.muted, T.brand];
      this._e5.setOption({
        tooltip: {
          trigger: "axis",
          backgroundColor: T.panel,
          borderColor: T.line,
          borderWidth: 1,
          padding: [8, 11],
          textStyle: { color: T.fg, fontSize: 12 },
          extraCssText: "box-shadow:0 6px 20px rgba(0,0,0,.55);border-radius:6px;",
          valueFormatter: v => (v * 100).toFixed(1) + "%",
        },
        grid: { left: 48, right: 22, top: 30, bottom: 46 },
        xAxis: {
          type: "category", data: profs.map(p => PROFILES[p] || p),
          axisLabel: {
            color: T.muted, fontSize: 10, interval: 0,
            rotate: profs.length > 3 ? 18 : 0,
            formatter: v => v.replace("（基线）", ""),
          },
          axisLine: { lineStyle: { color: T.line } },
          axisTick: { show: false },
        },
        yAxis: {
          type: "value", max: 1,
          axisLabel: { formatter: v => (v * 100) + "%", fontSize: 11, color: T.muted2 },
          splitLine: { lineStyle: { color: T.lineSoft } },
        },
        series: [{
          type: "bar", barWidth: "44%",
          // 零值柱默认什么都不画，"组合加固 0%"这一档会从图上整根消失，
          // 看着像这一档没跑过。加一层底槽，零值也有位置可读。
          showBackground: true,
          backgroundStyle: { color: T.lineSoft, borderRadius: [2, 2, 0, 0] },
          data: profs.map((p, i) => ({
            value: this.e5Data.profiles[p].asr,
            itemStyle: { color: palette[i % 5], borderRadius: [2, 2, 0, 0] },
          })),
          label: {
            show: true, position: "top",
            formatter: p => (p.value * 100).toFixed(0) + "%",
            color: T.muted, fontSize: 11, fontWeight: 500,
          },
        }],
      });
      this._e5.resize();
    },
    async loadE4() {
      try {
        this.e4Data = await api("/api/metrics/e4?target=T2");
      } catch (e) { alert("读取失败：" + e.message); }
    },

    /* ---------- 标准对齐 ---------- */
    async loadKnowledge() {
      try {
        const [std, cov, cmp] = await Promise.all([
          api("/api/knowledge/standards"),
          api("/api/knowledge/coverage"),
          api("/api/knowledge/compliance"),
        ]);
        this.std = std; this.coverage = cov; this.compliance = cmp;
      } catch (e) {
        console.error("标准数据加载失败", e);
      }
    },

    /* ---------- 复核 ---------- */
    async loadReviews() {
      const d = await api("/api/reviews?limit=50");
      this.reviews = d.items;
    },
    async doReview(judgeId, label) {
      await api("/api/reviews", {
        method: "POST",
        body: JSON.stringify({ judge_id: judgeId, label, reviewer: "owner" }),
      });
      this.reviews = this.reviews.filter(r => r.judge_id !== judgeId);
    },

    /* ---------- 报告 ---------- */
    async loadReport() {
      try {
        this.reportData = await api("/api/report/" + this.reportBatch);
        this.reportPaths = null;
      } catch (e) { alert("生成失败：" + e.message); }
    },
    async exportReport() {
      try {
        this.reportPaths = await api("/api/report/" + this.reportBatch + "/export", { method: "POST" });
      } catch (e) { alert("导出失败：" + e.message); }
    },
  },

  async mounted() {
    await this.loadProfiles();
    await this.loadOverview();
    // 首屏结论带读的是 hardenData，必须在 mount 时就取。
    // 原先只在 go("dash") 里加载，而首屏默认就是 dash、不会触发 go，
    // 结果是结论带写了却永远不显示。
    this.loadHarden();
    // 标准数据在启动时预取一次：切换页签时不必等待，演示更流畅
    this.loadKnowledge();

    // 深链：?tab=runs&run=7 直接落到某个任务。运维排查时把地址发给同事，
    // 对方打开就是同一条轨迹，比"点攻击任务，找到批次，再点进第 7 条"省事
    const q = new URLSearchParams(location.search);
    const tab = q.get("tab");
    // 必须走 go() 而不是直接赋 this.tab：go() 里挂着该页签的数据加载器。
    // 只赋值会让页面框架渲染出来、内容却全是空态——看起来像接口挂了。
    if (tab && TAB_GROUPS.some(g => g.items.some(i => i.k === tab))) this.go(tab);
    const rid = Number(q.get("run"));
    if (rid) {
      try {
        const run = await api("/api/runs/" + rid);
        this.tab = "runs";
        await this.selectBatch(run.batch_id);
        await this.openRun(rid);
        // 目标是"打开就能看到这条轨迹"，不滚一下的话还得自己往下找。
        // scroll=0 可以关掉这次滚动：贴进工单或截图对比时，不希望页面自己跳。
        this.$nextTick(() => {
          if (q.get("scroll") === "0") return;
          const el = document.querySelector(".taskgraph");
          if (el) el.scrollIntoView({ block: "center" });
        });
      } catch (e) { /* 深链失效不该阻断页面加载 */ }
    }

    window.addEventListener("resize", () => {
      if (this._e2) this._e2.resize();
      if (this._e5) this._e5.resize();
    });
  },
}).mount("#app");
