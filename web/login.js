/* ==========================================================================
   登录门禁
   --------------------------------------------------------------------------
   与 Vue 应用完全解耦：本文件只做四件事——校验、切 <html> 上的状态类、
   触发进场/退场动画、记住会话。不读写任何组件内部状态，也不 import app.js。

   会话存两处：
     localStorage  —— 勾了"保持登录"，关浏览器仍在
     sessionStorage —— 没勾，关标签页即失效
   ========================================================================== */
(function () {
  "use strict";

  const KEY = "rtp.session";
  const DEMO_USER = "admin";
  const DEMO_PASS = "rtp2026";
  /* 本地校验是同步的，几百毫秒内就结束。若不加下限，加载态一闪而过，
     看起来像"卡了一下然后页面变了"；给一个短下限让状态可被感知。 */
  const MIN_BUSY = 460;

  const html = document.documentElement;
  const gate = document.getElementById("gate");
  const app = document.getElementById("app");
  const form = document.getElementById("loginForm");
  if (!gate || !form) return;

  const userEl = form.querySelector("#lgUser");
  const passEl = form.querySelector("#lgPass");
  const keepEl = form.querySelector("#lgKeep");
  const pwBtn = form.querySelector("#pwToggle");
  const capsEl = form.querySelector("#capsHint");
  const alertEl = form.querySelector("#lgErr");
  const alertText = form.querySelector("#lgErrText");
  const submitEl = form.querySelector("#lgSubmit");
  const card = form.closest(".gate-card");

  let busy = false;
  let shakeTimer = null;

  /* ---------------- 会话 ---------------- */
  function readSession() {
    try {
      return localStorage.getItem(KEY) || sessionStorage.getItem(KEY) || null;
    } catch (e) {
      return null;
    }
  }
  window.RTPGate = {
    isAuthed: () => !!readSession(),
    lock,
  };

  /* ---------------- 校验 ---------------- */
  const RULES = {
    username(v) {
      if (!v) return "请输入用户名";
      if (v.length < 3) return "用户名至少 3 个字符";
      if (!/^[A-Za-z0-9._-]{3,32}$/.test(v)) return "仅支持字母、数字与 . _ -";
      return "";
    },
    password(v) {
      if (!v) return "请输入密码";
      if (v.length < 6) return "密码至少 6 位";
      return "";
    },
  };

  function fieldOf(name) {
    return form.querySelector(`.field[data-field="${name}"]`);
  }

  function setErr(name, msg) {
    const box = fieldOf(name);
    if (!box) return;
    const slot = box.querySelector(".field-err");
    const input = box.querySelector("input");
    box.classList.toggle("has-err", !!msg);
    slot.textContent = msg || "";
    if (msg) input.setAttribute("aria-invalid", "true");
    else input.removeAttribute("aria-invalid");
  }

  function setFormErr(msg) {
    if (!msg) {
      alertEl.classList.remove("on");
      alertText.textContent = "";
      return;
    }
    alertText.textContent = msg;
    alertEl.classList.add("on");
  }

  function setBusy(on) {
    busy = on;
    card.classList.toggle("is-busy", on);
    submitEl.disabled = on;
    submitEl.setAttribute("aria-busy", on ? "true" : "false");
    userEl.readOnly = on;
    passEl.readOnly = on;
  }

  function shake() {
    card.classList.remove("shake");
    /* 强制回流，否则连续两次失败时动画不会重新播放 */
    void card.offsetWidth;
    card.classList.add("shake");
    clearTimeout(shakeTimer);
    shakeTimer = setTimeout(() => card.classList.remove("shake"), 460);
  }

  /* 用户开始改输入就撤掉对应错误，避免"已经改对了还红着" */
  ["username", "password"].forEach((name) => {
    const input = name === "username" ? userEl : passEl;
    input.addEventListener("input", () => {
      setErr(name, "");
      setFormErr("");
    });
  });

  /* ---------------- 大写锁定提示 ---------------- */
  function checkCaps(e) {
    if (!e.getModifierState) return;
    capsEl.classList.toggle("on", e.getModifierState("CapsLock"));
  }
  passEl.addEventListener("keydown", checkCaps);
  passEl.addEventListener("keyup", checkCaps);
  passEl.addEventListener("blur", () => capsEl.classList.remove("on"));

  /* ---------------- 密码可见性 ---------------- */
  pwBtn.addEventListener("click", () => {
    const shown = pwBtn.getAttribute("aria-pressed") === "true";
    pwBtn.setAttribute("aria-pressed", shown ? "false" : "true");
    pwBtn.setAttribute("aria-label", shown ? "显示密码" : "隐藏密码");
    passEl.type = shown ? "password" : "text";
  });

  /* ---------------- 服务状态 ---------------- */
  (function probeHealth() {
    const dot = document.getElementById("gaHealth");
    const txt = document.getElementById("gaHealthText");
    if (!dot || !txt) return;
    fetch("/api/health", { headers: { Accept: "application/json" } })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((h) => {
        dot.classList.add("on");
        txt.textContent = h && h.mock ? "服务在线 · MOCK 模式" : "服务在线 · 真实模型";
      })
      .catch(() => {
        dot.classList.add("off");
        txt.textContent = "服务未连接 · 仅界面可用";
      });
  })();

  /* ---------------- 进场 ---------------- */
  function enter(user) {
    try {
      const rec = JSON.stringify({ u: user, t: Date.now(), v: 1 });
      if (keepEl.checked) {
        localStorage.setItem(KEY, rec);
        sessionStorage.removeItem(KEY);
      } else {
        sessionStorage.setItem(KEY, rec);
        localStorage.removeItem(KEY);
      }
    } catch (e) {
      /* 隐私模式下 storage 可能抛错，此时按"不记住"处理，不影响进入 */
    }

    /* 三段衔接，总时长约 720ms，且两段有重叠——重叠是刻意的：
       门禁淡出到一半时主界面已经开始浮现，两者叠加后总亮度几乎不变，
       眼睛看到的是"一层退、一层进"，而不是"先黑一下再亮起来"。
       0ms   卡片淡出 + 门禁整体后退（scale 1 → 1.028）
       170ms 主界面转为可见，顶栏与内容区分层入场
       620ms 门禁彻底移除（此时早已透明，只是为了不再接事件）      */
    gate.classList.add("is-out");

    setTimeout(() => {
      html.classList.remove("is-booting");
      app.classList.add("app-enter");
      app.addEventListener("animationend", function done(ev) {
        if (ev.target !== app.querySelector(".shell")) return;
        app.classList.remove("app-enter");
        app.removeEventListener("animationend", done);
      });
    }, 170);

    setTimeout(() => {
      html.classList.add("has-session");
      gate.classList.add("done");
      setBusy(false);
    }, 620);

    /* 兜底：animationend 在极端情况下可能不触发（例如标签页在后台被节流），
       留一个长的安全网，避免 app-enter 类永久挂在根节点上。 */
    setTimeout(() => app.classList.remove("app-enter"), 1800);
  }

  /* ---------------- 退场（退出登录） ---------------- */
  function lock() {
    try {
      localStorage.removeItem(KEY);
      sessionStorage.removeItem(KEY);
    } catch (e) { /* ignore */ }

    app.classList.remove("app-enter");
    app.classList.add("app-exit");
    html.classList.remove("has-session");
    gate.classList.remove("is-out", "done", "is-in");
    void gate.offsetWidth;
    gate.classList.add("is-in");

    setTimeout(() => {
      html.classList.add("is-booting");
      app.classList.remove("app-exit");
      setBusy(false);
      setFormErr("");
      setErr("username", "");
      setErr("password", "");
      passEl.value = "";
      passEl.type = "password";
      pwBtn.setAttribute("aria-pressed", "false");
      userEl.focus({ preventScroll: true });
    }, 300);
  }

  /* ---------------- 提交 ---------------- */
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (busy) return;

    const u = userEl.value.trim();
    const p = passEl.value;
    const e1 = RULES.username(u);
    const e2 = RULES.password(p);

    setErr("username", e1);
    setErr("password", e2);
    setFormErr("");

    if (e1 || e2) {
      (e1 ? userEl : passEl).focus();
      return;
    }

    setBusy(true);
    const t0 = performance.now();
    await new Promise((r) => setTimeout(r, MIN_BUSY));
    const waited = performance.now() - t0;

    if (u.toLowerCase() === DEMO_USER && p === DEMO_PASS) {
      /* 下限已等过，这里不再补时，避免总计拖到 1s 以上 */
      enter(u);
      return;
    }

    /* 失败：先复位按钮，再抖一下并把焦点送回密码框 */
    setBusy(false);
    setFormErr(
      waited > MIN_BUSY + 300
        ? "用户名或密码错误（服务响应较慢，请稍后重试）"
        : "用户名或密码错误，请检查后重试"
    );
    shake();
    passEl.select();
    passEl.focus();
  });

  /* 已登录状态（刷新后直接进场）时，把会话信息留给控制台 */
  if (!html.classList.contains("is-booting")) {
    gate.classList.add("done");
    try {
      const s = JSON.parse(readSession() || "null");
      if (s && s.u) document.documentElement.dataset.user = s.u;
    } catch (e) { /* ignore */ }
  } else {
    /* 首次进入：等一帧再聚焦，避免页面还在排版时抢焦点导致轻微跳动 */
    requestAnimationFrame(() => userEl.focus({ preventScroll: true }));
  }
})();
