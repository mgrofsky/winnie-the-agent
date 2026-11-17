// Operator console front-end.
//
// Everything this page shows was typed by attackers, so the rules are strict and simple:
// - DOM is built only with createElement and textContent (the el() helper below). There is
//   no HTML parsing anywhere in this file.
// - Data never becomes an attribute. The exceptions: record, approval, digest, detection
//   and honeytoken names that match the server's own patterns may build in-app routes or
//   API paths, and a few fixed sets (judgement, status, tier, transcript role) choose a CSS
//   class through a lookup table. Timestamps become a title only after they parse as dates.
// - State lives in memory and in the URL hash. Nothing is stored in the browser.
//
// Layout of this file: constants, DOM and format helpers, the API client, shared widgets,
// the shell (header, router, polling), then one function per screen.

"use strict";

(function () {
  // ---- constants ------------------------------------------------------------------------

  const POLL_MS = 30000;
  const LOADING_DELAY_MS = 250;
  const REVEAL_MS = 60000;
  const STALE_WARN_HOURS = 6;
  const STALE_BAD_HOURS = 24;
  const PER_PAGE = 50;
  const TRANSCRIPT_PER = 100;

  // Same patterns the server enforces (agents/ui/api.py).
  const RECORD_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;
  const APPROVAL_ID_RE = /^a-[0-9a-f]{12}$/;
  const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
  const DETECTION_RE = /^[0-9a-f]{8}-[a-z0-9-]{1,60}\.yml$/;
  const TOKEN_NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/;
  const PROTOCOL_RE = /^[a-z0-9]{1,16}$/;
  const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;
  const COMPACT_TIME_RE = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/;

  // Every API path this page requests. Ids are checked against their pattern by the caller
  // and URL-encoded here as well.
  const enc = encodeURIComponent;
  const API = {
    session: "/api/session",
    overview: "/api/overview",
    records: "/api/records",
    record: (id) => "/api/records/" + enc(id),
    transcript: (id) => "/api/records/" + enc(id) + "/transcript",
    queue: "/api/queue",
    approve: (id) => "/api/queue/" + enc(id) + "/approve",
    reject: (id) => "/api/queue/" + enc(id) + "/reject",
    blocklist: "/api/blocklist",
    unblock: "/api/blocklist/unblock",
    digests: "/api/digests",
    digest: (day) => "/api/digests/" + enc(day),
    decoy: "/api/decoy",
    playbooks: "/api/playbooks",
    detections: "/api/detections",
    detection: (kind, name) => "/api/detections/" + enc(kind) + "/" + enc(name),
    honeytokens: "/api/honeytokens",
  };

  const JUDGEMENTS = ["BENIGN", "SUSPICIOUS", "MALICIOUS"];
  const JUDGEMENT_CLASS = { BENIGN: "j-benign", SUSPICIOUS: "j-suspicious", MALICIOUS: "j-malicious" };
  const STATUS_CLASS = {
    pending: "st-pending", executing: "st-pending", done: "st-ok", failed: "st-bad",
    rejected: "st-neutral", expired: "st-neutral",
  };
  const TIER_CLASS = { local: "tier-local", notify: "tier-notify", enforce: "tier-enforce" };
  const ROLE_CLASS = { input: "turn t-input", response: "turn t-response" };
  const ROLE_LABEL = { input: "attacker", response: "decoy" };
  const HEALTH_MARK = { ok: "OK", warn: "Check", bad: "Problem" };

  const SECTIONS = [
    { key: "overview", label: "Overview", hash: "#/" },
    { key: "queue", label: "Queue", hash: "#/queue" },
    { key: "records", label: "Records", hash: "#/records" },
    { key: "digests", label: "Digests", hash: "#/digests" },
    { key: "decoy", label: "Decoy", hash: "#/decoy" },
    { key: "playbooks", label: "Playbooks", hash: "#/playbooks" },
  ];

  const state = {
    session: null,     // {csrf, actions, operator}; csrf is never shown
    view: null,        // {refresh(kind)} of the current screen
    gen: 0,            // bumped on every navigation; late answers for old screens are dropped
    pollTimer: null,
    confirm: null,     // the open confirmation panel, if any
    revealed: null,    // the one revealed honeytoken, if any
    signedOut: false,
    pending: 0,
  };
  const shell = { main: null, links: {}, badge: null, mode: null, updated: null };

  // ---- DOM helpers ----------------------------------------------------------------------

  // el(tag, classOrOptions, ...children). Options: cls, text, attrs (fixed names and values
  // chosen in this file), on (event listeners). Children: nodes, strings (become text
  // nodes), arrays, or null/false (skipped).
  function el(tag, opts, ...kids) {
    const node = document.createElement(tag);
    if (typeof opts === "string") {
      node.className = opts;
    } else if (opts) {
      if (opts.cls) node.className = opts.cls;
      if (opts.text !== undefined && opts.text !== null) node.textContent = String(opts.text);
      if (opts.attrs) {
        for (const name of Object.keys(opts.attrs)) node.setAttribute(name, opts.attrs[name]);
      }
      if (opts.on) {
        for (const name of Object.keys(opts.on)) node.addEventListener(name, opts.on[name]);
      }
    }
    append(node, kids);
    return node;
  }

  function append(node, kids) {
    for (const kid of kids) {
      if (kid === null || kid === undefined || kid === false) continue;
      if (Array.isArray(kid)) append(node, kid);
      else if (kid instanceof Node) node.append(kid);
      else node.append(document.createTextNode(String(kid)));
    }
  }

  // Replaces a node's children. Unlike the native replaceChildren, null entries are
  // skipped instead of becoming the text "null".
  function setKids(node, ...kids) {
    node.replaceChildren();
    append(node, kids);
  }

  function button(label, onClick, cls) {
    const b = el("button", { cls: "btn", attrs: { type: "button" }, text: label });
    if (cls) b.classList.add(...cls.split(" "));
    b.addEventListener("click", onClick);
    return b;
  }

  function link(href, ...kids) {
    return el("a", { attrs: { href: href } }, ...kids);
  }

  // A value from a fixed table, looked up without touching the prototype chain.
  function lookup(table, key, fallback) {
    return typeof key === "string" && Object.prototype.hasOwnProperty.call(table, key)
      ? table[key] : fallback;
  }

  function str(value) {
    if (value === null || value === undefined) return "";
    if (typeof value === "string") return value;
    if (typeof value === "number" || typeof value === "boolean") return String(value);
    return JSON.stringify(value);
  }

  function arr(value) {
    return Array.isArray(value) ? value : [];
  }

  function obj(value) {
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
  }

  // ---- format helpers -------------------------------------------------------------------

  const NUMBER = new Intl.NumberFormat("en-US");

  function num(value) {
    return typeof value === "number" && isFinite(value) ? NUMBER.format(value) : "-";
  }

  function bytes(value) {
    if (typeof value !== "number" || !isFinite(value)) return "-";
    if (value < 1024) return NUMBER.format(value) + " B";
    if (value < 1024 * 1024) return (value / 1024).toFixed(1) + " KiB";
    if (value < 1024 * 1024 * 1024) return (value / 1024 / 1024).toFixed(1) + " MiB";
    return (value / 1024 / 1024 / 1024).toFixed(2) + " GiB";
  }

  function yesNo(value) {
    return value === true ? "yes" : value === false ? "no" : "-";
  }

  function fmtValue(value) {
    if (value === null || value === undefined) return "-";
    if (typeof value === "number") return num(value);
    if (typeof value === "boolean") return yesNo(value);
    if (Array.isArray(value)) return value.map(fmtValue).join(", ");
    return str(value);
  }

  function plural(n, one, many) {
    return num(n) + " " + (n === 1 ? one : many);
  }

  // ISO 8601 from the API, or the tuner's compact 20261117T195242Z. Anything else: null.
  function parseTime(value) {
    if (typeof value !== "string" || value.length > 40) return null;
    const m = COMPACT_TIME_RE.exec(value);
    let d;
    if (m) d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
    else if (ISO_RE.test(value)) d = new Date(value);
    else return null;
    return isNaN(d.getTime()) ? null : d;
  }

  function absUtc(d) {
    return d.toISOString().slice(0, 19).replace("T", " ") + " UTC";
  }

  function clockUtc(d) {
    return d.toISOString().slice(11, 19);
  }

  function relative(d, now) {
    const diff = (d.getTime() - now) / 1000;
    const past = diff <= 0;
    const s = Math.abs(diff);
    let t;
    if (s < 45) return past ? "just now" : "in under a minute";
    if (s < 90 * 60) t = Math.max(1, Math.round(s / 60)) + "m";
    else if (s < 36 * 3600) t = Math.round(s / 3600) + "h";
    else if (s < 14 * 86400) {
      const days = Math.floor(s / 86400);
      const hours = Math.floor((s % 86400) / 3600);
      t = hours ? days + "d " + hours + "h" : days + "d";
    } else t = Math.round(s / 86400) + "d";
    return past ? t + " ago" : "in " + t;
  }

  // Relative time with the absolute UTC time on hover. Unparseable values are shown as
  // plain text with no title.
  function timeNode(value, fallback) {
    const d = parseTime(value);
    if (!d) {
      if (value === null || value === undefined || value === "") {
        return el("span", { cls: "faint", text: fallback || "-" });
      }
      return el("span", { cls: "mono wrap", text: str(value) });
    }
    const node = el("time", { text: relative(d, Date.now()) });
    node.dateTime = d.toISOString();
    node.title = absUtc(d);
    return node;
  }

  function hoursSince(value) {
    const d = parseTime(value);
    return d ? (Date.now() - d.getTime()) / 3600000 : null;
  }

  // ---- routes ---------------------------------------------------------------------------

  function recordHref(id) {
    return typeof id === "string" && RECORD_ID_RE.test(id) ? "#/records/" + enc(id) : null;
  }

  function approvalHref(id) {
    return typeof id === "string" && APPROVAL_ID_RE.test(id) ? "#/queue?all=1&focus=" + id : null;
  }

  function digestHref(day) {
    return typeof day === "string" && DAY_RE.test(day) ? "#/digests/" + day : null;
  }

  // Hash for an in-app path with query values typed by the operator (filters, pages).
  function hashFor(path, params) {
    const q = new URLSearchParams();
    for (const key of Object.keys(params || {})) {
      const value = params[key];
      if (value !== undefined && value !== null && value !== "") q.set(key, String(value));
    }
    const s = q.toString();
    return "#" + path + (s ? "?" + s : "");
  }

  function pageParam(params, name) {
    const n = Number.parseInt(params.get(name) || "1", 10);
    return Number.isFinite(n) && n >= 1 && n <= 1000000 ? n : 1;
  }

  function recordLink(id, ...kids) {
    const href = recordHref(id);
    return href ? link(href, ...kids) : el("span", null, ...kids);
  }

  // ---- API client -----------------------------------------------------------------------

  class ApiError extends Error {
    constructor(status, message) {
      super(message);
      this.status = status;
    }
  }

  async function request(method, path, params, body) {
    let url = path;
    if (params) {
      const q = new URLSearchParams();
      for (const key of Object.keys(params)) {
        const value = params[key];
        if (value !== undefined && value !== null && value !== "") q.set(key, String(value));
      }
      const s = q.toString();
      if (s) url += "?" + s;
    }
    const init = {
      method: method,
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      headers: { Accept: "application/json" },
    };
    if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.headers["X-Winnie-CSRF"] = state.session ? str(state.session.csrf) : "";
      init.body = JSON.stringify(body);
    }
    let resp;
    try {
      resp = await fetch(url, init);
    } catch (err) {
      throw new ApiError(0, "The console server did not answer.");
    }
    let data = null;
    try {
      data = await resp.json();
    } catch (err) {
      data = null;
    }
    if (resp.status === 401) {
      showSignedOut();
      throw new ApiError(401, "not signed in");
    }
    if (!resp.ok) {
      const message = data && typeof data.error === "string" ? data.error : "HTTP " + resp.status;
      throw new ApiError(resp.status, message);
    }
    return data;
  }

  function apiGet(path, params) {
    return request("GET", path, params);
  }

  function apiPost(path, body) {
    return request("POST", path, null, body);
  }

  // ---- shared widgets -------------------------------------------------------------------

  function empty(text) {
    return el("div", { cls: "state", text: text });
  }

  function errorMessage(err) {
    if (!(err instanceof ApiError)) return "Something went wrong while drawing this view.";
    if (err.status === 0) return err.message;
    if (err.status === 404) return "Not found (" + err.message + ").";
    return "Request failed (" + err.status + "): " + err.message;
  }

  function errorState(err, retry) {
    return el("div", { cls: "state state-error", attrs: { role: "alert" } },
      errorMessage(err), retry ? button("Retry", retry, "btn-small") : null);
  }

  // Loads data into target. The loading line appears only when a load is slow, so fast
  // loads do not flash. A failed background refresh keeps what is on screen (the header
  // says the refresh failed); a failed first load shows the error with a retry.
  const filled = new WeakMap();

  async function fill(target, load, draw, quiet) {
    const gen = state.gen;
    const hadContent = filled.get(target) === "ok";
    let timer = null;
    if (!quiet || !hadContent) {
      timer = setTimeout(() => {
        if (gen === state.gen) target.replaceChildren(el("div", { cls: "state", text: "Loading..." }));
      }, LOADING_DELAY_MS);
    }
    try {
      const data = await load();
      if (gen !== state.gen || state.signedOut) return false;
      clearTimeout(timer);
      const out = draw(data);
      target.replaceChildren();
      append(target, [out]);
      filled.set(target, "ok");
      return true;
    } catch (err) {
      clearTimeout(timer);
      if (gen !== state.gen || state.signedOut) return false;
      if (!(quiet && hadContent)) {
        target.replaceChildren(errorState(err, () => fill(target, load, draw, false)));
        filled.set(target, "error");
      }
      if (!(err instanceof ApiError)) console.error(err);
      return false;
    }
  }

  function pageHead(title, ...extras) {
    return el("div", "page-head", el("h1", { text: title }), el("div", "spacer"), ...extras);
  }

  // A bordered section. Returns {node, head, body}.
  function section(title, opts) {
    const options = opts || {};
    const head = el("div", "section-head", el("h2", { text: title }), el("div", "spacer"),
      options.extra || null);
    const body = el("div", options.flush ? "section-body flush" : "section-body");
    const node = el("section", "section", head, body);
    return { node, head, body };
  }

  function kv(pairs) {
    const dl = el("dl", "kv");
    for (const pair of pairs) {
      if (!pair) continue;
      dl.append(el("dt", { text: pair[0] }), el("dd", null, pair[1]));
    }
    return dl;
  }

  // Scrollable monospace block for long or multi-line attacker text.
  function textBlock(text, cls) {
    const pre = el("pre", { cls: "text-block", text: str(text), attrs: { tabindex: "0" } });
    if (cls) pre.classList.add(...cls.split(" "));
    return pre;
  }

  // Short identifier (address, id, name): one line inside tables.
  function mono(text) {
    return el("span", { cls: "mono", text: str(text) });
  }

  function clip(text, wide) {
    return el("span", { cls: wide ? "clip clip-wide mono" : "clip mono", text: str(text) });
  }

  function badge(text, cls) {
    const b = el("span", { cls: "badge", text: text });
    b.classList.add(cls);
    return b;
  }

  function judgementBadge(level) {
    const label = typeof level === "string" && level ? level : "UNKNOWN";
    return badge(label, lookup(JUDGEMENT_CLASS, label, "j-unknown"));
  }

  function statusBadge(status) {
    const label = typeof status === "string" && status ? status : "unknown";
    const b = badge(label, lookup(STATUS_CLASS, label, "st-neutral"));
    b.classList.add("plain");
    return b;
  }

  function tierBadge(tier) {
    const label = typeof tier === "string" && tier ? tier : "unknown";
    const b = badge(label, lookup(TIER_CLASS, label, "tier-local"));
    b.classList.add("plain");
    return b;
  }

  function tags(values) {
    const list = arr(values);
    if (!list.length) return el("span", { cls: "faint", text: "-" });
    return el("span", "tag-list", list.map((v) => el("span", { cls: "tag", text: str(v) })));
  }

  // columns: [{label, num?, cls?}]. rows: [{cells: [...], href?}]. A row with an href
  // navigates on click; its first link is the keyboard-reachable equivalent.
  function table(columns, rows, opts) {
    const headRow = el("tr", null, columns.map((c) =>
      el("th", { cls: c.num ? "num" : "", attrs: { scope: "col" }, text: c.label })));
    const tbody = el("tbody");
    for (const row of rows) {
      const tr = el("tr");
      row.cells.forEach((cell, i) => {
        const col = columns[i] || {};
        tr.append(el("td", col.num ? "num" : col.cls || "", cell));
      });
      if (row.href) {
        const href = row.href;
        tr.classList.add("nav-row");
        tr.addEventListener("click", (ev) => {
          if (ev.target.closest("a, button") || String(window.getSelection())) return;
          location.hash = href;
        });
      }
      tbody.append(tr);
    }
    const wrap = el("div", opts && opts.short ? "table-wrap short" : "table-wrap",
      el("table", null, el("thead", null, headRow), tbody));
    return wrap;
  }

  // "1-50 of 213" with previous/next links. hrefFor(page) builds the hash for a page.
  function pager(data, hrefFor) {
    const total = typeof data.total === "number" ? data.total : 0;
    const page = typeof data.page === "number" ? data.page : 1;
    const per = typeof data.per === "number" && data.per > 0 ? data.per : PER_PAGE;
    if (total <= per && page === 1) return null;
    const first = total ? Math.min(total, (page - 1) * per + 1) : 0;
    const last = Math.min(total, page * per);
    const prev = page > 1 ? link(hrefFor(page - 1), "Previous")
      : el("span", { cls: "disabled", text: "Previous" });
    const next = page * per < total ? link(hrefFor(page + 1), "Next")
      : el("span", { cls: "disabled", text: "Next" });
    return el("div", "pager", el("span", { text: num(first) + "-" + num(last) + " of " + num(total) }),
      el("span", "spacer"), prev, next);
  }

  function segmented(options, current, onPick) {
    return el("div", { cls: "segmented", attrs: { role: "group" } }, options.map(([value, label]) => {
      const b = button(label, () => onPick(value), "btn-small");
      b.setAttribute("aria-pressed", value === current ? "true" : "false");
      return b;
    }));
  }

  function notice(level, ...kids) {
    const cls = lookup({ ok: "notice notice-ok", warn: "notice notice-warn", bad: "notice notice-bad" },
      level, "notice");
    return el("div", { cls: cls, attrs: { role: "status" } }, ...kids);
  }

  // ---- confirmation panel ---------------------------------------------------------------

  // Opens below `after`. Restates what will happen, needs a second explicit click, and
  // starts with focus on Cancel so a stray Enter does nothing. Esc closes it.
  function openConfirm(after, opts) {
    closeConfirm();
    const returnFocus = document.activeElement;
    const status = el("div", { cls: "muted", attrs: { "aria-live": "polite" } });
    const go = button(opts.confirmLabel, () => run(), opts.danger ? "btn-danger-solid" : "btn-primary");
    const cancel = button("Cancel", () => close());
    const panel = el("div", { cls: opts.danger ? "confirm confirm-danger" : "confirm",
      attrs: { role: "group", "aria-label": opts.title } },
    el("div", { cls: "confirm-title", text: opts.title }),
    kv(opts.rows),
    opts.note ? el("p", { cls: "muted", text: opts.note }) : null,
    status,
    el("div", "confirm-buttons", go, cancel));
    const handle = { busy: false, close: close };

    function close() {
      if (handle.busy) return;
      panel.remove();
      if (state.confirm === handle) state.confirm = null;
      if (returnFocus && returnFocus.isConnected) returnFocus.focus();
    }

    async function run() {
      handle.busy = true;
      go.disabled = true;
      cancel.disabled = true;
      status.textContent = "Sending...";
      try {
        await opts.onConfirm();
      } finally {
        handle.busy = false;
        panel.remove();
        if (state.confirm === handle) state.confirm = null;
      }
    }

    after.after(panel);
    state.confirm = handle;
    cancel.focus();
  }

  function closeConfirm() {
    if (state.confirm && !state.confirm.busy) state.confirm.close();
  }

  // ---- shell: header, router, polling ---------------------------------------------------

  function buildShell() {
    const nav = el("nav", { cls: "nav", attrs: { "aria-label": "Sections" } });
    SECTIONS.forEach((sec, i) => {
      const a = link(sec.hash, sec.label);
      a.setAttribute("aria-keyshortcuts", String(i + 1));
      if (sec.key === "queue") {
        shell.badge = el("span", { cls: "nav-badge" });
        shell.badge.hidden = true;
        a.append(shell.badge);
      }
      shell.links[sec.key] = a;
      nav.append(a);
    });

    const actions = state.session.actions === true;
    shell.mode = el("span", { cls: actions ? "mode mode-actions" : "mode",
      text: actions ? "Actions enabled" : "Read-only" });
    const operator = str(state.session.operator);
    const who = operator ? el("span", { cls: "updated", text: operator }) : null;
    shell.updated = el("span", { cls: "updated", attrs: { "aria-live": "polite" } });
    const refresh = button("Refresh", manualRefresh, "btn-small");
    refresh.setAttribute("aria-keyshortcuts", "r");

    const header = el("header", "header",
      el("div", "brand", "Winnie console"), nav,
      el("div", "header-right", shell.mode, who, shell.updated, refresh));
    shell.main = el("main", "main");
    const hint = el("div", { cls: "footer-hint",
      text: "Keys: 1-6 switch sections, r refreshes, / searches records, Esc closes a confirmation." });
    document.body.replaceChildren(header, shell.main, el("div", "main", hint));
  }

  function setNav(key) {
    for (const sec of SECTIONS) {
      const a = shell.links[sec.key];
      if (sec.key === key) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
  }

  function setTitle(name) {
    const count = state.pending > 0 ? "(" + state.pending + ") " : "";
    document.title = count + name + " - Winnie console";
    state.title = name;
  }

  function markUpdated(ok) {
    const now = new Date();
    if (ok) {
      shell.updated.textContent = "Updated " + clockUtc(now) + " UTC";
      shell.updated.classList.remove("updated-failed");
    } else {
      shell.updated.textContent = "Refresh failed " + clockUtc(now) + " UTC";
      shell.updated.classList.add("updated-failed");
    }
  }

  function safeDecode(part) {
    try {
      return decodeURIComponent(part);
    } catch (err) {
      return "";
    }
  }

  function parseHash() {
    const raw = location.hash.replace(/^#/, "") || "/";
    const qi = raw.indexOf("?");
    const path = qi >= 0 ? raw.slice(0, qi) : raw;
    const params = new URLSearchParams(qi >= 0 ? raw.slice(qi + 1) : "");
    const parts = path.split("/").filter(Boolean).map(safeDecode);
    return { parts, params };
  }

  function resolve(route) {
    const [a, b, c] = route.parts;
    if (c !== undefined) return { view: viewNotFound, key: null };
    if (!a) return { view: viewOverview, key: "overview" };
    if (a === "queue" && !b) return { view: viewQueue, key: "queue" };
    if (a === "records" && !b) return { view: viewRecords, key: "records" };
    if (a === "records") return { view: viewRecord, key: "records" };
    if (a === "digests") return { view: viewDigests, key: "digests" };
    if (a === "decoy" && !b) return { view: viewDecoy, key: "decoy" };
    if (a === "playbooks" && !b) return { view: viewPlaybooks, key: "playbooks" };
    return { view: viewNotFound, key: null };
  }

  function render() {
    if (state.signedOut) return;
    if (state.confirm) {
      state.confirm.busy = false;
      closeConfirm();
    }
    hideRevealed();
    const route = parseHash();
    const { view, key } = resolve(route);
    state.gen += 1;
    setNav(key);
    shell.main.replaceChildren();
    state.view = view(route, shell.main) || {};
    window.scrollTo(0, 0);
    refreshView("initial");
  }

  // kind: "initial" (first draw of a screen), "poll" (background, every 30 s) or "manual"
  // (the Refresh control). Screens skip parts that would lose what the operator is doing.
  async function refreshView(kind) {
    const view = state.view;
    if (!view || !view.refresh) return;
    const gen = state.gen;
    let ok = false;
    try {
      ok = await view.refresh(kind);
    } catch (err) {
      console.error(err);
    }
    if (gen === state.gen && !state.signedOut) markUpdated(ok !== false);
  }

  async function updatePendingBadge() {
    try {
      const data = await apiGet(API.queue, { per: 1 });
      state.pending = typeof data.total === "number" ? data.total : 0;
    } catch (err) {
      return;
    }
    shell.badge.hidden = state.pending === 0;
    shell.badge.textContent = num(state.pending);
    shell.links.queue.setAttribute("aria-label",
      "Queue, " + plural(state.pending, "pending approval", "pending approvals"));
    if (state.title) setTitle(state.title);
  }

  function manualRefresh() {
    if (state.signedOut) return;
    closeConfirm();
    refreshView("manual");
    updatePendingBadge();
  }

  function pollTick() {
    if (state.signedOut || state.confirm || document.hidden) return;
    refreshView("poll");
    updatePendingBadge();
  }

  function startPolling() {
    stopPolling();
    if (!document.hidden) state.pollTimer = setInterval(pollTick, POLL_MS);
  }

  function stopPolling() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = null;
  }

  function showSignedOut() {
    if (state.signedOut) return;
    state.signedOut = true;
    stopPolling();
    hideRevealed();
    document.title = "Signed out - Winnie console";
    document.body.replaceChildren(el("main", "signed-out",
      el("h1", { text: "Signed out" }),
      el("p", { text: "This console session is no longer valid. The server may have restarted or its token changed." }),
      el("p", { text: "Open the sign-in link printed in the server log to sign in again." })));
  }

  function onKey(ev) {
    if (ev.key === "Escape" && state.confirm) {
      ev.preventDefault();
      closeConfirm();
      return;
    }
    if (ev.ctrlKey || ev.metaKey || ev.altKey || state.signedOut || !shell.main) return;
    const target = ev.target;
    if (target instanceof Element && target.closest("input, select, textarea, button, [contenteditable]")) return;
    if (ev.key === "r") {
      manualRefresh();
    } else if (/^[1-6]$/.test(ev.key)) {
      location.hash = SECTIONS[Number(ev.key) - 1].hash;
    } else if (ev.key === "/") {
      const search = shell.main.querySelector("input[data-search]");
      if (search) {
        ev.preventDefault();
        search.focus();
      }
    }
  }

  async function boot() {
    try {
      state.session = await apiGet(API.session);
    } catch (err) {
      if (err.status === 401) return;
      document.body.replaceChildren(el("main", "signed-out",
        el("h1", { text: "Console unavailable" }),
        el("p", { text: errorMessage(err) }),
        button("Try again", boot)));
      return;
    }
    buildShell();
    window.addEventListener("hashchange", render);
    document.addEventListener("keydown", onKey);
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        stopPolling();
      } else {
        pollTick();
        startPolling();
      }
    });
    render();
    updatePendingBadge();
    startPolling();
  }

  // ---- screen: overview -----------------------------------------------------------------

  function viewOverview(route, main) {
    setTitle("Overview");
    const win = route.params.get("window") === "7d" ? "7d" : "24h";
    const toggle = segmented([["24h", "Last 24 hours"], ["7d", "Last 7 days"]], win, (value) => {
      location.hash = hashFor("/", value === "7d" ? { window: "7d" } : {});
    });
    const body = el("div");
    main.append(pageHead("Overview", toggle), body);
    return {
      refresh: (kind) => fill(body, () => apiGet(API.overview, { window: win }),
        (data) => drawOverview(obj(data), win), kind !== "initial"),
    };
  }

  function drawOverview(data, win) {
    const totals = obj(data.totals);
    const approvals = obj(data.approvals);
    const health = obj(data.health);
    const hits = arr(data.honeytoken_hits).map(obj);
    const windowLabel = win === "7d" ? "last 7 days" : "last 24 hours";

    const pending = typeof approvals.pending === "number" ? approvals.pending : 0;
    const soonest = parseTime(approvals.soonest_expiry);
    const tiles = el("div", "tiles",
      tile("Pending approvals", num(pending), pending > 0,
        pending > 0 && soonest ? ["Soonest expires ", timeNode(approvals.soonest_expiry), ". "] : null,
        link("#/queue", pending > 0 ? "Open queue" : "Queue")),
      tile("Records, " + windowLabel, num(totals.records), false,
        plural(totals.sessions || 0, "session", "sessions") + ", " +
        plural(totals.campaigns || 0, "campaign", "campaigns")),
      tile("Records that used a honeytoken", num(hits.length), hits.length > 0,
        hits.length ? "Newest " : "None seen", hits.length ? timeNode(hits[0].last_seen || hits[0].first_seen) : null),
      tile("Newest record", health.newest_record ? timeNode(health.newest_record) : "none", false,
        plural(health.records_total || 0, "record", "records") + " stored"));

    const hitSection = section("Honeytoken use", { flush: true });
    append(hitSection.body, [hits.length ? hitList(hits)
      : empty("No stored record used a honeytoken.")]);

    const judgement = section("By judgement, " + windowLabel);
    const byJ = obj(totals.by_judgement);
    const jEntries = JUDGEMENTS.map((j) => [j, Number(byJ[j]) || 0]);
    for (const key of Object.keys(byJ)) {
      if (!JUDGEMENTS.includes(key)) jEntries.push([key, Number(byJ[key]) || 0]);
    }
    append(judgement.body, [(totals.records || 0) > 0
      ? bars(jEntries, judgementBadge, (label) => lookup(JUDGEMENT_CLASS, label, "j-unknown"))
      : empty("No records in this window.")]);

    const protocol = section("By protocol, " + windowLabel);
    const byP = obj(totals.by_protocol);
    const pEntries = Object.keys(byP).map((k) => [k, Number(byP[k]) || 0])
      .sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]));
    append(protocol.body, [pEntries.length ? bars(pEntries, mono, null)
      : empty("No records in this window.")]);

    const sources = section("Top sources, " + windowLabel, { flush: true });
    const top = arr(data.top_sources);
    append(sources.body, [top.length
      ? table([{ label: "Source" }, { label: "Records", num: true }, { label: "Worst" }],
        top.map((s) => ({ cells: [mono(s.src_ip), num(s.records), judgementBadge(s.worst)] })),
        { short: true })
      : empty("No sources in this window.")]);

    const healthSection = section("Pipeline health", { flush: true });
    healthSection.body.append(healthList(health));

    return [
      tiles,
      hitSection.node,
      el("div", "grid-2", judgement.node, protocol.node),
      el("div", "grid-2", sources.node, healthSection.node),
    ];
  }

  function tile(label, value, attention, ...sub) {
    return el("div", attention ? "tile tile-attention" : "tile",
      el("div", { cls: "tile-label", text: label }),
      el("div", "tile-value", value),
      el("div", "tile-sub", ...sub));
  }

  function bars(entries, labelNode, classFor) {
    const max = Math.max(1, ...entries.map((e) => e[1]));
    const grid = el("div", "bars");
    for (const [label, value] of entries) {
      const fillBar = el("div", "bar-fill");
      if (classFor) fillBar.classList.add(classFor(label));
      fillBar.style.width = ((value / max) * 100).toFixed(1) + "%";
      grid.append(el("div", "bar-label", labelNode(label)),
        el("div", { cls: "bar-track", attrs: { "aria-hidden": "true" } }, fillBar),
        el("div", { cls: "num", text: num(value) }));
    }
    return grid;
  }

  function hitList(records) {
    return el("ul", "hit-list", records.map((r) => el("li", null,
      el("div", "hit-line",
        judgementBadge(r.judgement),
        recordLink(r.id, mono(r.id)),
        el("span", { cls: "muted", text: str(r.protocol) + " " + str(r.kind) }),
        mono(r.src_ip),
        tags(r.honeytokens),
        el("span", "faint", timeNode(r.last_seen || r.first_seen))),
      el("div", { cls: "hit-narrative", text: str(r.narrative) }))));
  }

  // Each row: name, level ("ok" | "warn" | "bad") and a detail. Healthy rows stay quiet.
  function healthRows(h) {
    const rows = [];
    const recordsTotal = typeof h.records_total === "number" ? h.records_total : 0;

    const log = obj(h.event_log);
    if (log.state === "ok") {
      const index = obj(log.index);
      if (index.caught_up === false) {
        rows.push(["Event log", "warn", bytes(log.bytes) + "; the transcript index is still reading a backlog."]);
      } else {
        rows.push(["Event log", "ok", bytes(log.bytes) + ", " + plural(index.sessions || 0, "session", "sessions") +
          " indexed" + (index.rebuilds ? ", " + plural(index.rebuilds, "rebuild", "rebuilds") : "") + "."]);
      }
    } else if (log.state === "missing") {
      rows.push(["Event log", recordsTotal > 0 ? "warn" : "ok",
        recordsTotal > 0 ? "No event log file. It may have rotated or the path changed."
          : "Nothing logged yet (normal on a new sensor)."]);
    } else {
      rows.push(["Event log", "bad", "Not configured or unreadable."]);
    }

    const age = hoursSince(h.newest_record);
    if (age === null) {
      rows.push(["Triage", "ok", recordsTotal ? "No timestamp on the newest record." : "No records yet."]);
    } else {
      const level = age >= STALE_BAD_HOURS ? "bad" : age >= STALE_WARN_HOURS ? "warn" : "ok";
      rows.push(["Triage", level, ["Newest record ", timeNode(h.newest_record),
        level === "ok" ? "." : ". Triage may not be running."]]);
    }

    rows.push(["Analyst calls", ...usage(obj(h.analyst_calls), "calls", "calls")]);
    rows.push(["Front-end tokens", ...usage(obj(h.frontend_tokens), "tokens", "tokens")]);

    const limits = arr(h.sensor_limits);
    if (!limits.length) {
      rows.push(["Sensor limits", "ok", "No drops or rate limits."]);
    } else {
      rows.push(["Sensor limits", "warn", limits.map((l) =>
        str(l.protocol) + " " + str(l.reason) + (l.pool ? " (" + str(l.pool) + ")" : "") + ": " + num(l.count)).join("; ")]);
    }

    const alarm = h.size_alarm;
    if (alarm && typeof alarm === "object") {
      rows.push(["Response state", "bad", "State is " + bytes(alarm.bytes) + ", over the " +
        bytes(alarm.limit_bytes) + " alarm."]);
    } else {
      rows.push(["Response state", "ok", "Within its size limit."]);
    }

    const failures = arr(h.ship_failures);
    if (!failures.length) {
      rows.push(["Event export", "ok", "No recent failures."]);
    } else {
      const f = obj(failures[0]);
      rows.push(["Event export", "bad", [plural(failures.length, "recent failure", "recent failures") +
        "; newest ", timeNode(f.timestamp), ": " + str(f.event) + " " + str(f.error) +
        " (" + plural(f.lines || 0, "line", "lines") + ")."]]);
    }
    return rows;
  }

  function usage(u, unit) {
    const used = typeof u.calls === "number" ? u.calls : u.tokens;
    if (typeof used !== "number") return ["ok", "None today."];
    const limit = u.limit;
    if (typeof limit !== "number" || limit <= 0) {
      return ["ok", num(used) + " " + unit + " today (limit unknown)."];
    }
    const ratio = used / limit;
    const level = ratio >= 1 ? "bad" : ratio >= 0.8 ? "warn" : "ok";
    return [level, num(used) + " of " + num(limit) + " " + unit + " today" +
      (level === "bad" ? ", limit reached." : ".")];
  }

  function healthList(h) {
    const list = el("div", "health");
    for (const [name, level, detail] of healthRows(h)) {
      const row = el("div", "health-row");
      row.classList.add(lookup({ ok: "ok", warn: "warn", bad: "bad" }, level, "ok"));
      row.append(el("div", "health-name",
        el("span", { cls: "health-mark", text: lookup(HEALTH_MARK, level, "") }), name),
      el("div", "health-detail", detail));
      list.append(row);
    }
    return list;
  }

  // ---- screen: queue --------------------------------------------------------------------

  function viewQueue(route, main) {
    setTitle("Queue");
    const params = route.params;
    const showClosed = params.get("all") === "1";
    const focusParam = params.get("focus");
    const focusId = focusParam && APPROVAL_ID_RE.test(focusParam) ? focusParam : null;
    const cpage = pageParam(params, "cpage");
    const bpage = pageParam(params, "bpage");
    const actions = state.session.actions === true;
    const here = (extra) => hashFor("/queue", Object.assign(
      { all: showClosed ? "1" : "", cpage: cpage > 1 ? cpage : "", bpage: bpage > 1 ? bpage : "" }, extra));

    const toggle = button(showClosed ? "Hide closed items" : "Show closed items", () => {
      location.hash = here({ all: showClosed ? "" : "1", cpage: "", focus: "" });
    }, "btn-small");
    toggle.setAttribute("aria-pressed", showClosed ? "true" : "false");

    const noticeBox = el("div", { attrs: { "aria-live": "polite" } });
    const pendingBody = el("div");
    const closed = showClosed ? section("Closed items", { flush: true }) : null;
    const block = section("Approved blocklist", { flush: true });
    main.append(pageHead("Approval queue", toggle), noticeBox);
    if (!actions) {
      main.append(el("p", "readonly-line",
        "Read-only. Decide with ", el("code", { text: "python -m agents approve <id>" }), " or ",
        el("code", { text: "python -m agents reject <id>" }),
        ", or restart the console with actions enabled."));
    }
    main.append(pendingBody);
    if (closed) main.append(closed.node);
    main.append(block.node);

    const ctx = {
      actions,
      focusId,
      focusDone: false,
      reload: () => refreshView("manual"),
      say: (level, ...kids) => noticeBox.replaceChildren(notice(level, ...kids)),
      cards: new Map(),
    };

    function focusItem() {
      if (!ctx.focusId || ctx.focusDone) return;
      const node = ctx.cards.get(ctx.focusId);
      if (!node) return;
      ctx.focusDone = true;
      node.classList.add("focused");
      node.scrollIntoView({ block: "center" });
    }

    return {
      refresh: async (kind) => {
        const quiet = kind !== "initial";
        const jobs = [
          fill(pendingBody, () => apiGet(API.queue, { per: 200 }),
            (data) => drawPending(obj(data), ctx), quiet),
          fill(block.body, () => apiGet(API.blocklist, { page: bpage, per: PER_PAGE }),
            (data) => drawBlocklist(obj(data), ctx, (p) => here({ bpage: p })), quiet),
        ];
        if (closed) {
          jobs.push(fill(closed.body, () => apiGet(API.queue, { all: 1, page: cpage, per: PER_PAGE }),
            (data) => drawClosed(obj(data), ctx, (p) => here({ cpage: p })), quiet));
        }
        const results = await Promise.all(jobs);
        focusItem();
        return results.every(Boolean);
      },
    };
  }

  function drawPending(data, ctx) {
    const items = arr(data.items).filter((it) => obj(obj(it).approval).status === "pending");
    if (!items.length) return empty("Nothing is waiting for a decision.");
    const more = typeof data.total === "number" && data.total > arr(data.items).length
      ? el("p", { cls: "muted", text: "Showing the newest " + num(arr(data.items).length) + " of " + num(data.total) + " pending items." })
      : null;
    return [more, el("div", "cards", items.map((it) => approvalCard(obj(it), ctx)))];
  }

  function approvalCard(item, ctx) {
    const a = obj(item.approval);
    const id = typeof a.id === "string" && APPROVAL_ID_RE.test(a.id) ? a.id : null;
    const record = item.record && typeof item.record === "object" ? item.record : null;

    const head = el("div", "card-head",
      el("div", "card-title", mono(a.action), " on ", mono(a.subject)),
      statusBadge(a.status), tierBadge(a.tier),
      a.unverified_source === true ? badge("source may be forged", "st-bad") : null);

    const params = obj(a.params);
    const paramPairs = Object.keys(params).map((k) => [k, el("span", { cls: "mono wrap", text: fmtValue(params[k]) })]);
    const expires = parseTime(a.expires_at);
    const soon = expires && expires.getTime() - Date.now() < 6 * 3600000;
    const why = el("div", "stack",
      el("div", null, el("div", { cls: "label", text: "Why" }),
        kv([["Playbook", mono(a.playbook)], ["Tier", str(a.tier)]].concat(paramPairs))),
      el("div", null, el("div", { cls: "label", text: "Summary" }), textBlock(a.summary)),
      kv([
        ["Created", timeNode(a.created_at)],
        ["Expires", el("span", soon ? "expiry-soon" : "", timeNode(a.expires_at),
          expires ? " (" + absUtc(expires) + ")" : "")],
      ]));

    const facts = record ? el("div", "stack",
      el("div", "hit-line", judgementBadge(record.judgement),
        el("span", { cls: "muted", text: str(record.protocol) + " " + str(record.kind) })),
      kv([
        ["Source", el("span", null, mono(record.src_ip),
          record.unverified_source === true ? el("span", { cls: "muted", text: " (unverified)" }) : null)],
        ["Last seen", timeNode(record.last_seen || record.first_seen)],
        ["User", clip(record.username)],
        ["Activity", num(record.commands) + " commands, " + num(record.auth_successes) + "/" +
          num(record.auth_attempts) + " logins"],
        ["Honeytokens", tags(record.honeytokens)],
      ]),
      el("div", { cls: "hit-narrative", text: str(record.narrative) }),
      recordHref(record.id) ? link(recordHref(record.id), "Open record") : null)
      : el("div", "stack", el("p", { cls: "muted", text: "The triggering record is no longer stored." }),
        kv([["Record id", mono(a.record_id)]]));

    const body = el("div", "card-body", why,
      el("div", null, el("div", { cls: "label", text: "Triggering record" }), facts));

    const foot = el("div", "card-foot", el("span", { cls: "muted", text: "Id " }), mono(a.id), el("span", "spacer"));
    const card = el("article", "card", head, body, foot);
    if (id) ctx.cards.set(id, card);

    const viewHash = typeof item.view_hash === "string" ? item.view_hash : null;
    if (ctx.actions && id && viewHash && a.status === "pending") {
      const target = str(a.subject);
      const action = str(a.action);
      const rows = [["Action", mono(action)], ["Target", mono(target)], ["Approval", mono(id)],
        ["Playbook", mono(a.playbook)]];
      // Reject works for every pending item. Approve only when this process can run the
      // action (open_ticket and block_webhook need a connector the console usually lacks).
      if (item.can_approve_here !== true) {
        foot.append(el("span", { cls: "muted",
          text: "This action needs a connector; approve it with the CLI in the agents container. " }));
      }
      foot.append(
        button("Reject", () => openConfirm(foot, {
          title: "Reject " + id + "?",
          rows: rows,
          note: "Nothing is executed. The item is closed as rejected.",
          confirmLabel: "Reject",
          danger: false,
          onConfirm: () => decide("reject", id, viewHash, ctx),
        })));
      if (item.can_approve_here === true) {
        foot.append(button("Approve", () => openConfirm(foot, {
          title: "Approve and run " + action + " on " + target + "?",
          rows: rows,
          note: "Approving runs the action now. It can take as long as the action does.",
          confirmLabel: "Approve and run",
          danger: true,
          onConfirm: () => decide("approve", id, viewHash, ctx),
        }), "btn-primary"));
      }
    }
    return card;
  }

  async function decide(verb, id, viewHash, ctx) {
    const label = verb === "approve" ? "Approve" : "Reject";
    try {
      const res = await apiPost(verb === "approve" ? API.approve(id) : API.reject(id), { view_hash: viewHash });
      const a = obj(obj(res).approval);
      const status = str(a.status) || "unknown";
      const level = status === "failed" ? "bad" : "ok";
      // A 200 can still be a failure: respond may refuse after taking the approval, and
      // result.status says why.
      const result = obj(a.result);
      const why = result.status !== undefined ? el("div", null, "Result: ",
        el("span", { cls: "mono wrap", text: str(result.status) })) : null;
      ctx.say(level, el("div", null, label + " " + id + ": " + status + "."), why);
    } catch (err) {
      if (err.status === 401) return;
      if (err.status === 409) {
        ctx.say("warn", "Approval " + id + " changed after this page loaded, so nothing was decided. " +
          "The queue has been reloaded; review the current item and decide again.");
      } else {
        ctx.say("bad", label + " " + id + " was refused: ", el("span", { cls: "mono wrap", text: err.message }));
      }
    }
    ctx.focusId = id;
    ctx.focusDone = false;
    ctx.cards.clear();
    await ctx.reload();
  }

  function drawClosed(data, ctx, hrefFor) {
    const items = arr(data.items).map((it) => obj(it)).filter((it) => obj(it.approval).status !== "pending");
    if (!items.length && !data.total) return empty("No closed items yet.");
    const rows = items.map((it) => {
      const a = obj(it.approval);
      const decidedAt = a.approved_at || a.rejected_at || a.expired_at || null;
      const by = a.approved_by || a.rejected_by || "";
      const result = a.result && typeof a.result === "object"
        ? (a.result.ok === true ? "ok" : "failed") + (a.result.status !== undefined ? " (" + str(a.result.status) + ")" : "")
        : "";
      return {
        cells: [statusBadge(a.status), mono(a.action), clip(a.subject), mono(a.playbook),
          timeNode(decidedAt), clip(by), clip(result),
          a.record_id ? recordLink(a.record_id, clip(a.record_id)) : "-", mono(a.id)],
      };
    });
    const wrap = items.length ? table([
      { label: "Status" }, { label: "Action" }, { label: "Target" }, { label: "Playbook" },
      { label: "Decided" }, { label: "By" }, { label: "Result" }, { label: "Record" }, { label: "Id" },
    ], rows) : empty("No closed items on this page.");
    for (const [i, it] of items.entries()) {
      const id = obj(it.approval).id;
      if (typeof id === "string" && APPROVAL_ID_RE.test(id) && !ctx.cards.has(id)) {
        ctx.cards.set(id, wrap.querySelectorAll("tbody tr")[i]);
      }
    }
    return [wrap, pager(data, hrefFor)];
  }

  function drawBlocklist(data, ctx, hrefFor) {
    const items = arr(data.items).map((it) => obj(it));
    if (!items.length) return empty("The blocklist is empty.");
    const columns = [{ label: "Target" }, { label: "Approved" }, { label: "Expires" }];
    if (ctx.actions) columns.push({ label: "" });
    const wrap = table(columns, items.map((it) => {
      const target = str(it.target);
      const cells = [mono(target), timeNode(it.approved_at), timeNode(it.expires_at)];
      if (ctx.actions) {
        const cell = el("span");
        cell.append(button("Unblock", () => openConfirm(wrap, {
          title: "Remove " + target + " from the blocklist?",
          rows: [["Target", mono(target)]],
          note: "Every live entry equal to or inside this address or network is removed.",
          confirmLabel: "Unblock",
          danger: true,
          onConfirm: () => unblock(target, ctx),
        }), "btn-small btn-danger"));
        cells.push(cell);
      }
      return { cells };
    }));
    return [wrap, pager(data, hrefFor)];
  }

  async function unblock(target, ctx) {
    try {
      const res = obj(await apiPost(API.unblock, { target: target }));
      const removed = arr(res.removed).map(str);
      const left = typeof res.entries === "number" ? " " + plural(res.entries, "entry", "entries") + " left." : "";
      ctx.say("ok", (removed.length ? "Removed from the blocklist: " + removed.join(", ") + "."
        : "Nothing matched " + target + "; the blocklist is unchanged.") + left);
    } catch (err) {
      if (err.status === 401) return;
      ctx.say("bad", "Unblock " + target + " was refused: ", el("span", { cls: "mono wrap", text: err.message }));
    }
    await ctx.reload();
  }

  // ---- screen: records ------------------------------------------------------------------

  function recordFilters(params) {
    const pick = (name, allowed) => {
      const v = params.get(name);
      return v && allowed.includes(v) ? v : "";
    };
    const protocol = (params.get("protocol") || "").toLowerCase();
    return {
      kind: pick("kind", ["session", "campaign"]),
      protocol: PROTOCOL_RE.test(protocol) ? protocol : "",
      judgement: pick("judgement", JUDGEMENTS),
      honeytoken: pick("honeytoken", ["1", "0"]),
      src: (params.get("src") || "").trim().slice(0, 64),
      q: (params.get("q") || "").slice(0, 200),
      sort: pick("sort", ["rank"]),
    };
  }

  function viewRecords(route, main) {
    setTitle("Records");
    const f = recordFilters(route.params);
    const page = pageParam(route.params, "page");
    const active = Boolean(f.kind || f.protocol || f.judgement || f.honeytoken || f.src || f.q);

    const select = (name, label, options) => {
      const s = el("select", { attrs: { name: name } },
        options.map(([value, text]) => el("option", { attrs: { value: value }, text: text })));
      s.value = f[name];
      s.addEventListener("change", apply);
      return el("label", "field", el("span", { text: label }), s);
    };
    const input = (name, label, placeholder, wide) => {
      const i = el("input", { cls: wide ? "wide" : "", attrs: { type: "text", name: name, placeholder: placeholder,
        autocomplete: "off", spellcheck: "false" } });
      i.value = f[name];
      return el("label", "field", el("span", { text: label }), i);
    };

    const form = el("form", { cls: "filters", attrs: { role: "search" } },
      input("q", "Search", "id, source, user, command, IOC", true),
      select("kind", "Kind", [["", "Any"], ["session", "Session"], ["campaign", "Campaign"]]),
      input("protocol", "Protocol", "ssh, ftp, sip"),
      select("judgement", "Judgement", [["", "Any"]].concat(JUDGEMENTS.map((j) => [j, j]))),
      select("honeytoken", "Honeytoken", [["", "Any"], ["1", "Used one"], ["0", "Did not"]]),
      input("src", "Source", "exact address"),
      select("sort", "Sort", [["", "Newest"], ["rank", "Rank"]]),
      el("button", { cls: "btn btn-primary", attrs: { type: "submit" }, text: "Apply" }),
      active ? link("#/records", "Clear filters") : null);
    form.elements.namedItem("q").setAttribute("data-search", "");
    const protocolInput = form.elements.namedItem("protocol");
    protocolInput.addEventListener("input", () => protocolInput.setCustomValidity(""));
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      apply();
    });

    function apply() {
      const data = new FormData(form);
      const next = {};
      for (const key of ["q", "kind", "protocol", "judgement", "honeytoken", "src", "sort"]) {
        next[key] = String(data.get(key) || "").trim();
      }
      next.protocol = next.protocol.toLowerCase();
      if (next.protocol && !PROTOCOL_RE.test(next.protocol)) {
        form.elements.namedItem("protocol").setCustomValidity("Letters and digits only, up to 16.");
        form.reportValidity();
        return;
      }
      location.hash = hashFor("/records", next);
    }

    const filterSection = el("section", "section", form);
    const results = section("Records", { flush: true });
    main.append(pageHead("Records"), filterSection, results.node);

    const query = Object.assign({}, f, { page: page, per: PER_PAGE, sort: f.sort || "newest" });
    return {
      refresh: (kind) => fill(results.body, () => apiGet(API.records, query),
        (data) => drawRecordTable(obj(data), active, (p) => hashFor("/records", Object.assign({}, f, { page: p }))),
        kind !== "initial"),
    };
  }

  function drawRecordTable(data, filtered, hrefFor) {
    const items = arr(data.items).map((it) => obj(it));
    if (!items.length) {
      if (data.total) return [empty("No records on this page."), pager(data, hrefFor)];
      return empty(filtered ? "No records match these filters."
        : "No triage records yet. They appear after the first triage run.");
    }
    const rows = items.map((r) => {
      const href = recordHref(r.id);
      const when = timeNode(r.last_seen || r.first_seen);
      return {
        href: href,
        cells: [
          href ? link(href, when) : when,
          judgementBadge(r.judgement),
          mono(r.protocol),
          str(r.kind),
          el("span", null, mono(r.src_ip)),
          clip(r.username),
          num(r.commands),
          num(r.auth_successes) + "/" + num(r.auth_attempts),
          tags(r.honeytokens),
          el("span", { cls: "clip clip-wide", text: str(r.narrative) }),
        ],
      };
    });
    return [table([
      { label: "Last seen" }, { label: "Judgement" }, { label: "Protocol" }, { label: "Kind" },
      { label: "Source" }, { label: "User" }, { label: "Commands", num: true },
      { label: "Logins", num: true }, { label: "Honeytokens" }, { label: "Narrative" },
    ], rows), pager(data, hrefFor)];
  }

  // ---- screen: record detail ------------------------------------------------------------

  function viewRecord(route, main) {
    setTitle("Record");
    const id = route.parts[1];
    main.append(el("p", null, link("#/records", "Back to records")));
    if (!RECORD_ID_RE.test(id || "")) {
      main.append(empty("That is not a record id."));
      return {};
    }
    const body = el("div");
    main.append(body);
    return {
      // A record rarely changes once written; background polls leave the page (and any
      // transcript pages already loaded) alone. The Refresh control reloads it.
      refresh: (kind) => kind === "poll" ? Promise.resolve(true)
        : fill(body, () => apiGet(API.record(id)), (data) => drawRecord(obj(data), id), kind !== "initial"),
    };
  }

  function drawRecord(data, id) {
    const r = obj(data.record);
    const out = [];

    out.push(el("div", "detail-head",
      el("h1", { text: str(r.id) || id }),
      judgementBadge(r.judgement),
      r.upstream_judgement ? el("span", { cls: "muted", text: "upstream: " + str(r.upstream_judgement) }) : null,
      el("span", { cls: "tag", text: str(r.protocol) }),
      el("span", { cls: "muted", text: str(r.kind) }),
      el("span", { cls: "muted", text: r.llm_used === true ? "model-assisted triage" : "rule-based triage" })));

    out.push(el("section", "section", el("div", "section-body", el("div", "facts",
      fact("Source", el("span", null, mono(r.src_ip),
        r.unverified_source === true ? el("span", { cls: "muted", text: " (may be forged)" }) : null)),
      fact("First seen", timeNode(r.first_seen)),
      fact("Last seen", timeNode(r.last_seen)),
      fact("Username", clip(r.username)),
      fact("Logins", num(r.auth_successes) + " of " + num(r.auth_attempts)),
      fact("Connections", num(r.connections)),
      fact("Commands", num(r.commands))))));

    const narrative = section("Narrative");
    narrative.body.append(textBlock(r.narrative));
    const signals = obj(r.high_signal);
    const assess = section("Assessment");
    assess.body.append(kv([
      ["Intent", str(r.intent) || "-"],
      ["Stage", str(r.stage) || "-"],
      ["Skill", str(r.skill) || "-"],
      ["High-signal", Object.keys(signals).length
        ? tags(Object.keys(signals).map((k) => k + ": " + fmtValue(signals[k]))) : "none"],
    ]));
    out.push(el("div", "grid-2", narrative.node, assess.node));

    const techniques = arr(r.techniques).map(obj);
    const tech = section("Techniques", { flush: true });
    tech.body.append(techniques.length
      ? table([{ label: "Id" }, { label: "Name" }], techniques.map((t) => ({ cells: [mono(t.id), str(t.name)] })), { short: true })
      : empty("None identified."));
    const iocs = arr(r.iocs).map(obj);
    const iocSection = section("Indicators", { flush: true });
    iocSection.body.append(iocs.length
      ? table([{ label: "Type" }, { label: "Value (not a link)" }],
        iocs.map((i) => ({ cells: [str(i.type), el("span", { cls: "mono wrap", text: str(i.value) })] })), { short: true })
      : empty("None extracted."));
    out.push(el("div", "grid-2", tech.node, iocSection.node));

    const creds = section("Credentials tried");
    creds.body.append(credentials(obj(r.credentials)));
    const commands = section("Command sample");
    const sample = arr(r.command_sample).map(str);
    commands.body.append(sample.length ? textBlock(sample.join("\n")) : empty("No commands recorded."));
    out.push(el("div", "grid-2", creds.node, commands.node));

    const tokens = section("Honeytokens");
    const tokenSources = arr(r.honeytoken_sources);
    tokens.body.append(arr(r.honeytokens).length || tokenSources.length
      ? kv([["Used", tags(r.honeytokens)], tokenSources.length ? ["Used from", tags(tokenSources)] : null])
      : empty("No honeytoken was used."));
    const related = section("Related approvals");
    const approvals = arr(data.approvals).filter((a) => typeof a === "string");
    related.body.append(approvals.length
      ? el("ul", null, approvals.map((a) => el("li", null,
        approvalHref(a) ? link(approvalHref(a), mono(a)) : mono(a))))
      : empty("No approvals were queued for this record."));
    out.push(el("div", "grid-2", tokens.node, related.node));

    const addresses = arr(r.src_addresses);
    if (addresses.length || (typeof r.src_address_count === "number" && r.src_address_count > 0)) {
      const sources = section("Source addresses (" + num(r.src_address_count || addresses.length) + ")");
      sources.body.append(tags(addresses));
      out.push(sources.node);
    }

    if (r.kind === "session" && r.protocol === "ssh") {
      const transcript = section("Transcript");
      transcript.body.append(data.transcript_available === true
        ? transcriptView(id)
        : empty("Transcript not available: the session's lines are no longer in the current event log."));
      out.push(transcript.node);
    }
    return out;
  }

  function fact(label, value) {
    return el("div", "fact", el("div", { cls: "label", text: label }), el("div", "fact-value", value));
  }

  function credentials(c) {
    const parts = [];
    const pairs = (title, list) => {
      const rows = arr(list).filter(Array.isArray);
      if (!rows.length) return;
      parts.push(el("div", null, el("div", { cls: "label", text: title }),
        table([{ label: "Value" }, { label: "Count", num: true }],
          rows.map((p) => ({ cells: [el("span", { cls: "mono wrap", text: str(p[0]) }), num(p[1])] })), { short: true })));
    };
    pairs("Usernames", c.top_usernames);
    pairs("Passwords", c.top_passwords);
    const pairRows = arr(c.top_pairs).filter(Array.isArray);
    if (pairRows.length) {
      parts.push(el("div", null, el("div", { cls: "label", text: "Pairs" }),
        table([{ label: "User" }, { label: "Password" }, { label: "Count", num: true }],
          pairRows.map((p) => ({ cells: [el("span", { cls: "mono wrap", text: str(p[0]) }),
            el("span", { cls: "mono wrap", text: str(p[1]) }), num(p[2])] })), { short: true })));
    }
    pairs("SIP extensions", c.sip_extensions);
    pairs("Dialed numbers", c.dialed_numbers);
    return parts.length ? el("div", "stack", parts) : empty("None recorded.");
  }

  // Terminal-like transcript: time gutter, a role marker, then the text. Attacker input is
  // bold in the input colour; decoy output is plain. Loaded one page at a time.
  function transcriptView(id) {
    const info = el("div");
    const term = el("div", { cls: "terminal", attrs: { tabindex: "0", role: "log", "aria-label": "Session transcript" } });
    term.hidden = true;
    const foot = el("div", { cls: "terminal-foot", attrs: { "aria-live": "polite" } });
    const gen = state.gen;
    let page = 0;
    let shown = 0;

    async function loadNext() {
      const timer = setTimeout(() => foot.replaceChildren(el("span", { text: "Loading transcript..." })), LOADING_DELAY_MS);
      let data;
      try {
        data = obj(await apiGet(API.transcript(id), { page: page + 1, per: TRANSCRIPT_PER }));
      } catch (err) {
        clearTimeout(timer);
        if (gen !== state.gen || err.status === 401) return;
        const text = err.status === 404 ? "Transcript not available (" + err.message + ")."
          : err.status === 422 ? "This transcript is too large to show (" + err.message + ")."
            : errorMessage(err);
        setKids(foot, el("span", { cls: "state-error", text: text }),
          err.status === 404 || err.status === 422 ? null : button("Retry", loadNext, "btn-small"));
        return;
      }
      clearTimeout(timer);
      if (gen !== state.gen) return;
      page += 1;
      if (page === 1) info.replaceChildren(transcriptInfo(data));
      const turns = obj(data.turns);
      const items = arr(turns.items).map(obj);
      for (const t of items) term.append(turnNode(t));
      shown += items.length;
      term.hidden = shown === 0;
      const total = typeof turns.total === "number" ? turns.total : shown;
      setKids(foot, el("span", { text: shown ? num(shown) + " of " + plural(total, "turn", "turns") : "No turns in this session." }),
        shown < total && items.length ? button("Load more", loadNext, "btn-small") : null);
    }

    loadNext();
    return el("div", "stack", info, term, foot);
  }

  function transcriptInfo(d) {
    const attempts = arr(d.auth_attempts).map(obj);
    return el("div", "stack",
      kv([
        ["Started", timeNode(d.start)],
        ["Ended", d.closed === true ? timeNode(d.end) : el("span", { cls: "muted", text: "still open" })],
        ["Username", clip(d.username)],
      ]),
      attempts.length ? el("div", null, el("div", { cls: "label", text: "Login attempts" }),
        table([{ label: "Time" }, { label: "Username" }, { label: "Password" }, { label: "Result" }],
          attempts.map((a) => ({ cells: [turnTime(a.ts), el("span", { cls: "mono wrap", text: str(a.username) }),
            el("span", { cls: "mono wrap", text: str(a.password) }),
            a.success === true ? badge("accepted", "st-bad") : statusBadgeText("refused")] })), { short: true }))
        : null);
  }

  function statusBadgeText(text) {
    const b = badge(text, "st-neutral");
    b.classList.add("plain");
    return b;
  }

  function turnTime(value) {
    const d = parseTime(value);
    if (!d) return el("span", { cls: "turn-time", text: "--:--:--" });
    const t = el("time", { cls: "turn-time", text: clockUtc(d) });
    t.dateTime = d.toISOString();
    t.title = absUtc(d);
    return t;
  }

  function turnNode(t) {
    const row = el("div", lookup(ROLE_CLASS, t.role, "turn t-other"));
    const who = lookup(ROLE_LABEL, t.role, "other");
    row.append(turnTime(t.ts),
      el("span", { cls: "visually-hidden", text: who }),
      el("span", { cls: "turn-mark", text: t.role === "input" ? ">" : "", attrs: { "aria-hidden": "true" } }),
      el("pre", { cls: "turn-text", text: str(t.text) }));
    const notes = [];
    if (t.interactive === null) notes.push("exec request");
    if (t.truncated === true) notes.push("cut at 4,000 characters");
    if (notes.length) row.append(el("div", { cls: "turn-note", text: notes.join(", ") }));
    return row;
  }

  // ---- screen: digests ------------------------------------------------------------------

  function viewDigests(route, main) {
    setTitle("Digests");
    const asked = route.parts[1];
    const day = asked && DAY_RE.test(asked) ? asked : null;
    const list = section("Days", { flush: true });
    const content = el("div");
    main.append(pageHead("Daily digests"), el("div", "split", list.node, content));
    if (asked && !day) {
      content.append(empty("That is not a day (expected YYYY-MM-DD)."));
    }
    let days = [];
    let shownDay = null;

    return {
      refresh: async (kind) => {
        const quiet = kind !== "initial";
        const ok = await fill(list.body, () => apiGet(API.digests, { per: 200 }), (data) => {
          days = arr(obj(data).items).filter((d) => typeof d === "string" && DAY_RE.test(d));
          return days.length ? dayList(days, day || days[0]) : empty("No digests yet.");
        }, quiet);
        if (!ok || (asked && !day)) return ok;
        const chosen = day || days[0];
        if (!chosen) {
          const s = section("Digest");
          s.body.append(empty("No daily digest has been written yet. The digest step writes one per day."));
          content.replaceChildren(s.node);
          return true;
        }
        // Today's digest can change, but reloading it in the background would reset the
        // reader's scroll position; the Refresh control reloads it.
        if (kind === "poll" && shownDay === chosen) return true;
        shownDay = chosen;
        return fill(content, () => apiGet(API.digest(chosen)), (data) => drawDigest(obj(data), chosen), quiet);
      },
    };
  }

  function dayList(days, current) {
    return el("ul", "pick-list", days.map((d) => {
      const a = link(digestHref(d), d);
      if (d === current) a.setAttribute("aria-current", "true");
      return el("li", null, a);
    }));
  }

  function drawDigest(data, day) {
    const s = section("Digest for " + day, {
      extra: data.truncated === true ? el("span", { cls: "muted", text: "Cut at 200,000 characters" }) : null,
    });
    s.body.append(textBlock(data.text, "tall"));
    return s.node;
  }

  // ---- screen: decoy --------------------------------------------------------------------

  function viewDecoy(route, main) {
    setTitle("Decoy");
    const spage = pageParam(route.params, "spage");
    const body = el("div");
    main.append(pageHead("Decoy"), body);
    return {
      refresh: (kind) => fill(body, () => apiGet(API.decoy, { page: spage, per: PER_PAGE }),
        (data) => drawDecoy(obj(data), (p) => hashFor("/decoy", { spage: p })), kind !== "initial"),
    };
  }

  function drawDecoy(d, hrefFor) {
    const out = [];

    const overlay = section("Current overlay");
    if (d.overlay && typeof d.overlay === "object") {
      const o = obj(d.overlay);
      const accounts = obj(o.accounts);
      const accountRows = [];
      for (const service of Object.keys(accounts)) {
        for (const acct of arr(accounts[service]).map(obj)) {
          accountRows.push({ cells: [mono(service), mono(acct.username), mono(acct.password)] });
        }
      }
      const policies = obj(o.policies);
      overlay.body.append(el("div", "stack",
        kv([
          ["Hostname", o.hostname ? mono(o.hostname) : el("span", { cls: "faint", text: "default" })],
          ["Lures", tags(o.lures)],
          ["SIP extensions", tags(arr(o.sip_extensions).map(fmtValue))],
          ["Policies", Object.keys(policies).length
            ? tags(Object.keys(policies).map((k) => k + ": " + fmtValue(policies[k]))) : el("span", { cls: "faint", text: "none" })],
        ]),
        el("div", null, el("div", { cls: "label", text: "Bait accounts (fake by design)" }),
          accountRows.length ? table([{ label: "Service" }, { label: "Username" }, { label: "Password" }], accountRows, { short: true })
            : empty("No bait accounts in the overlay."))));
    } else if (d.overlay_error) {
      overlay.body.append(notice("bad", str(d.overlay_error)));
    } else {
      overlay.body.append(empty("No overlay yet. The tuner writes one on its first change."));
    }
    out.push(overlay.node);

    const runs = section("Tuner runs, newest first");
    const runItems = arr(d.tuner_runs).map(obj);
    runs.body.append(runItems.length ? el("div", "stack", runItems.map(tunerRun)) : empty("The tuner has not run yet."));
    out.push(runs.node);

    const history = section("Overlay snapshots", { flush: true });
    const snaps = arr(d.history).map(obj);
    history.body.append(snaps.length
      ? table([{ label: "N", num: true }, { label: "Time" }, { label: "Action" }, { label: "Changes" }],
        snaps.map((s) => ({ cells: [num(s.n), timeNode(s.timestamp), str(s.action), tags(s.changes)] })), { short: true })
      : empty("No snapshots yet."));
    if (snaps.length) {
      history.head.append(el("span", { cls: "muted", text: "Restore with " }),
        el("code", { text: "python -m agents tune --rollback N" }));
    }
    out.push(history.node);

    const sources = section("Per-source state", { flush: true });
    const ss = obj(d.source_state);
    const items = arr(ss.items).map(obj);
    sources.body.append(items.length
      ? table([
        { label: "Source" }, { label: "Tags" }, { label: "Tarpit ms", num: true }, { label: "Budget" },
        { label: "Capture more" }, { label: "Plant token" }, { label: "Reasons" }, { label: "Updated" }, { label: "Expires" },
      ], items.map((s) => ({ cells: [mono(s.key), tags(s.tags), num(s.tarpit_ms), str(s.budget_mode),
        yesNo(s.capture_more), yesNo(s.plant_token), tags(s.reasons), timeNode(s.updated_at), timeNode(s.expires_at)] })))
      : empty("No per-source treatment is active."));
    append(sources.body, [pager(ss, hrefFor)]);
    out.push(sources.node);
    return out;
  }

  function tunerRun(run) {
    const changes = arr(run.changes).map(obj);
    const rejected = arr(run.rejected).map(str);
    const describe = (c) => Object.keys(c).filter((k) => k !== "kind" && k !== "reason")
      .map((k) => k + "=" + fmtValue(c[k])).join(" ");
    return el("div", "section",
      el("div", "section-head",
        el("h3", null, timeNode(run.timestamp)),
        run.snapshot !== null && run.snapshot !== undefined ? el("span", { cls: "muted", text: "snapshot " + str(run.snapshot) }) : null,
        el("span", "spacer"),
        run.commit ? mono(run.commit) : null,
        el("span", { cls: "faint mono", text: str(run.file) })),
      el("div", "section-body stack",
        changes.length ? table([{ label: "Applied" }, { label: "Details" }, { label: "Reason" }],
          changes.map((c) => ({ cells: [mono(c.kind), el("span", { cls: "mono wrap", text: describe(c) }), str(c.reason)] })), { short: true })
          : el("p", { cls: "muted", text: "No changes applied." }),
        rejected.length ? el("div", null, el("div", { cls: "label", text: "Rejected" }), textBlock(rejected.join("\n"), "bad")) : null));
  }

  // ---- screen: playbooks ----------------------------------------------------------------

  function viewPlaybooks(route, main) {
    setTitle("Playbooks");
    const cpage = pageParam(route.params, "cpage");
    const tpage = pageParam(route.params, "tpage");
    const here = (extra) => hashFor("/playbooks", Object.assign(
      { cpage: cpage > 1 ? cpage : "", tpage: tpage > 1 ? tpage : "" }, extra));
    const pbBody = el("div");
    const detections = section("Detections");
    const tokens = section("Honeytokens", { flush: true });
    main.append(pageHead("Playbooks"), pbBody, detections.node, tokens.node);

    return {
      refresh: async (kind) => {
        const quiet = kind !== "initial";
        const jobs = [fill(pbBody, () => apiGet(API.playbooks, { page: cpage, per: PER_PAGE }),
          (data) => drawPlaybooks(obj(data), (p) => here({ cpage: p })), quiet)];
        // Detections (an open file) and honeytokens (a revealed value) keep their state
        // through background polls.
        if (kind !== "poll") {
          jobs.push(fill(detections.body, () => apiGet(API.detections), (data) => drawDetections(obj(data)), quiet));
          jobs.push(fill(tokens.body, () => apiGet(API.honeytokens, { page: tpage, per: PER_PAGE }),
            (data) => drawHoneytokens(obj(data), tokens.head, (p) => here({ tpage: p })), quiet));
        }
        const results = await Promise.all(jobs);
        return results.every(Boolean);
      },
    };
  }

  function drawPlaybooks(d, hrefFor) {
    const out = [];
    const engine = obj(d.engine);
    const counts = obj(engine.counts);
    const errors = arr(d.errors).map(str);
    if (errors.length) {
      out.push(notice("bad", el("div", { text: plural(errors.length, "playbook file failed", "playbook files failed") + " validation and will not run." }),
        el("div", "stack", errors.map((e) => textBlock(e)))));
    }

    const books = arr(d.playbooks).map(obj);
    const list = section("Playbooks (" + num(books.length) + ")");
    list.body.append(books.length ? el("div", "cards", books.map((pb) => playbookCard(pb, counts)))
      : empty("No playbooks are installed."));
    out.push(list.node);

    const eng = section("Engine today" + (engine.day ? ", " + str(engine.day) : ""));
    const sent = obj(engine.notify_sent);
    const cooldowns = obj(engine.cooldowns);
    const cdItems = arr(cooldowns.items).map(obj);
    eng.body.append(el("div", "grid-2",
      el("div", null, el("div", { cls: "label", text: "Notifications sent" }),
        Object.keys(sent).length
          ? table([{ label: "Connector" }, { label: "Sent", num: true }],
            Object.keys(sent).map((k) => ({ cells: [mono(k), num(sent[k])] })), { short: true })
          : empty("None today.")),
      el("div", null, el("div", { cls: "label", text: "Active cooldowns" }),
        cdItems.length
          ? table([{ label: "Playbook" }, { label: "Source" }, { label: "Last run" }],
            cdItems.map((c) => {
              const key = str(c.key);
              const cut = key.indexOf("|");
              return { cells: [mono(cut >= 0 ? key.slice(0, cut) : key), mono(cut >= 0 ? key.slice(cut + 1) : ""), timeNode(c.at)] };
            }), { short: true })
          : empty("No cooldowns."),
        pager(cooldowns, hrefFor))));
    out.push(eng.node);
    return out;
  }

  function playbookCard(pb, counts) {
    const enabled = pb.enabled === true;
    const name = str(pb.name);
    const runs = Object.prototype.hasOwnProperty.call(counts, name) ? counts[name] : pb.runs_today;
    const steps = arr(pb.steps).map(obj);
    const when = obj(pb.when);
    const stepNodes = [];
    steps.forEach((s, i) => {
      if (i) stepNodes.push(el("span", { cls: "step-arrow", text: ">", attrs: { "aria-hidden": "true" } }));
      stepNodes.push(el("span", "step", mono(s.action), tierBadge(s.tier)));
    });
    return el("article", enabled ? "section pb-card enabled" : "section pb-card",
      el("div", "section-head",
        el("h3", { cls: "mono", text: name }),
        enabled ? badge("enabled", "st-ok") : badge("disabled", "st-neutral"),
        pb.priority === true ? el("span", { cls: "tag", text: "priority" }) : null),
      el("div", "section-body stack",
        pb.description ? el("p", { cls: "prose", text: str(pb.description) }) : null,
        kv([
          ["Runs today", num(runs) + (typeof pb.max_runs_per_day === "number" ? " of " + num(pb.max_runs_per_day) : "")],
          ["Cooldown", typeof pb.cooldown_minutes === "number" ? num(pb.cooldown_minutes) + " min" : "-"],
          ["Steps", steps.length ? el("span", "steps", stepNodes) : "none"],
          ["When", Object.keys(when).length
            ? tags(Object.keys(when).map((k) => k + ": " + fmtValue(when[k]))) : "any record"],
        ])));
  }

  function drawDetections(d) {
    const viewer = el("div", null, empty("Choose a file to read it."));
    let current = null;
    const groups = [["pending", "Pending review"], ["approved", "Approved"]].map(([kind, title]) => {
      const names = arr(d[kind]).filter((n) => typeof n === "string" && DETECTION_RE.test(n));
      return el("div", "pick-group", el("div", { cls: "label", text: title + " (" + num(names.length) + ")" }),
        names.length ? el("ul", "pick-list", names.map((name) => {
          const b = el("button", { attrs: { type: "button" }, text: name });
          b.addEventListener("click", () => {
            if (current) current.removeAttribute("aria-current");
            current = b;
            b.setAttribute("aria-current", "true");
            fill(viewer, () => apiGet(API.detection(kind, name)), (f) => {
              const file = obj(f);
              return el("div", "stack",
                el("div", "hit-line", el("strong", { cls: "mono", text: name }),
                  el("span", { cls: "muted", text: kind }),
                  file.truncated === true ? el("span", { cls: "muted", text: "(cut at 200,000 characters)" }) : null),
                textBlock(file.text, "tall"));
            }, false);
          });
          return el("li", null, b);
        })) : el("div", { cls: "state", text: "None." }));
    });
    return el("div", "split", el("div", null, groups), viewer);
  }

  function drawHoneytokens(d, head, hrefFor) {
    const tokens = obj(d.tokens);
    const items = arr(tokens.items).map(obj);
    const old = head.querySelector(".scenario");
    if (old) old.remove();
    if (d.scenario) head.append(el("span", { cls: "muted scenario", text: "scenario " + str(d.scenario) }));
    if (!items.length) return empty("No honeytokens are registered.");
    return [table([
      { label: "Name" }, { label: "Kind" }, { label: "Planted in" }, { label: "For source" },
      { label: "Legacy" }, { label: "Hits", num: true }, { label: "Value" },
    ], items.map((t) => ({
      cells: [mono(t.name), str(t.kind), tags(t.planted_in), t.planted_for ? mono(t.planted_for) : "-",
        yesNo(t.legacy), num(t.hits), secretCell(t)],
    }))), pager(tokens, hrefFor)];
  }

  // Masked value with a Reveal control. One token is revealed at a time, only after an
  // explicit click, and it is masked again after a minute or on navigation.
  function secretCell(t) {
    const name = str(t.name);
    const masked = str(t.value);
    const value = el("span", { cls: "secret", text: masked });
    if (!TOKEN_NAME_RE.test(name)) return value;
    const toggle = button("Reveal", () => {
      if (state.revealed && state.revealed.value === value) {
        hideRevealed();
      } else {
        reveal();
      }
    }, "btn-small");
    const cell = el("span", "hit-line", value, toggle);

    async function reveal() {
      hideRevealed();
      toggle.disabled = true;
      try {
        const res = obj(await apiGet(API.honeytokens, { reveal: name }));
        value.textContent = str(res.value);
        value.classList.add("revealed");
        toggle.textContent = "Hide";
        const timer = setTimeout(hideRevealed, REVEAL_MS);
        state.revealed = {
          value: value,
          hide: () => {
            clearTimeout(timer);
            value.textContent = masked;
            value.classList.remove("revealed");
            toggle.textContent = "Reveal";
          },
        };
      } catch (err) {
        if (err.status !== 401) value.textContent = masked + " (reveal failed: " + err.message + ")";
      } finally {
        toggle.disabled = false;
      }
    }
    return cell;
  }

  function hideRevealed() {
    if (!state.revealed) return;
    const r = state.revealed;
    state.revealed = null;
    r.hide();
  }

  // ---- screen: not found ----------------------------------------------------------------

  function viewNotFound(route, main) {
    setTitle("Not found");
    main.append(pageHead("Not found"), el("p", null, "There is no such page. ", link("#/", "Go to the overview"), "."));
    return {};
  }

  // ---- start ----------------------------------------------------------------------------

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
