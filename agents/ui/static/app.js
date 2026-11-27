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
  const MORE_LINES = 6;
  const MORE_CHARS = 600;

  // Same patterns the server enforces (agents/ui/api.py).
  const RECORD_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;
  const APPROVAL_ID_RE = /^a-[0-9a-f]{12}$/;
  const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
  const DETECTION_RE = /^[0-9a-f]{8}-[a-z0-9-]{1,60}\.yml$/;
  const TOKEN_NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/;
  const PROTOCOL_RE = /^[a-z0-9]{1,16}$/;
  const COUNTRY_RE = /^[A-Z]{2}$/;
  const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;
  const COMPACT_TIME_RE = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/;
  const SESSION_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
  // An IPv4 or IPv6 address as the log writes it: only these characters reach a link.
  const ADDRESS_RE = /^[0-9A-Fa-f:.]{2,45}$/;
  const USER_TIME_RE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:\d{2})?)?$/;

  // Every API path this page requests. Ids are checked against their pattern by the caller
  // and URL-encoded here as well.
  const enc = encodeURIComponent;
  const API = {
    session: "/api/session",
    overview: "/api/overview",
    records: "/api/records",
    record: (id) => "/api/records/" + enc(id),
    transcript: (id) => "/api/records/" + enc(id) + "/transcript",
    replies: (id) => "/api/records/" + enc(id) + "/replies",
    activity: "/api/activity",
    activitySession: (id) => "/api/activity/session/" + enc(id),
    queue: "/api/queue",
    approve: (id) => "/api/queue/" + enc(id) + "/approve",
    reject: (id) => "/api/queue/" + enc(id) + "/reject",
    blocklist: "/api/blocklist",
    unblock: "/api/blocklist/unblock",
    enforce: "/api/blocklist/enforce",
    digests: "/api/digests",
    digest: (day) => "/api/digests/" + enc(day),
    decoy: "/api/decoy",
    playbooks: "/api/playbooks",
    detections: "/api/detections",
    detection: (kind, name) => "/api/detections/" + enc(kind) + "/" + enc(name),
    honeytokens: "/api/honeytokens",
    map: "/api/map",
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
  const ACTIVITY_KINDS = [
    ["connection", "Connection"], ["login", "Login attempt"], ["input", "Input"], ["reply", "Reply"],
    ["request", "Request"], ["transfer", "Transfer"], ["register", "Register"], ["call", "Call attempt"],
    ["error", "Error"], ["close", "Close"], ["other", "Other"],
  ];
  const ACTIVITY_KIND_LABEL = Object.fromEntries(ACTIVITY_KINDS);
  const ACTIVITY_WINDOWS = { "1h": 3600000, "24h": 86400000, "7d": 7 * 86400000 };

  const SECTIONS = [
    { key: "overview", label: "Overview", hash: "#/" },
    { key: "queue", label: "Queue", hash: "#/queue" },
    { key: "records", label: "Records", hash: "#/records" },
    { key: "digests", label: "Digests", hash: "#/digests" },
    { key: "decoy", label: "Decoy", hash: "#/decoy" },
    { key: "playbooks", label: "Playbooks", hash: "#/playbooks" },
    { key: "activity", label: "Activity", hash: "#/activity" },
    { key: "map", label: "Map", hash: "#/map" },
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
      // The server caps list and dict sizes and drops keys with hidden characters, and says
      // so with a top-level flag (a digest or detection uses the same flag for its text and
      // shows its own note).
      const d = obj(data);
      if (d.truncated === true && typeof d.text !== "string") {
        append(target, [el("p", { cls: "muted", text: "Part of this answer was cut at the server's size limits." })]);
      }
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

  // One line under a screen's title saying what the screen is.
  function intro(text) {
    return el("p", { cls: "intro", text: text });
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

  // A record's narrative laid out in parts (headline, who / volume / target, what they did,
  // what it means, not seen) from the server's "layout" object. Every value is model or
  // attacker text and goes in as a text node. A record without parts (written before they
  // existed) shows its paragraph instead: through textBlock when "block" is set, otherwise
  // as a plain line.
  function narrativeView(layout, narrative, block) {
    const l = obj(layout);
    if (l.structured !== true) {
      return block ? textBlock(narrative) : el("div", { cls: "hit-narrative", text: str(narrative) });
    }
    const joined = (v) => arr(v).map(str).join(", ");
    const list = (title, items) => arr(items).length
      ? el("div", "nl-block", el("div", { cls: "label", text: title }),
        el("ul", "nl-list", arr(items).map((i) => el("li", { text: str(i) }))))
      : null;
    return el("div", "narrative-layout",
      str(l.headline) ? el("div", "nl-head", el("strong", { text: str(l.headline) }),
        el("span", { cls: "muted", text: " (" + str(l.judgement) + ")" })) : null,
      kv([
        ["Who", el("span", { cls: "wrap", text: joined(l.who) })],
        ["Volume", el("span", { text: joined(l.volume) })],
        ["Target", el("span", { cls: "wrap", text: joined(l.target) })],
      ]),
      list("What they did", l.actions),
      list("What it means", l.assessment),
      arr(l.not_seen).length ? el("p", { cls: "muted", text: "Not seen: " + joined(l.not_seen) }) : null);
  }

  // Short identifier (address, id, name): one line inside tables.
  function mono(text) {
    return el("span", { cls: "mono", text: str(text) });
  }

  // Where an address is (city, country, network owner) from the server's "geo" object, as
  // muted text after the address; nothing when the lookup is off or knows nothing. The
  // text comes from a database file, so it is a text node like everything else.
  function geoText(geo) {
    const short = str(obj(geo).short);
    return short ? el("span", { cls: "muted", text: " · " + short }) : null;
  }

  function addressNode(addr, geo) {
    return el("span", null, mono(addr), geoText(geo));
  }

  // What Shodan InternetDB knew about an address, from the server's "shodan" object: a
  // compact line that opens to the full lists, the lookup date and the credit. Nothing when
  // the feature is off or the file has no answer. Third-party data (host names are
  // attacker-influenced), so text nodes only, like everything else.
  function shodanNode(info, opts) {
    const s = obj(info);
    const short = str(s.short);
    if (!short) return null;
    const o = obj(opts);
    const list = (label, items) => arr(items).length
      ? [label, el("span", { cls: "mono wrap", text: arr(items).map(str).join(", ") })] : null;
    return el("details", "shodan",
      el("summary", { cls: "muted", text: (o.prefix ? "Shodan: " : "") + short }),
      kv([list("Ports", s.ports), list("Tags", s.tags), list("Known CVEs", s.vulns),
        list("Host names", s.hostnames), list("CPEs", s.cpes),
        ["Looked up", el("span", null, str(s.looked_up),
          o.note ? el("span", { cls: "muted", text: o.note }) : null)]]),
      el("div", { cls: "faint", text: "Data from Shodan InternetDB." }));
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
    // The title can name a target, so it is text only; the group gets a fixed label.
    const panel = el("div", { cls: opts.danger ? "confirm confirm-danger" : "confirm",
      attrs: { role: "group", "aria-label": "Confirmation" } },
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
      text: "Keys: 1-8 switch sections, r refreshes, / searches records or activity, Esc closes a confirmation." });
    // [geoip] attribution (free databases require credit), plain text.
    const credit = str(state.session.attribution);
    document.body.replaceChildren(header, shell.main, el("div", "main", hint,
      credit ? el("div", { cls: "footer-hint", text: credit }) : null));
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
    const [a, b, c, d] = route.parts;
    if (d !== undefined || (c !== undefined && a !== "activity")) return { view: viewNotFound, key: null };
    if (!a) return { view: viewOverview, key: "overview" };
    if (a === "queue" && !b) return { view: viewQueue, key: "queue" };
    if (a === "records" && !b) return { view: viewRecords, key: "records" };
    if (a === "records") return { view: viewRecord, key: "records" };
    if (a === "digests") return { view: viewDigests, key: "digests" };
    if (a === "decoy" && !b) return { view: viewDecoy, key: "decoy" };
    if (a === "playbooks" && !b) return { view: viewPlaybooks, key: "playbooks" };
    if (a === "activity" && !b) return { view: viewActivity, key: "activity" };
    if (a === "activity" && b === "session" && c !== undefined) return { view: viewActivitySession, key: "activity" };
    if (a === "map" && !b) return { view: viewMap, key: "map" };
    return { view: viewNotFound, key: null };
  }

  function render() {
    if (state.signedOut) return;
    if (state.confirm) {
      state.confirm.busy = false;
      closeConfirm();
    }
    hideRevealed();
    // A screen with its own timers (the map) stops them before the next one is drawn.
    if (state.view && state.view.stop) state.view.stop();
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
    } else if (/^[1-8]$/.test(ev.key)) {
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
    main.append(pageHead("Overview", toggle),
      intro("What the sensor has seen lately and whether the pipeline is healthy. Start here."), body);
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
        top.map((s) => ({ cells: [el("div", null, addressNode(s.src_ip, s.geo), shodanNode(s.shodan, { prefix: true })),
          num(s.records), judgementBadge(s.worst)] })),
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
        addressNode(r.src_ip, r.geo),
        tags(r.honeytokens),
        el("span", "faint", timeNode(r.last_seen || r.first_seen))),
      narrativeView(r.layout, r.narrative))));
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

    const calls = obj(h.analyst_calls);
    const [callLevel, callText] = usage(calls, "calls");
    rows.push(["Analyst calls", callLevel, typeof calls.reused === "number" && calls.reused > 0
      ? callText + " " + num(calls.reused) + " reused today." : callText]);
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
        (typeof f.lines === "number" ? " (" + plural(f.lines, "line", "lines") + ")" : "") + "."]]);
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
    main.append(pageHead("Approval queue", toggle),
      intro("Actions the playbooks want to take that wait for a person to approve or reject them, " +
        "and the blocklist those approvals feed."), noticeBox);
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
    ctx.track = obj(data.mode).track_before_enforce === true;
    const items = arr(data.items).filter((it) => obj(obj(it).approval).status === "pending");
    if (!items.length) return empty("Nothing is waiting for a decision.");
    const more = typeof data.total === "number" && data.total > arr(data.items).length
      ? el("p", { cls: "muted", text: "Showing the newest " + num(arr(data.items).length) + " of " + num(data.total) + " pending items." })
      : null;
    return [more, el("div", "cards", items.map((it) => approvalCard(obj(it), ctx)))];
  }

  // The detection files a publish_detection approval names, as the server listed them
  // (names it checked against DETECTION_FILE_RE; checked here again). Text nodes only.
  function detectionFiles(item) {
    return arr(item.detection_files).map((f) => obj(f))
      .filter((f) => typeof f.name === "string" && DETECTION_RE.test(f.name));
  }

  function fileNames(files) {
    if (!files.length) return el("span", { cls: "muted", text: "(no files listed)" });
    return el("span", "wrap", files.map((f, i) => [i ? ", " : null, mono(f.name),
      f.present === false ? el("span", { cls: "muted", text: " (no longer pending)" }) : null]));
  }

  function approvalCard(item, ctx) {
    const a = obj(item.approval);
    // Decisions go to the approval file's own name (item.id). The server marks an item
    // decidable only when the id inside the file is the same and every value it acts on
    // is shown exactly; this checks the id again.
    const id = typeof item.id === "string" && APPROVAL_ID_RE.test(item.id) ? item.id : null;
    const record = item.record && typeof item.record === "object" ? item.record : null;
    // publish_detection acts on files, not on the source: the files are its target, and the
    // source is context.
    const publish = a.action === "publish_detection";
    const files = publish ? detectionFiles(item) : [];

    const head = el("div", "card-title", mono(a.action),
      publish ? [" of ", fileNames(files), el("span", { cls: "muted", text: " from " }), mono(a.subject)]
        : [" on ", mono(a.subject), geoText(item.geo)]);
    const headRow = el("div", "card-head", head,
      statusBadge(a.status), tierBadge(a.tier),
      a.unverified_source === true ? badge("source may be forged", "st-bad") : null);

    const params = obj(a.params);
    const paramPairs = publish
      ? [["Files", fileNames(files)], ["Source", mono(a.subject)]]
      : Object.keys(params).map((k) => [k, el("span", { cls: "mono wrap", text: fmtValue(params[k]) })]);
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
          geoText(record.geo || (record.src_ip === a.subject ? item.geo : null)),
          record.unverified_source === true ? el("span", { cls: "muted", text: " (unverified)" }) : null)],
        ["Last seen", timeNode(record.last_seen || record.first_seen)],
        ["User", clip(record.username)],
        ["Activity", num(record.commands) + " commands, " + num(record.auth_successes) + "/" +
          num(record.auth_attempts) + " logins"],
        ["Honeytokens", tags(record.honeytokens)],
      ]),
      narrativeView(record.layout, record.narrative),
      recordHref(record.id) ? link(recordHref(record.id), "Open record") : null)
      : el("div", "stack", el("p", { cls: "muted", text: "The triggering record is no longer stored." }),
        kv([["Record id", mono(a.record_id)]]));

    const body = el("div", "card-body", why,
      el("div", null, el("div", { cls: "label", text: "Triggering record" }), facts));

    const foot = el("div", "card-foot", el("span", { cls: "muted", text: "Id " }), mono(id || a.id), el("span", "spacer"));
    const card = el("article", "card", headRow, body, foot);
    if (id) ctx.cards.set(id, card);

    if (a.status === "pending" && item.can_decide_here !== true && typeof item.undecidable_reason === "string") {
      // Not decidable here: say why (a fixed server text) and where to decide it.
      foot.append(el("span", { cls: "muted",
        text: "Cannot be decided in the console: " + item.undecidable_reason + ". Check the file and use the CLI. " }));
    }

    const viewHash = typeof item.view_hash === "string" ? item.view_hash : null;
    if (ctx.actions && id && viewHash && a.status === "pending" && item.can_decide_here === true && a.id === id) {
      const target = str(a.subject);
      const action = str(a.action);
      const names = files.map((f) => f.name);
      // Built per panel: a node can sit in one panel only.
      const rows = () => publish
        ? [["Action", mono(action)], ["Files", fileNames(files)], ["Source", mono(target)],
          ["Approval", mono(id)], ["Playbook", mono(a.playbook)]]
        : [["Action", mono(action)], ["Target", mono(target)], ["Approval", mono(id)],
          ["Playbook", mono(a.playbook)]];
      // With two stages, approving export_blocklist or block_webhook only tracks the
      // address (enforce is what blocks and calls the block connector); say so.
      const tracking = ctx.track === true && (action === "export_blocklist" || action === "block_webhook");
      const approveTitle = publish
        ? "Approve and publish " + plural(names.length, "detection file", "detection files") + ": " + names.join(", ") + "?"
        : tracking ? "Approve and track " + target + "?"
          : "Approve and run " + action + " on " + target + "?";
      // Reject works for every pending item. Approve only when this process can run the
      // action (open_ticket and block_webhook need a connector the console usually lacks).
      if (item.can_approve_here !== true) {
        foot.append(el("span", { cls: "muted",
          text: "This action needs a connector; approve it with the CLI in the agents container. " }));
      }
      foot.append(
        button("Reject", () => openConfirm(foot, {
          title: "Reject " + id + "?",
          rows: rows(),
          note: "Nothing is executed. The item is closed as rejected.",
          confirmLabel: "Reject",
          danger: false,
          onConfirm: () => decide("reject", id, viewHash, ctx),
        })));
      if (item.can_approve_here === true) {
        foot.append(button("Approve", () => openConfirm(foot, {
          title: approveTitle,
          rows: rows(),
          note: tracking
            ? "Approving adds " + target + " to the tracked list (tracked.json) for your cloud to watch. " +
              "Nothing is blocked and no connector is called; enforcing it is a separate decision " +
              "on the blocklist below."
            : "Approving runs the action now. It can take as long as the action does.",
          confirmLabel: tracking ? "Approve and track" : "Approve and run",
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
          a.record_id ? recordLink(a.record_id, clip(a.record_id)) : "-", mono(it.id)],
      };
    });
    const wrap = items.length ? table([
      { label: "Status" }, { label: "Action" }, { label: "Target" }, { label: "Playbook" },
      { label: "Decided" }, { label: "By" }, { label: "Result" }, { label: "Record" }, { label: "Id" },
    ], rows) : empty("No closed items on this page.");
    for (const [i, it] of items.entries()) {
      const id = it.id;   // the approval file's name
      if (typeof id === "string" && APPROVAL_ID_RE.test(id) && !ctx.cards.has(id)) {
        ctx.cards.set(id, wrap.querySelectorAll("tbody tr")[i]);
      }
    }
    return [wrap, pager(data, hrefFor)];
  }

  function drawBlocklist(data, ctx, hrefFor) {
    const items = arr(data.items).map((it) => obj(it));
    // The server adds mode (and per-entry status and sightings) only when entries have two
    // stages; otherwise the list is drawn as one stage.
    if (data.mode && typeof data.mode === "object") return drawStagedBlocklist(data, items, ctx, hrefFor);
    if (!items.length) return empty("The blocklist is empty.");
    const columns = [{ label: "Target" }, { label: "Approved" }, { label: "Expires" }];
    if (ctx.actions) columns.push({ label: "" });
    const wrap = table(columns, items.map((it) => {
      const target = str(it.target);
      const cells = [addressNode(target, it.geo), timeNode(it.approved_at), timeNode(it.expires_at)];
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

  const STAGE_LABEL = { tracked: "Tracked", enforced: "Enforced" };
  const STAGE_CLASS = { tracked: "st-pending", enforced: "st-bad" };

  // Where the sightings file stands: age, stale or refused. All text nodes.
  function sightingsLine(info) {
    const s = obj(info);
    if (s.state === "missing") {
      return el("p", { cls: "muted", text: "No sightings file yet. Sightings are display only; see docs/operations.md." });
    }
    const parts = [];
    if (s.generated_at) {
      parts.push(el("span", null, "Sightings file generated ", timeNode(s.generated_at), "."));
    }
    if (s.stale === true) {
      parts.push(" ", badge("stale", "st-bad"),
        el("span", { text: " older than " + num(s.stale_hours) + " hours; counts may be out of date." }));
    }
    if (s.state === "invalid") {
      parts.push(" ", badge("refused", "st-bad"),
        el("span", { text: " The newest file was refused (" + str(s.error) + ")" +
          (s.generated_at ? "; showing the last good copy." : "; nothing to show.") }));
    }
    return el("p", { cls: "muted" }, parts);
  }

  function sightingsCell(sum) {
    const s = obj(sum);
    const rows = arr(s.rows).map((r) => obj(r));
    if (!rows.length) return el("span", { cls: "faint", text: "No sightings yet" });
    const head = el("div", null, el("strong", { text: num(s.total) }),
      el("span", { cls: "muted", text: " seen in " + plural(num(s.places), "place", "places") + ", last " }),
      timeNode(s.last_seen));
    const detail = table([{ label: "Where" }, { label: "Service" }, { label: "Count", num: true },
      { label: "Last seen" }, { label: "Source" }],
    rows.map((r) => ({ cells: [clip(r.where), clip(r.service), num(r.count), timeNode(r.last_seen), clip(r.source)] })),
    { short: true });
    return el("div", "stack", head, detail);
  }

  function drawStagedBlocklist(data, items, ctx, hrefFor) {
    const mode = obj(data.mode);
    const fileName = str(mode.blocklist_file) || "the blocklist file";
    const trackedName = str(mode.tracked_file) || "tracked.json";
    const line = sightingsLine(data.sightings);
    if (!items.length) return [line, empty("The blocklist is empty.")];
    const columns = [{ label: "Target" }, { label: "Status" }, { label: "Since" }, { label: "Expires" },
      { label: "Sightings" }];
    if (ctx.actions) columns.push({ label: "" });
    const wrap = table(columns, items.map((it) => {
      const target = str(it.target);
      const stage = it.status === "enforced" ? "enforced" : "tracked";
      const since = stage === "enforced" && it.enforced_at ? it.enforced_at : it.approved_at;
      const cells = [addressNode(target, it.geo), badge(STAGE_LABEL[stage], STAGE_CLASS[stage]), timeNode(since),
        timeNode(it.expires_at), sightingsCell(it.sightings)];
      if (ctx.actions) {
        const cell = el("span", "stack");
        const viewHash = typeof it.view_hash === "string" ? it.view_hash : null;
        if (stage === "tracked" && viewHash) {
          const connector = mode.block_connector === true
            ? "The block connector is enabled and will be called with " + target + "."
            : "The block connector is not enabled here, so nothing is sent to it.";
          cell.append(button("Enforce", () => openConfirm(wrap, {
            title: "Enforce " + target + "?",
            rows: [["Target", mono(target)], ["Now", el("span", { text: "Tracked" })],
              ["After", el("span", { text: "Enforced" })]],
            note: "This blocks it: " + target + " is added to " + fileName + " (what your firewall loads) and " +
              "marked enforced in " + trackedName + ". " + connector + " Unblock removes it again.",
            confirmLabel: "Enforce",
            danger: true,
            onConfirm: () => enforceEntry(target, viewHash, ctx),
          }), "btn-small btn-danger"));
        }
        cell.append(button("Unblock", () => openConfirm(wrap, {
          title: "Remove " + target + " from the blocklist?",
          rows: [["Target", mono(target)], ["Status", el("span", { text: STAGE_LABEL[stage] })]],
          note: "It is removed from " + trackedName + (stage === "enforced" ? " and from " + fileName : "") +
            ". Every live entry equal to or inside this address or network is removed.",
          confirmLabel: "Unblock",
          danger: true,
          onConfirm: () => unblock(target, ctx),
        }), "btn-small btn-danger"));
        cells.push(cell);
      }
      return { cells };
    }));
    return [line, wrap, pager(data, hrefFor)];
  }

  async function enforceEntry(target, viewHash, ctx) {
    try {
      const res = obj(await apiPost(API.enforce, { target: target, view_hash: viewHash }));
      const conn = obj(res.connector);
      const level = conn.ok === false ? "warn" : "ok";
      ctx.say(level, el("div", null, "Enforced " + str(res.target) + "; it is in " + str(res.file) + "."),
        el("div", null, "Block connector: ", el("span", { cls: "mono wrap", text: str(conn.status) })));
    } catch (err) {
      if (err.status === 401) return;
      if (err.status === 409) {
        ctx.say("warn", "The entry for " + target + " changed after this page loaded, so nothing was enforced. " +
          "The list has been reloaded; check it and decide again.");
      } else {
        ctx.say("bad", "Enforce " + target + " was refused: ", el("span", { cls: "mono wrap", text: err.message }));
      }
    }
    await ctx.reload();
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
    const country = (params.get("country") || "").trim().toUpperCase();
    return {
      kind: pick("kind", ["session", "campaign"]),
      protocol: PROTOCOL_RE.test(protocol) ? protocol : "",
      judgement: pick("judgement", JUDGEMENTS),
      honeytoken: pick("honeytoken", ["1", "0"]),
      src: (params.get("src") || "").trim().slice(0, 64),
      country: COUNTRY_RE.test(country) ? country : "",
      q: (params.get("q") || "").slice(0, 200),
      sort: pick("sort", ["rank"]),
    };
  }

  function viewRecords(route, main) {
    setTitle("Records");
    const f = recordFilters(route.params);
    const page = pageParam(route.params, "page");
    const active = Boolean(f.kind || f.protocol || f.judgement || f.honeytoken || f.src || f.country || f.q);

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
      input("country", "Country", "code, e.g. DE"),
      select("sort", "Sort", [["", "Newest"], ["rank", "Rank"]]),
      el("button", { cls: "btn btn-primary", attrs: { type: "submit" }, text: "Apply" }),
      active ? link("#/records", "Clear filters") : null);
    form.elements.namedItem("q").setAttribute("data-search", "");
    const protocolInput = form.elements.namedItem("protocol");
    protocolInput.addEventListener("input", () => protocolInput.setCustomValidity(""));
    const countryInput = form.elements.namedItem("country");
    countryInput.addEventListener("input", () => countryInput.setCustomValidity(""));
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      apply();
    });

    function apply() {
      const data = new FormData(form);
      const next = {};
      for (const key of ["q", "kind", "protocol", "judgement", "honeytoken", "src", "country", "sort"]) {
        next[key] = String(data.get(key) || "").trim();
      }
      next.protocol = next.protocol.toLowerCase();
      next.country = next.country.toUpperCase();
      if (next.country && !COUNTRY_RE.test(next.country)) {
        countryInput.setCustomValidity("Two letters, the country's ISO code (DE, US, ...).");
        form.reportValidity();
        return;
      }
      if (next.protocol && !PROTOCOL_RE.test(next.protocol)) {
        form.elements.namedItem("protocol").setCustomValidity("Letters and digits only, up to 16.");
        form.reportValidity();
        return;
      }
      location.hash = hashFor("/records", next);
    }

    const filterSection = el("section", "section", form);
    const results = section("Records", { flush: true });
    main.append(pageHead("Records"),
      intro("Triaged sessions and campaigns: what each source did and how serious it looks. Open one for the detail."),
      filterSection, results.node);

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
          addressNode(r.src_ip, r.geo),
          clip(r.username),
          num(r.commands),
          num(r.auth_successes) + "/" + num(r.auth_attempts),
          tags(r.honeytokens),
          el("span", { cls: "clip clip-wide", text: str(obj(r.layout).headline) || str(r.narrative) }),
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
      el("span", { cls: "muted", text: r.llm_used === true ? "model-assisted triage"
        : r.analysis_reused === true ? "model-assisted triage (stored analysis)" : "rule-based triage" })));

    out.push(el("section", "section", el("div", "section-body", el("div", "facts",
      fact("Source", el("span", null, mono(r.src_ip),
        r.unverified_source === true ? el("span", { cls: "muted", text: " (may be forged)" }) : null)),
      data.geo ? fact("Where", el("span", "wrap", str(obj(data.geo).short),
        el("span", { cls: "muted", text: data.geo_stored === true ? " (when recorded)" : " (looked up now)" }))) : null,
      data.shodan ? fact("Shodan", shodanNode(data.shodan,
        { note: data.shodan_stored === true ? " (when recorded)" : " (latest lookup)" })) : null,
      fact("First seen", timeNode(r.first_seen)),
      fact("Last seen", timeNode(r.last_seen)),
      fact("Username", clip(r.username)),
      fact("Logins", num(r.auth_successes) + " of " + num(r.auth_attempts)),
      fact("Connections", num(r.connections)),
      fact("Commands", num(r.commands))))));

    const narrative = section("Narrative");
    narrative.body.append(narrativeView(data.layout, r.narrative, true));
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
    const sample = arr(r.command_sample).map(str);
    // An SSH session's commands are shown with what the decoy answered to each; a campaign
    // keeps its sample (commands from many connections, with no single sequence).
    const replies = r.kind === "session" && r.protocol === "ssh" && data.transcript_available === true && sample.length;
    const commands = section(replies ? "Commands and replies" : "Command sample");
    commands.body.append(replies ? commandReplies(id) : sample.length ? textBlock(sample.join("\n")) : empty("No commands recorded."));
    commands.body.append(el("p", null, rawActivityLink(r, id)));
    out.push(el("div", "grid-2", creds.node, commands.node));

    const findings = findingsSection(data.findings);
    if (findings) out.push(findings);
    const sequence = arr(r.request_sequence).map(obj);
    if (sequence.length) out.push(requestSequence(r, id, sequence));

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
      const places = obj(data.address_geo);
      sources.body.append(Object.keys(places).length
        ? el("ul", null, addresses.map((a) => el("li", null, addressNode(a, places[a]))))
        : tags(addresses));
      out.push(sources.node);
    }

    if (r.kind === "session" && r.protocol === "ssh") {
      const transcript = section("Transcript");
      // A session too large to replay is said up front, with the server's fixed text naming
      // the command that reads it from the log, instead of a transcript that answers 422.
      transcript.body.append(typeof data.transcript_withheld === "string"
        ? notice("warn", el("span", { cls: "wrap", text: data.transcript_withheld }))
        : data.transcript_available === true
          ? transcriptView(id)
          : empty("Transcript not available: the session's lines are no longer in the current event log."));
      out.push(transcript.node);
    }
    return out;
  }

  // From a record to its raw events: a session's own view, or a campaign's source and
  // service over its time span.
  // A record's behaviour and indicator matches from the server's "findings" object, each
  // with its confidence; an indicator match also shows where its fact comes from. Source
  // URLs are shown as text, not links. Nothing when the record matched nothing.
  function findingsSection(findings) {
    const f = obj(findings);
    const behaviours = arr(f.behaviours).map(obj);
    const indicators = arr(f.indicators).map(obj);
    if (!behaviours.length && !indicators.length) return null;
    const like = arr(f.like).map(str).filter(Boolean);
    const s = section("Behaviours and indicators");
    s.body.append(el("p", { cls: "muted",
      text: "Pattern and list matches: shown for context, never used for the judgement or the blocklist." }));
    if (behaviours.length) {
      s.body.append(el("ul", "nl-list", behaviours.map((b) => {
        const span = typeof b.first_seq === "number" && typeof b.last_seq === "number"
          ? ", requests #" + num(b.first_seq) + " to #" + num(b.last_seq) : "";
        return el("li", null, el("strong", { text: str(b.label) }),
          like.length ? el("span", { text: " (" + like.map((x) => x + "-like").join(", ") + ")" }) : null,
          el("span", { cls: "muted", text: " · " + str(b.confidence) + " confidence · count " + num(b.count) + span }));
      })));
    }
    if (indicators.length) {
      s.body.append(el("ul", "nl-list", indicators.map((m) => {
        const p = obj(m.provenance);
        const reported = str(p.reported);
        return el("li", null,
          el("strong", { text: str(m.label) }),
          el("span", { cls: "muted", text: " · " + str(m.confidence) + " confidence · " + num(m.count) + " hit" + (m.count === 1 ? "" : "s") }),
          m.provenance ? el("div", { cls: "faint wrap",
            text: "Reported " + (reported || "-") + " by " + arr(p.sources).map(str).join(", ") }) : null,
          str(p.notes) ? el("div", { cls: "faint wrap", text: str(p.notes) }) : null);
      })));
    }
    return s.node;
  }

  // An HTTP campaign's requests in order, with seconds since the first one. Every cell is
  // attacker or scenario text, set as text.
  function requestSequence(r, id, rows) {
    const total = typeof r.commands === "number" ? r.commands : rows.length;
    const s = section("Request sequence" + (total > rows.length ? " (first " + num(rows.length) + " of " + num(total) + ")" : ""), { flush: true });
    const target = (e) => str(e.path) + (str(e.query) ? "?" + str(e.query) : "");
    s.body.append(table([
      { label: "#", num: true }, { label: "+s", num: true }, { label: "Request" },
      { label: "Status", num: true }, { label: "Route" }, { label: "Found in" }, { label: "Flow" },
      { label: "Marker" }, { label: "Client" }],
    rows.map((e) => ({ cells: [
      typeof e.seq === "number" ? num(e.seq) : "-",
      typeof e.offset === "number" ? num(e.offset) : "-",
      el("span", { cls: "mono wrap", text: str(e.method) + " " + target(e) }),
      typeof e.status === "number" ? num(e.status) : "-",
      mono(e.route || e.lure || "-"),
      mono(e.discovered_via || "-"),
      mono(e.flow ? str(e.flow) + (e.flow_step ? " / " + str(e.flow_step) : "") : "-"),
      mono(e.marker ? str(e.marker) + (e.marker_src === true ? " (other source)" : "") : "-"),
      clip(e.client || "-")] }))));
    s.body.append(el("p", null, rawActivityLink(r, id)));
    return s.node;
  }

  function rawActivityLink(r, id) {
    if (r.kind === "session") {
      const href = sessionHref(id);
      return href ? link(href, "Raw activity for this session") : null;
    }
    const params = { win: "custom", from: str(r.first_seen).slice(0, 40), to: str(r.last_seen).slice(0, 40),
      service: PROTOCOL_RE.test(str(r.protocol)) ? r.protocol : "" };
    if (!parseTime(params.from) || !parseTime(params.to)) {
      params.win = "all";
      params.from = params.to = "";
    }
    if (typeof r.src_ip === "string" && ADDRESS_RE.test(r.src_ip)) params.src = r.src_ip;
    return link(activityHref(params), "Raw activity for this source");
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

  // ---- screen: activity -----------------------------------------------------------------

  // Every event-log line, raw and newest first. Filters live in the hash like Records.
  // Background polls only count newer events and offer them; rows the operator is reading
  // never move under them.
  function activityFilters(params) {
    const pick = (name, allowed) => {
      const v = params.get(name);
      return v && allowed.includes(v) ? v : "";
    };
    const service = (params.get("service") || "").toLowerCase();
    const win = params.get("win") || "";
    return {
      win: ["1h", "24h", "7d", "all", "custom"].includes(win) ? win : "24h",
      from: (params.get("from") || "").trim().slice(0, 40),
      to: (params.get("to") || "").trim().slice(0, 40),
      service: PROTOCOL_RE.test(service) ? service : "",
      kind: pick("kind", ACTIVITY_KINDS.map((k) => k[0])),
      outcome: pick("outcome", ["success", "failure"]),
      src: (params.get("src") || "").trim().slice(0, 64),
      user: (params.get("user") || "").slice(0, 64),
      q: (params.get("q") || "").slice(0, 200),
    };
  }

  // "2026-11-18 09:00", "2026-11-18T09:00:00Z" or a date alone; no zone means UTC.
  function parseUserTime(value) {
    const t = str(value).trim().replace(" ", "T");
    if (!USER_TIME_RE.test(t)) return null;
    const full = t.length === 10 ? t + "T00:00" : t;
    const d = new Date(/(Z|[+-]\d{2}:\d{2})$/.test(full) ? full : full + "Z");
    return isNaN(d.getTime()) ? null : d;
  }

  function activityQuery(f) {
    const q = { service: f.service, kind: f.kind, outcome: f.outcome, src: f.src, user: f.user, q: f.q };
    if (f.win === "custom") {
      const from = parseUserTime(f.from);
      const to = parseUserTime(f.to);
      if (from) q.from = from.toISOString();
      if (to) q.to = to.toISOString();
    } else if (f.win !== "all") {
      q.from = new Date(Date.now() - ACTIVITY_WINDOWS[f.win]).toISOString();
    }
    return q;
  }

  function activityHref(params) {
    return hashFor("/activity", params);
  }

  function sessionHref(id) {
    return typeof id === "string" && SESSION_ID_RE.test(id) ? "#/activity/session/" + enc(id) : null;
  }

  // A source address from the log becomes a filter link only when it is plainly an address.
  function sourceLink(src) {
    if (typeof src !== "string" || !src) return el("span", { cls: "faint", text: "-" });
    return ADDRESS_RE.test(src) ? link(activityHref({ src: src }), mono(src)) : mono(src);
  }

  function kindLabel(kind) {
    return lookup(ACTIVITY_KIND_LABEL, kind, str(kind) || "-");
  }

  function outcomeBadge(outcome) {
    if (outcome === "success") return badge("success", "st-bad");
    if (outcome === "failure") return statusBadgeText("failure");
    return el("span", { cls: "faint", text: "-" });
  }

  function viewActivity(route, main) {
    setTitle("Activity");
    const f = activityFilters(route.params);
    const active = Boolean(f.service || f.kind || f.outcome || f.src || f.user || f.q || f.win !== "24h");

    const select = (name, label, options) => {
      const s = el("select", { attrs: { name: name } },
        options.map(([value, text]) => el("option", { attrs: { value: value }, text: text })));
      s.value = f[name];
      return el("label", "field", el("span", { text: label }), s);
    };
    const input = (name, label, placeholder, wide) => {
      const i = el("input", { cls: wide ? "wide" : "", attrs: { type: "text", name: name, placeholder: placeholder,
        autocomplete: "off", spellcheck: "false" } });
      i.value = f[name];
      return el("label", "field", el("span", { text: label }), i);
    };
    // Services come from the indexed window once it has loaded; a chosen one stays listed.
    const serviceField = select("service", "Service", [["", "Any"]].concat(f.service ? [[f.service, f.service]] : []));
    const fromField = input("from", "From (UTC)", "2026-11-18 09:00");
    const toField = input("to", "To (UTC)", "now");
    const form = el("form", { cls: "filters", attrs: { role: "search", "aria-label": "Activity filters" } },
      input("q", "Search", "what was sent or answered", true),
      select("win", "Time", [["1h", "Last hour"], ["24h", "Last 24 hours"], ["7d", "Last 7 days"],
        ["all", "Everything indexed"], ["custom", "Custom"]]),
      fromField, toField, serviceField,
      select("kind", "Event", [["", "Any"]].concat(ACTIVITY_KINDS)),
      select("outcome", "Outcome", [["", "Any"], ["success", "Success"], ["failure", "Failure"]]),
      input("src", "Source", "address or network"),
      input("user", "User", "exact username"),
      el("button", { cls: "btn btn-primary", attrs: { type: "submit" }, text: "Apply" }),
      active ? link("#/activity", "Clear filters") : null);
    form.elements.namedItem("q").setAttribute("data-search", "");
    const winSelect = form.elements.namedItem("win");
    const showCustom = () => {
      fromField.hidden = toField.hidden = winSelect.value !== "custom";
    };
    showCustom();
    winSelect.addEventListener("change", showCustom);
    for (const name of ["win", "service", "kind", "outcome"]) {
      form.elements.namedItem(name).addEventListener("change", () => {
        if (name !== "win" || winSelect.value !== "custom") apply();
      });
    }
    for (const name of ["from", "to"]) {
      const i = form.elements.namedItem(name);
      i.addEventListener("input", () => i.setCustomValidity(""));
    }
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      apply();
    });

    function apply() {
      const data = new FormData(form);
      const next = {};
      for (const key of ["q", "win", "from", "to", "service", "kind", "outcome", "src", "user"]) {
        next[key] = String(data.get(key) || "").trim();
      }
      if (next.win === "24h") next.win = "";
      if (next.win !== "custom") {
        next.from = "";
        next.to = "";
      } else {
        for (const key of ["from", "to"]) {
          if (next[key] && !parseUserTime(next[key])) {
            const i = form.elements.namedItem(key);
            i.setCustomValidity("A time like 2026-11-18 09:00 (UTC).");
            form.reportValidity();
            return;
          }
        }
      }
      location.hash = activityHref(next);
    }

    const lead = intro("Every event in the log, raw: who tried what, on which service, " +
      "what they sent and what the honeypot answered. Newest first; open a row for the details.");
    const notices = el("div", { cls: "stack", attrs: { "aria-live": "polite" } });
    const results = section("Events", { flush: true });
    main.append(pageHead("Activity"), lead, el("section", "section", form), notices, results.node);

    const ctx = { f: f, query: activityQuery(f), newest: null, logId: null, logNotice: null,
      serviceField: serviceField, notices: notices };
    return {
      refresh: (kind) => kind === "poll" ? checkNewActivity(ctx)
        : fill(results.body, () => {
          ctx.query = activityQuery(f);
          return apiGet(API.activity, ctx.query);
        }, (data) => drawActivity(obj(data), ctx, active), kind !== "initial"),
    };
  }

  async function checkNewActivity(ctx) {
    if (ctx.newest === null) return true;
    const gen = state.gen;
    let data;
    try {
      data = obj(await apiGet(API.activity, Object.assign({}, ctx.query, { after: ctx.newest, log_id: ctx.logId })));
    } catch (err) {
      if (gen === state.gen && err.status === 409) {
        logChanged(ctx);
        return true;
      }
      return false;
    }
    if (gen !== state.gen) return true;
    const n = typeof data.new === "number" ? data.new : 0;
    if (n > 0) {
      setKids(ctx.notices, notice("ok",
        plural(n, "new event", "new events") + (data.approximate === true ? " match the filters before the search. " : ". "),
        button("Show", manualRefresh, "btn-small")));
    }
    return true;
  }

  // Cursors are byte offsets into one log. When the server says the log changed (rotated,
  // truncated, or the console restarted), the list is reloaded from the top with a notice
  // instead of mixing rows from two logs.
  function logChanged(ctx) {
    ctx.logNotice = "The event log was rotated or replaced (or the console restarted), so the list was reloaded from the newest events.";
    ctx.newest = null;
    manualRefresh();
  }

  function fillServices(ctx, facets) {
    const s = ctx.serviceField.querySelector("select");
    const services = Object.keys(obj(facets.services)).filter((k) => PROTOCOL_RE.test(k)).sort();
    const keep = s.value;
    const names = services.includes(keep) || !keep ? services : services.concat([keep]);
    setKids(s, el("option", { attrs: { value: "" }, text: "Any" }),
      names.map((k) => el("option", { attrs: { value: k },
        text: k + (typeof facets.services[k] === "number" ? " (" + num(facets.services[k]) + ")" : "") })));
    s.value = keep;
  }

  function drawActivity(data, ctx, filtered) {
    ctx.newest = typeof data.newest === "number" ? data.newest : null;
    ctx.logId = typeof data.log_id === "string" ? data.log_id : null;
    ctx.notices.replaceChildren();
    if (ctx.logNotice) {
      ctx.notices.append(notice("warn", ctx.logNotice));
      ctx.logNotice = null;
    }
    const facets = obj(data.facets);
    fillServices(ctx, facets);
    const win = obj(data.window);
    const search = data.search ? obj(data.search) : null;
    const notes = [];
    if (win.caught_up === false) {
      notes.push(notice("warn", "Still reading a backlog of the log; the newest events may be missing for a minute."));
    }
    if (win.older_outside === true) {
      notes.push(notice("warn", "Older lines exist outside the indexed window. It holds the newest " +
        plural(win.entries || 0, "event", "events") + (win.oldest ? ", back to " : "."),
      win.oldest ? timeNode(win.oldest) : null, win.oldest ? "." : null,
      " Read older lines on the host."));
    }
    const items = arr(data.items).map(obj);
    const out = [];
    if (notes.length) out.push(el("div", "stack pad", notes));
    if (!items.length) {
      const why = search && search.complete === false ? null
        : (win.entries || 0) === 0 ? "No events in the indexed window yet. They appear as the services log them."
          : filtered ? "No events match these filters." : "No events in the last 24 hours.";
      if (why) out.push(empty(why));
    }
    const tbody = el("tbody");
    for (const it of items) addActivityRows(tbody, it);
    // Always in the page, hidden while empty: a search whose first page ran out of its read
    // budget has no rows yet, and "Search further back" adds them to this same table.
    const head = el("tr", null, ["", "Time", "Source", "Service", "Event", "User", "Outcome", "Summary"].map((c) =>
      el("th", { attrs: { scope: "col" }, text: c })));
    head.firstChild.append(el("span", { cls: "visually-hidden", text: "Details" }));
    const wrap = el("div", "table-wrap", el("table", { cls: "activity", attrs: { "aria-label": "Events, newest first" } },
      el("thead", null, head), tbody));
    wrap.hidden = !items.length;
    out.push(wrap);
    out.push(activityFoot(data, ctx, tbody, search, wrap));
    return out;
  }

  // "Load older" by cursor; for a search that ran out of its byte budget, "Search further".
  function activityFoot(data, ctx, tbody, search, wrap) {
    const foot = el("div", { cls: "pager", attrs: { "aria-live": "polite" } });
    const gen = state.gen;
    let cursor = typeof data.next_before === "number" ? data.next_before : null;
    let shown = tbody.childElementCount / 2;

    function draw(s, readCut) {
      const parts = [el("span", { text: plural(shown, "event", "events") + " shown" })];
      if (s) {
        parts.push(el("span", null, s.complete === true ? " - searched the whole indexed window"
          : s.searched_back_to ? [" - searched back to ", timeNode(s.searched_back_to)] : " - search stopped at its read limit"));
      } else if (readCut === true) {
        parts.push(el("span", { text: " - this page stopped at the server's read limit (very long log lines); Load older continues" }));
      }
      parts.push(el("span", "spacer"));
      if (cursor !== null) {
        parts.push(button(s && s.complete === false ? "Search further back" : "Load older", more, "btn-small"));
      }
      setKids(foot, parts);
    }

    async function more() {
      const b = foot.querySelector("button");
      if (b) b.disabled = true;
      let next;
      try {
        next = obj(await apiGet(API.activity, Object.assign({}, ctx.query, { before: cursor, log_id: ctx.logId })));
      } catch (err) {
        if (gen !== state.gen || err.status === 401) return;
        if (err.status === 409) {
          logChanged(ctx);
          return;
        }
        setKids(foot, el("span", { cls: "state-error", text: errorMessage(err) }), el("span", "spacer"),
          button("Retry", more, "btn-small"));
        return;
      }
      if (gen !== state.gen) return;
      const items = arr(next.items).map(obj);
      for (const it of items) addActivityRows(tbody, it);
      if (items.length) wrap.hidden = false;
      shown += items.length;
      cursor = typeof next.next_before === "number" ? next.next_before : null;
      draw(next.search ? obj(next.search) : null, next.read_cut);
    }

    draw(search, data.read_cut);
    return foot;
  }

  // One event: a summary row and a details row below it, built when first opened.
  function addActivityRows(tbody, it) {
    const toggle = el("button", { cls: "row-toggle", text: "+",
      attrs: { type: "button", "aria-expanded": "false", "aria-label": "Show details" } });
    const detailCell = el("td", { attrs: { colspan: "8" } });
    const detail = el("tr", "row-detail", detailCell);
    detail.hidden = true;
    let built = false;
    const flip = () => {
      const open = detail.hidden;
      if (open && !built) {
        detailCell.append(eventDetail(it));
        built = true;
      }
      detail.hidden = !open;
      toggle.textContent = open ? "-" : "+";
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      toggle.setAttribute("aria-label", open ? "Hide details" : "Show details");
    };
    toggle.addEventListener("click", flip);
    const row = el("tr", "nav-row",
      el("td", null, toggle),
      el("td", null, timeNode(it.time)),
      el("td", null, sourceLink(it.src), geoText(it.geo)),
      el("td", null, mono(it.service)),
      el("td", null, kindLabel(it.kind)),
      el("td", null, clip(it.username)),
      el("td", null, outcomeBadge(it.outcome)),
      el("td", null, el("span", { cls: "clip clip-wide mono", text: str(it.summary) })));
    row.addEventListener("click", (ev) => {
      if (ev.target.closest("a, button") || String(window.getSelection())) return;
      flip();
    });
    tbody.append(row, detail);
  }

  function eventDetail(it) {
    const blocks = [];
    if (it.unreadable === true) {
      blocks.push(notice("warn", "This line is no longer in the event log (it was rotated or cut), so its content cannot be shown."));
    }
    if (typeof it.sent === "string" && it.sent) {
      blocks.push(el("div", null, el("div", { cls: "label", text: "Sent" }), moreBlock(it.sent, it.sent_truncated, "attacker")));
    } else if (typeof it.sent === "string" && it.kind === "input") {
      blocks.push(el("div", null, el("div", { cls: "label", text: "Sent" }), el("p", { cls: "muted", text: "(empty line)" })));
    }
    // A reply field that is present but empty is a real answer of nothing; a missing one
    // means the log holds no reply for this event.
    if (typeof it.answered === "string" && it.answered) {
      blocks.push(el("div", null, el("div", { cls: "label", text: "Answered" }), moreBlock(it.answered, it.answered_truncated)));
    } else if (typeof it.answered === "string") {
      blocks.push(el("div", null, el("div", { cls: "label", text: "Answered" }), el("p", { cls: "muted", text: "Answered with nothing." })));
    } else if (it.kind === "input" || it.kind === "request") {
      blocks.push(el("p", { cls: "muted", text: "No reply is recorded in the log for this event." }));
    }
    const sid = sessionHref(it.session);
    blocks.push(kv([
      it.result ? ["Result", el("span", { cls: "mono wrap", text: str(it.result) })] : null,
      it.kind === "login" && it.password !== undefined ? ["Password", el("span", { cls: "mono wrap", text: str(it.password) })] : null,
      it.message ? ["Logged as", el("span", { cls: "wrap", text: str(it.message) })] : null,
      ["Session", sid ? link(sid, mono(it.session)) : el("span", { cls: "faint", text: "-" })],
      ["Source", el("span", null, sourceLink(it.src), geoText(it.geo))],
    ]));
    return el("div", "stack pad", blocks);
  }

  // Long attacker text collapsed to its first lines, with "Show more".
  function moreBlock(text, truncated, who) {
    const full = str(text);
    const lines = full.split("\n");
    const long = lines.length > MORE_LINES || full.length > MORE_CHARS;
    const short = long ? lines.slice(0, MORE_LINES).join("\n").slice(0, MORE_CHARS) : full;
    const pre = textBlock(short, who === "attacker" ? "attacker" : "");
    const out = el("div", "more", pre);
    if (long) {
      let open = false;
      const b = button("Show more", () => {
        open = !open;
        pre.textContent = open ? full : short;
        b.textContent = open ? "Show less" : "Show more";
        b.setAttribute("aria-expanded", open ? "true" : "false");
      }, "btn-small");
      b.setAttribute("aria-expanded", "false");
      out.append(b);
    }
    if (truncated === true) out.append(el("div", { cls: "note-faint", text: "Cut at 4,000 characters by the server." }));
    return out;
  }

  // ---- screen: one session's activity ---------------------------------------------------

  function viewActivitySession(route, main) {
    setTitle("Session");
    const id = route.parts[2];
    main.append(el("p", null, link("#/activity", "Back to activity")));
    if (!SESSION_ID_RE.test(id || "")) {
      main.append(empty("That is not a session id."));
      return {};
    }
    const body = el("div");
    main.append(body);
    return {
      // Like a record, a session is reloaded only by the Refresh control.
      refresh: (kind) => kind === "poll" ? Promise.resolve(true)
        : fill(body, () => apiGet(API.activitySession(id)), (data) => drawActivitySession(obj(data), id),
          kind !== "initial"),
    };
  }

  function drawActivitySession(data, id) {
    const events = arr(data.events).map(obj);
    const record = recordHref(data.record_id);
    const head = el("div", "detail-head",
      el("h1", { text: id }),
      el("span", { cls: "tag", text: str(data.service) }),
      record ? link(record, "Open the triage record") : el("span", { cls: "muted", text: "No triage record for this session yet." }));
    const facts = el("section", "section", el("div", "section-body", el("div", "facts",
      fact("Source", el("span", null, sourceLink(data.src), geoText(data.geo))),
      fact("Started", timeNode(data.start)),
      fact("Ended", timeNode(data.end)),
      fact("Events", num(events.length)))));
    // For SSH, logins and commands come from the transcript; connection, close and error
    // lines only when the indexed window still holds them, and the heading says which.
    const partial = data.from === "transcript" && data.connection_lines !== true;
    const s = section(partial ? "Logins and commands in this session, in order" : "Everything in this session, in order");
    const term = el("div", { cls: "terminal", attrs: { tabindex: "0", role: "log", "aria-label": "Session events" } });
    for (const ev of events) {
      const sent = typeof ev.sent === "string" && ev.sent;
      const answered = typeof ev.answered === "string" && ev.answered;
      if (sent) term.append(turnNode({ ts: ev.time, role: "input", text: ev.sent, truncated: ev.sent_truncated }));
      if (answered) term.append(turnNode({ ts: ev.time, role: "response", text: ev.answered, truncated: ev.answered_truncated }));
      if (!sent && !answered) {
        // The summary of an event with nothing sent or answered is already its result.
        term.append(turnNode({ ts: ev.time, role: "other", text: kindLabel(ev.kind) + ": " + str(ev.summary) }));
      } else if (ev.result) {
        term.append(turnNode({ ts: ev.time, role: "other", text: "result: " + str(ev.result) }));
      } else if (sent && !answered && data.from === "index" && ev.kind === "input") {
        term.append(turnNode({ ts: ev.time, role: "other", text: "no reply recorded" }));
      }
    }
    append(s.body, [events.length ? term : empty("No events recorded for this session."),
      data.events_cut === true ? el("p", { cls: "muted", text: "Only the first " + num(events.length) + " events are shown" +
        (data.read_cut === true ? ": the view stopped at the server's read limit for one request (very long log lines)." : ".") }) : null,
      el("p", { cls: "muted", text: data.from !== "transcript"
        ? "Read from the event log's indexed window. Where a service logs only a status or result, that is shown; no reply is made up."
        : partial ? "Logins and commands replayed from the SSH transcript, as on the record page. Its connection and close lines are not in the indexed window."
          : "Logins and commands replayed from the SSH transcript, as on the record page, with the connection, close and error lines from the indexed window." })]);
    return [head, facts, s.node];
  }

  // Under each command of an SSH session record: what the decoy answered, paired by place
  // in the session (the server does the pairing), collapsed to its first lines.
  function commandReplies(id) {
    const box = el("div", { cls: "stack", attrs: { "aria-live": "polite" } }, el("div", { cls: "muted", text: "Loading replies..." }));
    const gen = state.gen;
    apiGet(API.replies(id)).then((data) => {
      if (gen !== state.gen) return;
      const items = arr(obj(data).items).map(obj);
      if (!items.length) {
        box.replaceChildren(empty("No commands recorded."));
        return;
      }
      box.replaceChildren(el("ol", { cls: "commands", attrs: { "aria-label": "Commands and replies" } },
        items.map((it) => el("li", "command-item",
          el("pre", { cls: "command-text", text: str(it.command) }),
          it.recorded === true
            ? moreBlock(it.reply, it.truncated)
            : el("div", { cls: "note-faint", text: replyNote(it.status) })))));
      if (obj(data).read_cut === true) {
        box.append(el("p", { cls: "muted", text: "This session is longer than the server reads for one request; replies past that point are not shown." }));
      }
    }).catch((err) => {
      if (gen !== state.gen || err.status === 401) return;
      box.replaceChildren(el("div", { cls: "muted", text: "Replies not available (" + err.message + ")." }));
    });
    return box;
  }

  // Why a command has no reply shown. The server checks each pairing: the paired input must
  // start with the command, or it is not shown as its reply.
  function replyNote(status) {
    if (status === "unmatched") return "reply could not be matched to this command";
    if (status === "not_read") return "not read (past the server's read limit for one request)";
    return "no reply recorded";
  }

  // ---- screen: digests ------------------------------------------------------------------

  function viewDigests(route, main) {
    setTitle("Digests");
    const asked = route.parts[1];
    const day = asked && DAY_RE.test(asked) ? asked : null;
    const list = section("Days", { flush: true });
    const content = el("div");
    main.append(pageHead("Daily digests"),
      intro("One summary per day of what the sensor saw, written by the pipeline's digest step."),
      el("div", "split", list.node, content));
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
    main.append(pageHead("Decoy"),
      intro("This screen shows how the fake system is being adjusted to stay convincing to attackers. " +
        "Nothing here needs a decision."), body);
    return {
      refresh: (kind) => fill(body, () => apiGet(API.decoy, { page: spage, per: PER_PAGE }),
        (data) => drawDecoy(obj(data), (p) => hashFor("/decoy", { spage: p })), kind !== "initial"),
    };
  }

  // A heading, one sentence on what the part is and why it matters, then its content.
  function explained(title, why, opts) {
    const s = section(title, opts);
    s.node.insertBefore(el("p", { cls: "section-why", text: why }), s.body);
    return s;
  }

  // The raw value behind a plain description, for anyone who wants the exact data.
  function rawDetails(label, value) {
    return el("details", "raw", el("summary", { text: label }),
      textBlock(JSON.stringify(value, null, 2)));
  }

  function plainList(items) {
    return el("ul", "plain-list", items.map((it) => el("li", null, it)));
  }

  function drawDecoy(d, hrefFor) {
    const out = [];

    const overlay = explained("Current adjustments to the fake system",
      "What the tuner has added on top of the configured scenario: the fake logins, files and names " +
      "attackers find. Keeping these in line with what attackers look for makes the decoy look lived in.");
    if (d.overlay && typeof d.overlay === "object") {
      const o = obj(d.overlay);
      const lines = overlayLines(o);
      append(overlay.body, [lines.length ? plainList(lines)
        : empty("No adjustments: the fake system is exactly the configured scenario. The tuner adds some " +
          "when triage records show attackers trying logins, files or extensions the decoy does not have."),
      rawDetails("Show the raw adjustments file", o)]);
    } else if (d.overlay_error) {
      overlay.body.append(notice("bad", "The adjustments file cannot be read (" + str(d.overlay_error) + "). " +
        "Restore an earlier one with python -m agents tune --rollback N (the undo points are listed below)."));
    } else {
      overlay.body.append(empty("No adjustments yet: the fake system is exactly the configured scenario. " +
        "The tuner writes adjustments the first time triage records give it a reason to change something."));
    }
    out.push(overlay.node);

    const runs = explained("What the tuner changed and when",
      "Each time the tuner changed the fake system, with the reason for each change and any change its " +
      "safety checks refused. It only changes things inside fixed limits, and every change can be undone.",
      { flush: true });
    const runItems = arr(d.tuner_runs).map(obj);
    append(runs.body, [runItems.length ? tunerRunTable(runItems)
      : empty("The tuner has not changed anything yet. It runs with each pipeline pass (hourly by default) " +
        "and makes a change only when triage records show a reason, such as an account attackers keep " +
        "trying. It works without a model; a configured model only reorders its suggestions.")]);
    const snaps = arr(d.history).map(obj);
    if (snaps.length) {
      runs.body.append(el("div", "pad", el("details", "raw",
        el("summary", { text: "Undo points (" + num(snaps.length) + ")" }),
        el("p", { cls: "muted" }, "Restore the fake system as it was before an undo point with ",
          el("code", { text: "python -m agents tune --rollback N" }), "."),
        table([{ label: "N", num: true }, { label: "When" }, { label: "What happened" }],
          snaps.map((s) => ({ cells: [num(s.n), timeNode(s.timestamp), snapshotText(s)] })),
          { short: true }))));
    }
    out.push(runs.node);

    const sources = explained("What returning attackers are shown",
      "Sources a playbook singled out, and what the decoy keeps the same for them on every visit, so a " +
      "returning attacker sees a consistent system (and the same planted secret).", { flush: true });
    const ss = obj(d.source_state);
    const items = arr(ss.items).map(obj);
    append(sources.body, [items.length
      ? table([{ label: "Source" }, { label: "Last seen" }, { label: "Kept for them" }, { label: "Why" }, { label: "Until" }],
        items.map((s) => ({ cells: [el("div", null, el("span", null, sourceLink(s.key), geoText(s.geo)),
          shodanNode(s.shodan, { prefix: true })),
          s.last_seen ? timeNode(s.last_seen) : el("span", { cls: "faint", text: "no stored record" }),
          treatment(s), s.reasons && arr(s.reasons).length ? "playbooks: " + arr(s.reasons).map(str).join(", ")
            : el("span", { cls: "faint", text: "-" }),
          timeNode(s.expires_at)] })))
      : empty("No attacker has been singled out yet. A source appears here when a playbook's local step " +
        "(slow it down, deepen or shorten replies, plant a token, tag it, log more) matches its activity."),
    pager(ss, hrefFor)]);
    out.push(sources.node);
    return out;
  }

  function overlayLines(o) {
    const lines = [];
    if (o.hostname) lines.push(["The fake system's host name is ", mono(o.hostname), "."]);
    const accounts = obj(o.accounts);
    for (const service of Object.keys(accounts)) {
      for (const acct of arr(accounts[service]).map(obj)) {
        lines.push(["A fake ", mono(service), " login: user ", mono(acct.username), ", password ",
          mono(acct.password), " (bait, fake by design)."]);
      }
    }
    for (const lure of arr(o.lures)) lines.push(["A bait file at ", mono(lure), "."]);
    for (const ext of arr(o.sip_extensions).map(obj)) lines.push(["A SIP phone extension ", mono(ext.extension), "."]);
    const policies = obj(o.policies);
    for (const service of Object.keys(policies)) {
      const p = obj(policies[service]);
      lines.push(["On ", mono(service), ", a login is let in after " + num(p.after_n_min) + " to " +
        num(p.after_n_max) + " tries, as a weak real system would."]);
    }
    return lines;
  }

  // One tuner change in words.
  function changeText(c) {
    const who = (u) => "“" + str(u) + "”";
    switch (c.kind) {
      case "add_account": return "Added a fake " + str(c.service) + " login " + who(c.username) + ".";
      case "remove_account": return "Removed the fake " + str(c.service) + " login " + who(c.username) + " it had added.";
      case "set_hostname": return "Changed the host name to " + str(c.value) + ".";
      case "add_lure": return "Added a bait file at " + str(c.value) + ".";
      case "add_sip_extension": return "Added the SIP extension " + str(c.username) + ".";
      case "set_after_n": return "On " + str(c.service) + ", let a login in after " + str(c.after_n_min) + " to " +
        str(c.after_n_max) + " tries.";
      default: return "A change of a kind this console does not know.";
    }
  }

  // An undo point: a tuner run (its changes as the tuner summarised them, "add_account
  // ftp:backup") or a rollback ("rollback to before 3").
  function snapshotText(s) {
    const action = str(s.action);
    const back = /^rollback to before (\d+)$/.exec(action);
    if (back) return "Rolled back to how it was before undo point " + back[1] + ".";
    const changes = arr(s.changes).map((c) => {
      const m = /^([a-z_]+) (.*)$/.exec(str(c));
      if (!m) return str(c);
      const [svc, user] = m[2].includes(":") ? m[2].split(/:(.*)/s) : ["", m[2]];
      if (m[1] === "add_account" || m[1] === "remove_account") {
        return changeText({ kind: m[1], service: svc, username: user });
      }
      if (m[1] === "set_after_n") {
        const [service, range] = m[2].split(" ");
        const [lo, hi] = str(range).split("-");
        return changeText({ kind: m[1], service: service, after_n_min: lo, after_n_max: hi });
      }
      return changeText({ kind: m[1], value: m[2], username: m[2] });
    });
    return changes.length ? changes.join(" ") : action === "tune" ? "A tuner change." : action;
  }

  // "FenceError: max accounts reached" -> the reason, said as a refusal by the safety checks.
  function rejectionText(text) {
    const value = str(text);
    const i = value.indexOf(": ");
    const reason = i > 0 ? value.slice(i + 2) : value;
    return "Refused by the safety checks: " + (reason || "no reason given") + ".";
  }

  function tunerRunTable(runs) {
    const tbody = el("tbody");
    for (const run of runs) {
      const changes = arr(run.changes).map(obj);
      const rejected = arr(run.rejected).map(str);
      const toggle = el("button", { cls: "row-toggle", text: "+",
        attrs: { type: "button", "aria-expanded": "false", "aria-label": "Show what changed" } });
      const cell = el("td", { attrs: { colspan: "5" } });
      const detail = el("tr", "row-detail", cell);
      detail.hidden = true;
      let built = false;
      const flip = () => {
        const open = detail.hidden;
        if (open && !built) {
          cell.append(el("div", "stack pad",
            changes.length ? el("div", null, el("div", { cls: "label", text: "Changes" }),
              plainList(changes.map((c) => [changeText(c), c.reason ? el("span", { cls: "muted", text: " Why: " + str(c.reason) + "." }) : null])))
              : el("p", { cls: "muted", text: "Nothing was changed in this run." }),
            rejected.length ? el("div", null, el("div", { cls: "label", text: "Refused" }),
              plainList(rejected.map(rejectionText))) : null,
            rawDetails("Show the raw run record", run)));
          built = true;
        }
        detail.hidden = !open;
        toggle.textContent = open ? "-" : "+";
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
        toggle.setAttribute("aria-label", open ? "Hide what changed" : "Show what changed");
      };
      toggle.addEventListener("click", flip);
      const row = el("tr", "nav-row",
        el("td", null, toggle),
        el("td", null, timeNode(run.timestamp)),
        el("td", "num", num(changes.length)),
        el("td", "num", num(rejected.length)),
        el("td", null, run.snapshot !== null && run.snapshot !== undefined
          ? "undo point " + str(run.snapshot) : el("span", { cls: "faint", text: "-" })));
      row.addEventListener("click", (ev) => {
        if (ev.target.closest("a, button") || String(window.getSelection())) return;
        flip();
      });
      tbody.append(row, detail);
    }
    const head = el("tr", null, ["", "When", "Changes", "Refused", "Undo with"].map((c, i) =>
      el("th", { cls: i === 2 || i === 3 ? "num" : "", attrs: { scope: "col" }, text: c })));
    head.firstChild.append(el("span", { cls: "visually-hidden", text: "Details" }));
    return el("div", "table-wrap", el("table", { attrs: { "aria-label": "Tuner runs, newest first" } },
      el("thead", null, head), tbody));
  }

  // What a returning source is shown, in words.
  function treatment(s) {
    const parts = [];
    if (s.plant_token === true) parts.push("its own planted secret, the same one each visit" + untilText(s.token_until));
    if (typeof s.tarpit_ms === "number" && s.tarpit_ms > 0) parts.push("replies slowed by " + num(s.tarpit_ms) + " ms" + untilText(s.tarpit_until));
    if (s.budget_mode === "deep") parts.push("longer, model-written replies" + untilText(s.mode_until));
    if (s.budget_mode === "shallow") parts.push("short canned replies, no model" + untilText(s.mode_until));
    if (s.capture_more === true) parts.push("fuller logging of what it sends" + untilText(s.capture_until));
    const tagList = arr(s.tags).map(str);
    if (tagList.length) parts.push("labelled " + tagList.join(", "));
    return parts.length ? plainList(parts) : el("span", { cls: "faint", text: "nothing special" });
  }

  function untilText(value) {
    const d = parseTime(value);
    return d ? " (until " + absUtc(d) + ")" : "";
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
    main.append(pageHead("Playbooks"),
      intro("The rules that decide what happens when a record matches, with today's runs, and the " +
        "detection drafts and honeytokens they use."), pbBody, detections.node, tokens.node);

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

  // ---- screen: map ----------------------------------------------------------------------

  // Live attack map: each event flies from where its source is to the dock of the service it
  // reached, beside a feed of the same events as text. One canvas; attacker text reaches it
  // only through fillText, and the feed builds text nodes with el() like every other screen.

  const MAP_POLL_MS = 5000;
  const MAP_FLYING = 60;
  const MAP_QUEUE = 600;
  const MAP_FEED = 80;
  const MAP_KEEP = 400;
  const MAP_DOCKS = 12;
  const MAP_REPLAY = 6;
  const MAP_TOP = 84;
  const MAP_BOTTOM = -58;
  const MAP_WINDOWS = [["5m", "5 min"], ["15m", "15 min"], ["1h", "1 hour"]];
  const MAP_WINDOW_TEXT = { "5m": "5 minutes", "15m": "15 minutes", "1h": "hour" };
  const MAP_SERVICES = ["ssh", "http", "telnet", "ftp", "redis", "sip", "mysql", "smtp",
    "postgres", "mssql", "s3", "mllp"];
  const MAP_SVC_CLASS = ["svc-0", "svc-1", "svc-2", "svc-3", "svc-4", "svc-5", "svc-6", "svc-7"];
  const MAP_JUDGEMENT_VAR = { BENIGN: "--benign", SUSPICIOUS: "--suspicious", MALICIOUS: "--malicious" };
  const BEE = 26;

  // Land outline: Natural Earth, public domain. 110m land, simplified, Antarctica left out;
  // each string is one ring of longitude,latitude pairs in tenths of a degree.
  const LAND = [
    "1070,770,1072,765,1082,767,1111,767,1133,762,1141,758,1139,753,1094,742,1121,738,1130,740,1135,733,1140,736,1156,738,1188,736,1190,731,1232,730,1233,737,1270,736,1286,730,1291,724,1285,720,1297,712,1313,708,1323,718,1339,714,1356,717,1375,713,1382,716,1399,715,1391,724,1405,728,1495,722,1504,716,1530,708,1570,710,1590,709,1598,705,1597,697,1609,694,1623,696,1659,695,1678,696,1696,687,1708,690,1700,697,1705,701,1736,698,1757,699,1786,694,1800,690,1800,650,1787,645,1774,646,1783,641,1789,633,1794,630,1795,626,1792,623,1774,625,1737,617,1707,603,1703,599,1689,606,1663,598,1658,602,1649,597,1635,599,1632,592,1620,582,1621,578,1632,576,1631,562,1621,561,1617,553,1621,549,1604,543,1600,532,1585,530,1582,519,1568,510,1564,517,1554,554,1559,568,1568,574,1568,578,1584,581,1619,603,1637,611,1645,626,1633,625,1627,616,1601,605,1593,618,1567,614,1542,598,1550,591,1513,588,1513,595,1498,597,1485,592,1455,593,1422,590,1351,547,1367,546,1372,540,1382,538,1388,543,1399,542,1413,531,1414,522,1406,512,1405,500,1401,484,1386,470,1382,463,1349,434,1335,428,1329,428,1323,433,1309,426,1308,422,1304,423,1300,419,1297,416,1297,409,1286,402,1275,398,1274,392,1283,386,1292,374,1295,368,1295,356,1291,351,1282,349,1274,345,1265,344,1264,349,1266,357,1261,367,1269,369,1262,377,1257,379,1253,377,1252,379,1247,381,1252,387,1253,396,1243,399,1229,396,1221,392,1211,389,1216,394,1214,398,1222,404,1216,409,1196,399,1190,393,1180,392,1175,387,1181,381,1189,379,1189,374,1197,372,1208,379,1217,375,1224,375,1225,369,1211,367,1206,361,1197,356,1192,349,1202,344,1206,334,1219,317,1219,309,1213,307,1215,301,1221,298,1217,282,1211,281,1187,245,1159,228,1148,227,1142,222,1138,225,1132,221,1118,216,1108,214,1104,203,1099,203,1096,210,1099,214,1085,217,1067,207,1059,198,1057,191,1074,167,1083,161,1089,153,1093,134,1092,117,1072,104,1052,86,1048,92,1051,99,1043,105,1035,106,1026,122,1017,126,1008,126,1010,134,1001,134,1000,123,992,100,992,92,999,92,1005,74,1010,69,1016,67,1030,55,1034,49,1035,28,1039,25,1042,13,1035,12,1014,28,1013,33,1007,39,1006,48,1002,53,1003,60,1001,65,997,68,995,73,985,84,983,78,982,84,986,99,985,107,988,114,984,120,985,131,981,136,976,161,972,169,954,157,942,160,945,173,943,182,935,194,937,197,931,199,924,207,918,222,914,228,905,228,906,224,903,218,898,220,897,219,890,221,889,217,870,215,870,207,865,202,851,195,839,183,822,170,822,166,803,159,800,151,803,130,799,121,799,104,793,103,789,95,792,92,783,89,779,83,775,80,766,89,757,113,749,127,744,146,735,160,728,192,726,214,712,208,705,209,692,221,696,225,693,228,682,237,674,239,671,247,664,254,615,251,574,257,570,270,565,271,547,265,535,268,525,276,515,279,501,301,496,300,489,303,486,299,480,300,488,277,502,267,501,259,508,248,507,255,510,260,513,261,516,258,514,246,516,242,518,243,518,240,526,242,540,241,564,264,565,263,563,257,564,249,568,242,574,239,587,236,595,227,598,225,598,223,585,204,580,205,578,202,577,189,572,189,566,186,563,179,557,179,553,176,553,172,548,170,542,170,524,164,522,156,496,147,487,140,479,140,474,136,456,133,450,127,435,126,432,132,433,138,426,152,428,153,426,168,412,187,409,195,402,202,398,203,391,213,391,226,385,237,375,243,369,256,351,281,346,281,349,295,342,278,339,276,331,284,324,299,323,298,327,287,341,261,357,239,355,238,355,231,369,220,372,210,370,208,371,198,375,186,384,180,393,159,412,145,433,124,433,120,427,117,435,113,441,104,446,104,466,108,484,114,493,114,511,120,510,106,495,68,477,42,466,29,431,3,416,-17,409,-21,406,-25,403,-26,396,-43,392,-47,387,-59,388,-65,394,-68,392,-85,399,-101,403,-103,405,-108,406,-142,408,-147,401,-161,395,-167,374,-176,348,-198,347,-205,352,-213,354,-221,356,-221,354,-235,356,-237,355,-241,326,-257,327,-261,329,-262,325,-283,322,-288,313,-294,301,-311,282,-328,275,-332,259,-337,258,-339,252,-338,247,-340,236,-338,226,-339,196,-348,192,-345,189,-344,184,-340,184,-341,182,-339,183,-333,179,-326,182,-324,182,-317,163,-286,156,-278,152,-271,144,-239,143,-221,134,-209,126,-190,118,-181,116,-167,118,-158,125,-135,136,-120,137,-107,129,-92,132,-86,127,-69,122,-63,123,-61,119,-50,94,-21,88,-11,95,10,93,12,98,31,94,37,89,39,85,45,85,48,67,42,59,43,50,56,43,63,19,61,-20,47,-29,50,-46,52,-58,50,-75,43,-80,44,-90,48,-114,68,-124,73,-129,78,-132,89,-141,99,-146,102,-148,109,-157,115,-161,115,-166,122,-168,132,-167,136,-171,144,-176,147,-172,149,-165,161,-165,167,-163,172,-161,181,-164,196,-163,201,-171,210,-170,219,-163,227,-163,230,-160,237,-151,245,-148,256,-144,263,-138,266,-131,276,-126,280,-117,281,-96,299,-98,312,-93,326,-87,332,-69,341,-59,358,-52,358,-46,353,-36,354,-22,352,-12,357,-1,359,15,366,48,369,53,367,63,371,84,369,95,374,102,372,102,367,110,371,111,369,106,364,106,359,109,357,108,348,101,343,103,338,109,338,111,333,115,331,127,328,139,327,152,323,157,314,180,308,191,303,201,310,198,318,201,322,209,327,215,328,229,326,232,322,249,319,252,316,265,316,289,309,301,315,310,316,317,314,320,309,322,313,338,310,346,315,350,328,360,346,359,354,361,358,358,363,362,367,356,366,347,368,340,362,325,361,317,366,306,367,304,363,297,361,287,367,276,367,270,377,263,382,268,390,262,395,273,404,288,405,292,412,311,411,323,417,335,420,352,420,383,409,404,410,416,415,417,420,415,426,367,452,374,454,382,462,377,466,391,470,391,473,374,470,368,467,358,466,350,463,350,457,355,454,365,455,363,451,352,449,339,444,333,446,335,450,325,453,336,459,333,461,317,463,317,467,307,466,296,453,296,450,291,448,288,449,286,437,280,433,277,426,281,416,290,413,288,411,276,410,264,402,261,408,249,409,237,407,244,401,239,400,233,400,228,405,226,403,228,397,234,392,230,390,240,382,240,377,231,379,234,374,228,373,232,364,225,364,217,368,211,383,202,393,200,399,194,403,193,407,195,417,189,423,160,435,152,442,154,443,149,447,149,451,143,452,140,448,137,451,137,455,139,456,131,457,123,454,123,446,126,441,135,436,140,428,151,420,159,420,162,417,159,415,175,409,185,402,183,398,177,403,169,404,164,398,172,394,171,389,166,388,161,380,157,379,159,388,161,390,154,400,136,412,129,413,121,417,105,429,102,439,89,444,65,431,46,434,31,431,30,419,21,412,8,410,-3,393,1,387,-5,383,-7,376,-14,374,-21,367,-44,367,-54,359,-59,360,-65,369,-75,371,-79,368,-84,370,-89,369,-88,383,-93,384,-95,387,-94,394,-90,398,-88,408,-90,419,-90,426,-94,430,-80,437,-43,434,-19,434,-14,440,-12,460,-30,476,-45,480,-46,487,-33,489,-16,486,-19,498,-10,493,13,501,16,509,38,516,47,531,61,535,69,535,71,537,79,537,81,535,88,540,85,550,81,555,81,565,85,571,94,572,106,577,105,572,103,569,104,566,109,565,107,561,104,562,97,555,99,546,110,544,109,540,125,545,141,538,176,549,186,547,187,544,197,544,199,549,213,552,211,568,216,574,225,578,233,570,241,570,244,584,241,583,234,586,233,592,259,596,280,595,291,600,281,605,263,604,229,598,223,604,213,607,215,617,211,626,215,632,224,638,254,651,253,655,239,660,222,657,212,650,214,644,178,627,171,613,178,606,188,601,179,590,168,587,164,570,159,561,147,562,141,554,129,554,126,563,110,589,104,595,84,583,70,581,57,586,53,597,50,620,59,626,86,635,105,645,148,678,192,698,214,703,230,702,245,710,264,710,282,712,313,705,300,702,311,696,321,699,338,693,365,691,403,679,411,675,411,668,400,663,384,660,339,668,332,666,348,659,349,644,370,638,371,643,365,648,372,651,396,645,404,648,398,655,421,665,430,664,439,661,445,668,437,674,442,680,435,686,463,683,468,677,456,676,456,670,463,667,479,669,481,675,537,689,545,688,535,682,547,681,554,684,573,685,588,689,599,683,611,689,600,695,606,699,635,695,685,681,692,686,682,691,681,694,669,695,673,699,667,710,685,719,692,728,699,730,726,728,728,722,718,714,725,711,728,704,726,690,737,684,732,677,713,663,724,662,728,665,739,668,742,673,751,678,745,683,749,690,738,691,736,696,744,706,731,714,749,721,747,728,752,729,757,723,753,713,764,712,759,719,776,723,797,723,815,718,806,726,805,736,823,739,868,739,860,745,872,751,883,751,903,756,929,758,932,760,959,761,967,759,989,764,1008,764,1010,769,1020,773,1044,777,1061,774,1047,771",
    "-905,695,-906,685,-892,693,-880,686,-883,679,-874,672,-863,679,-856,688,-855,699,-826,697,-813,692,-812,687,-820,681,-813,676,-814,671,-833,664,-847,663,-858,666,-873,648,-885,641,-899,640,-907,636,-908,630,-919,628,-932,620,-942,609,-946,601,-947,589,-932,588,-923,571,-909,573,-890,569,-873,560,-850,553,-823,551,-824,543,-821,533,-814,522,-799,512,-791,515,-786,526,-791,541,-798,547,-782,551,-771,558,-765,565,-766,572,-773,581,-785,588,-773,599,-778,608,-781,623,-774,626,-747,622,-738,624,-717,615,-714,611,-696,611,-696,602,-693,590,-684,588,-676,582,-662,588,-652,599,-646,603,-614,570,-618,563,-596,552,-580,549,-573,546,-569,538,-562,536,-558,533,-557,521,-571,514,-588,511,-600,502,-617,501,-639,503,-664,502,-672,495,-685,491,-711,468,-703,470,-687,483,-666,491,-651,492,-642,487,-651,481,-645,462,-632,457,-615,459,-605,470,-604,463,-598,459,-610,453,-642,443,-654,435,-661,436,-662,445,-644,453,-671,451,-670,448,-701,437,-707,430,-708,423,-705,418,-701,418,-702,421,-699,419,-700,416,-729,412,-737,409,-722,411,-719,409,-733,406,-740,406,-740,408,-743,405,-740,404,-742,397,-749,389,-750,392,-755,395,-751,388,-751,384,-759,372,-757,379,-762,383,-763,392,-765,387,-763,381,-770,382,-763,379,-763,370,-760,369,-757,356,-764,348,-774,345,-781,339,-786,339,-791,335,-792,332,-803,325,-813,314,-815,307,-813,300,-805,285,-801,269,-801,258,-804,252,-807,251,-812,252,-813,256,-817,259,-829,279,-827,286,-829,291,-837,299,-841,301,-851,296,-864,304,-892,303,-896,302,-892,293,-902,291,-909,291,-916,297,-925,296,-932,298,-938,297,-947,295,-956,287,-966,283,-974,274,-973,262,-971,259,-977,243,-979,224,-972,206,-965,199,-963,193,-959,188,-948,186,-944,181,-920,187,-908,193,-903,210,-885,215,-871,215,-868,213,-868,208,-874,203,-876,196,-874,195,-878,183,-883,185,-881,183,-884,165,-889,159,-881,157,-879,159,-869,158,-860,160,-850,160,-834,153,-831,150,-833,147,-832,143,-835,136,-835,124,-836,123,-838,111,-834,104,-822,92,-822,90,-817,90,-814,88,-799,93,-796,96,-785,94,-774,87,-768,86,-761,93,-757,94,-755,106,-749,111,-743,111,-742,113,-734,112,-718,124,-711,121,-714,115,-719,114,-716,110,-716,104,-721,99,-717,91,-713,91,-710,99,-714,102,-714,110,-702,114,-703,118,-699,122,-696,115,-689,114,-682,109,-682,106,-662,106,-657,102,-649,101,-643,104,-643,106,-619,107,-627,104,-624,99,-616,99,-608,94,-607,86,-602,86,-591,80,-585,73,-585,68,-581,68,-571,60,-559,58,-558,60,-550,60,-540,58,-529,54,-518,46,-517,42,-513,42,-505,19,-500,17,-499,10,-507,2,-504,-1,-486,-2,-486,-12,-478,-6,-449,-16,-444,-21,-446,-27,-434,-24,-415,-29,-400,-29,-385,-37,-372,-48,-365,-51,-356,-51,-352,-55,-347,-73,-351,-90,-370,-110,-384,-130,-387,-131,-390,-138,-389,-157,-393,-179,-396,-183,-398,-196,-408,-209,-409,-219,-418,-224,-420,-230,-431,-230,-446,-234,-454,-238,-465,-241,-476,-249,-485,-259,-486,-266,-485,-272,-489,-287,-496,-292,-507,-310,-523,-322,-527,-332,-538,-344,-549,-350,-557,-348,-562,-349,-571,-344,-578,-345,-584,-339,-585,-344,-572,-353,-574,-360,-567,-364,-568,-369,-577,-382,-592,-387,-612,-389,-623,-388,-621,-394,-623,-402,-621,-407,-627,-410,-638,-412,-647,-408,-651,-411,-650,-421,-643,-424,-638,-420,-635,-426,-644,-429,-652,-435,-656,-450,-665,-450,-673,-456,-676,-463,-666,-470,-656,-472,-660,-481,-672,-487,-678,-499,-687,-503,-691,-507,-688,-518,-682,-523,-695,-523,-708,-529,-710,-538,-714,-539,-726,-535,-749,-523,-753,-516,-750,-510,-755,-504,-756,-487,-752,-477,-741,-469,-756,-466,-747,-458,-744,-441,-732,-445,-727,-424,-734,-421,-737,-434,-743,-432,-737,-399,-732,-393,-736,-372,-732,-371,-714,-324,-717,-309,-714,-301,-715,-289,-709,-276,-701,-214,-702,-198,-704,-183,-714,-178,-715,-174,-734,-164,-760,-146,-764,-138,-763,-135,-798,-72,-812,-61,-809,-57,-814,-47,-811,-40,-803,-34,-798,-27,-800,-22,-804,-27,-810,-22,-808,-20,-809,-11,-806,-9,-800,4,-801,8,-789,14,-790,17,-786,18,-787,23,-784,26,-779,27,-771,38,-775,41,-773,47,-775,56,-773,58,-775,67,-782,75,-784,81,-782,83,-791,90,-796,89,-798,86,-805,81,-800,75,-809,72,-811,78,-812,76,-815,77,-817,81,-828,83,-829,81,-835,84,-837,87,-836,91,-846,96,-850,101,-849,98,-851,96,-857,99,-858,101,-857,108,-859,109,-857,111,-877,129,-876,131,-873,130,-875,133,-878,134,-879,131,-885,132,-906,139,-912,139,-922,145,-934,156,-947,162,-966,157,-1008,172,-1019,179,-1035,183,-1039,187,-1050,193,-1055,199,-1057,204,-1054,205,-1055,208,-1053,211,-1053,214,-1060,228,-1084,252,-1093,256,-1094,258,-1093,264,-1104,272,-1106,279,-1112,279,-1122,290,-1132,308,-1131,312,-1139,316,-1142,315,-1148,318,-1149,314,-1147,302,-1133,288,-1131,284,-1130,284,-1128,278,-1116,267,-1107,248,-1107,243,-1102,243,-1094,234,-1100,228,-1103,234,-1122,247,-1123,260,-1135,268,-1136,266,-1145,271,-1151,277,-1146,277,-1142,281,-1142,286,-1149,293,-1155,296,-1167,316,-1173,330,-1179,336,-1184,337,-1185,340,-1206,346,-1207,352,-1217,362,-1225,376,-1225,378,-1237,390,-1239,398,-1244,403,-1242,411,-1242,420,-1245,428,-1241,437,-1239,455,-1241,469,-1247,482,-1246,484,-1231,480,-1226,471,-1223,474,-1228,490,-1256,504,-1274,508,-1280,517,-1279,523,-1291,528,-1293,536,-1305,543,-1305,548,-1320,555,-1322,564,-1335,572,-1341,581,-1366,582,-1378,585,-1399,595,-1426,601,-1440,600,-1471,609,-1482,607,-1480,600,-1517,592,-1519,597,-1514,607,-1503,610,-1506,613,-1519,607,-1526,601,-1540,594,-1533,589,-1542,581,-1563,574,-1566,570,-1581,565,-1584,560,-1596,556,-1603,556,-1631,547,-1648,544,-1649,546,-1618,559,-1606,560,-1601,564,-1577,576,-1576,583,-1570,589,-1582,586,-1585,588,-1591,584,-1597,589,-1600,586,-1604,591,-1614,587,-1620,587,-1621,593,-1619,596,-1625,600,-1638,598,-1653,605,-1654,611,-1661,615,-1646,631,-1631,631,-1623,635,-1615,635,-1608,638,-1610,642,-1615,644,-1608,648,-1625,646,-1628,643,-1635,646,-1650,644,-1664,647,-1668,651,-1681,657,-1645,666,-1637,666,-1638,661,-1617,661,-1625,667,-1637,671,-1654,680,-1668,684,-1662,689,-1644,689,-1632,694,-1629,699,-1619,703,-1590,709,-1581,708,-1566,714,-1551,711,-1543,707,-1539,709,-1522,708,-1523,706,-1507,704,-1497,705,-1449,700,-1436,702,-1365,689,-1344,696,-1329,695,-1298,702,-1291,698,-1284,700,-1281,705,-1274,704,-1258,695,-1244,702,-1243,694,-1231,696,-1227,699,-1215,698,-1176,690,-1152,689,-1139,684,-1153,679,-1135,677,-1099,680,-1089,674,-1078,679,-1088,683,-1082,687,-1062,688,-1043,680,-1032,681,-1015,676,-984,678,-986,684,-977,686,-961,682,-961,673,-955,681,-947,681,-942,691,-965,701,-964,712,-952,719,-939,718,-929,713,-915,702,-924,697",
    "1436,-138,1439,-145,1446,-142,1454,-150,1453,-154,1455,-163,1456,-168,1459,-169,1462,-178,1461,-183,1464,-190,1488,-204,1487,-206,1493,-213,1497,-223,1501,-221,1505,-226,1507,-224,1509,-235,1529,-253,1531,-261,1531,-273,1536,-281,1529,-316,1525,-326,1517,-330,1503,-357,1500,-374,1494,-378,1483,-378,1474,-382,1463,-390,1449,-384,1450,-379,1445,-381,1436,-388,1406,-380,1400,-374,1396,-361,1391,-357,1381,-356,1384,-351,1382,-344,1377,-351,1368,-353,1374,-347,1375,-341,1379,-336,1378,-329,1370,-338,1364,-341,1360,-349,1352,-345,1352,-339,1341,-328,1343,-326,1313,-315,1295,-316,1271,-323,1261,-322,1242,-330,1237,-339,1222,-340,1213,-338,1199,-340,1193,-345,1190,-345,1180,-351,1166,-350,1150,-342,1150,-336,1157,-333,1158,-322,1150,-300,1150,-295,1146,-285,1142,-281,1140,-273,1133,-261,1138,-265,1134,-256,1142,-263,1142,-258,1134,-244,1138,-231,1137,-225,1141,-218,1142,-225,1146,-218,1167,-207,1174,-207,1193,-200,1209,-197,1222,-182,1223,-173,1230,-164,1234,-173,1239,-171,1235,-166,1238,-161,1243,-163,1244,-156,1252,-147,1257,-145,1257,-142,1261,-143,1261,-141,1271,-138,1284,-149,1296,-150,1294,-144,1299,-136,1303,-134,1302,-131,1306,-125,1312,-122,1317,-123,1326,-121,1326,-116,1318,-113,1324,-111,1336,-118,1344,-120,1347,-119,1353,-122,1365,-119,1370,-124,1363,-133,1360,-133,1361,-137,1354,-147,1355,-150,1383,-168,1391,-171,1393,-174,1402,-177,1409,-174,1417,-150,1415,-137,1418,-127,1417,-124,1421,-110,1425,-107,1428,-112,1429,-118,1431,-119,1432,-123,1435,-128,1436,-134",
    "-271,835,-208,827,-227,823,-319,822,-314,820,-279,821,-248,818,-229,821,-221,817,-232,812,-158,819,-128,817,-122,813,-168,804,-200,802,-177,801,-197,788,-197,776,-185,770,-200,769,-217,766,-198,761,-196,752,-207,752,-194,743,-216,742,-204,738,-208,735,-236,733,-223,726,-223,722,-243,726,-248,723,-234,721,-221,715,-218,707,-235,705,-255,714,-252,708,-264,702,-223,701,-277,685,-318,681,-328,677,-342,667,-364,660,-398,655,-407,648,-407,641,-412,635,-428,627,-424,619,-434,601,-448,600,-463,609,-483,609,-492,614,-499,624,-516,636,-521,643,-523,652,-537,661,-533,668,-540,672,-530,684,-515,687,-511,691,-509,699,-535,693,-547,696,-548,703,-544,708,-514,706,-540,715,-550,714,-558,717,-547,726,-573,747,-586,751,-586,755,-613,761,-685,761,-714,770,-668,774,-710,776,-733,780,-732,784,-657,794,-653,798,-680,801,-672,805,-637,812,-622,813,-627,818,-572,822,-541,822,-530,819,-504,824,-445,817,-469,822,-468,826,-434,832,-399,832,-386,835,-351,836",
    "-866,732,-858,725,-849,733,-823,738,-806,727,-807,721,-788,724,-778,727,-742,718,-741,713,-722,716,-712,709,-688,705,-679,701,-670,692,-688,687,-664,681,-649,678,-634,669,-619,669,-622,662,-639,650,-651,654,-667,664,-680,663,-681,657,-653,644,-647,634,-650,627,-688,637,-663,623,-662,619,-689,623,-710,629,-722,634,-719,637,-748,647,-748,644,-777,642,-786,646,-779,653,-740,655,-743,658,-739,663,-727,673,-729,677,-733,681,-748,686,-769,689,-762,691,-773,698,-782,698,-790,702,-795,699,-813,697,-887,704,-895,708,-885,712,-899,712,-902,722,-894,731,-884,735,-858,738",
    "1341,-12,1344,-28,1355,-34,1363,-23,1374,-17,1383,-17,1399,-24,1410,-26,1446,-39,1458,-49,1460,-55,1476,-61,1479,-66,1470,-67,1472,-74,1481,-80,1487,-91,1493,-91,1493,-95,1500,-97,1497,-99,1508,-103,1507,-106,1500,-107,1498,-104,1479,-101,1466,-89,1460,-81,1447,-76,1433,-82,1434,-90,1426,-93,1410,-91,1401,-83,1391,-81,1389,-84,1376,-84,1380,-76,1387,-73,1384,-62,1379,-54,1360,-45,1352,-45,1337,-35,1334,-40,1330,-41,1328,-33,1320,-28,1331,-25,1338,-25,1337,-22,1322,-22,1318,-16,1309,-14,1305,-9,1319,-7,1324,-4,1340,-8",
    "-685,831,-637,829,-618,826,-619,824,-677,815,-655,815,-695,806,-712,798,-739,794,-769,793,-755,792,-762,790,-754,785,-779,779,-784,775,-798,772,-796,770,-779,770,-779,768,-806,762,-832,765,-861,763,-895,765,-896,770,-878,772,-883,779,-876,780,-850,775,-863,782,-880,784,-872,788,-854,790,-851,793,-865,797,-869,803,-834,801,-818,805,-876,805,-894,809,-914,816,-916,819,-870,823,-855,827,-843,826,-832,823,-824,829,-793,831,-707,832",
    "-30,586,-41,576,-20,577,-22,569,-31,560,-21,559,-11,546,-4,545,5,529,17,527,16,521,11,518,14,513,6,508,-8,508,-25,505,-30,507,-36,502,-45,503,-52,500,-58,502,-43,512,-34,514,-50,516,-53,520,-42,523,-48,528,-46,535,-31,534,-29,540,-36,546,-48,548,-51,551,-47,555,-50,558,-56,553,-56,563,-61,568,-58,578,-50,586,-42,586",
    "1252,14,1244,4,1237,2,1227,4,1202,2,1200,-5,1209,-14,1215,-10,1233,-6,1233,-11,1228,-9,1224,-15,1215,-19,1225,-32,1223,-35,1232,-47,1232,-53,1226,-56,1222,-53,1227,-45,1217,-49,1215,-46,1216,-42,1209,-36,1210,-26,1203,-29,1204,-55,1198,-57,1194,-54,1197,-45,1195,-35,1191,-35,1188,-28,1192,-21,1200,6,1209,13,1217,10,1241,9,1251,16",
    "1179,18,1190,9,1178,8,1175,1,1175,-8,1166,-15,1165,-25,1161,-40,1160,-37,1149,-41,1145,-35,1138,-34,1133,-31,1121,-35,1117,-30,1102,-29,1101,-16,1096,-13,1091,-5,1090,4,1091,13,1097,20,1104,17,1112,19,1114,27,1130,31,1146,49,1162,61,1167,69,1171,69,1176,64,1177,60,1192,54,1191,50,1184,50,1186,45,1179,41,1173,32,1180,23",
    "1410,371,1406,363,1408,358,1403,351,1390,347,1372,346,1358,335,1351,338,1351,346,1333,344,1322,339,1310,339,1320,331,1313,315,1307,310,1302,314,1304,323,1298,326,1294,333,1304,336,1309,342,1319,347,1326,354,1346,357,1357,355,1367,373,1374,368,1394,382,1401,394,1399,406,1403,412,1414,414,1419,400,1419,392,1410,382",
    "-1142,731,-1147,727,-1124,730,-1111,725,-1099,730,-1090,726,-1082,717,-1077,721,-1084,731,-1075,732,-1065,731,-1054,727,-1045,710,-1010,700,-1011,696,-1027,695,-1021,691,-1024,688,-1060,692,-1090,688,-1133,685,-1139,690,-1152,693,-1161,692,-1173,700,-1124,704,-1144,706,-1179,705,-1184,709,-1161,713,-1177,713,-1194,716,-1179,727,-1152,733",
    "501,-136,502,-148,505,-152,504,-157,502,-160,499,-154,497,-157,499,-165,498,-169,495,-171,494,-180,471,-249,454,-256,440,-250,438,-245,433,-221,434,-213,439,-212,439,-208,444,-201,445,-194,440,-183,440,-174,444,-162,463,-158,477,-146,480,-141,479,-137,483,-138,488,-131,489,-125,492,-120,498,-129",
    "-797,228,-793,224,-783,225,-765,212,-756,210,-757,207,-749,207,-742,203,-743,201,-750,199,-778,199,-771,204,-775,207,-781,207,-785,210,-787,216,-793,216,-805,220,-818,222,-822,224,-818,226,-828,227,-835,222,-839,222,-841,219,-850,219,-844,222,-842,226,-833,230,-823,232,-806,231",
    "-726,199,-717,197,-716,199,-708,199,-700,196,-698,193,-692,193,-693,190,-688,190,-683,186,-687,182,-692,184,-700,184,-705,182,-707,184,-710,183,-714,176,-717,178,-717,180,-724,182,-735,182,-739,180,-745,183,-744,187,-727,184,-723,187,-728,191,-728,195,-734,196,-732,199",
    "1213,185,1219,182,1222,185,1222,178,1225,171,1223,163,1217,159,1215,151,1217,143,1227,143,1240,138,1239,132,1242,130,1241,125,1233,130,1229,136,1227,132,1220,138,1211,136,1206,139,1207,143,1210,145,1207,148,1206,144,1201,150,1199,164,1203,160,1204,176,1207,185",
    "-561,507,-568,498,-561,502,-555,499,-558,496,-549,493,-545,496,-535,492,-538,485,-531,487,-526,475,-531,467,-542,468,-540,476,-542,478,-554,469,-560,469,-553,474,-563,476,-593,476,-594,479,-588,483,-592,485,-584,491,-574,507,-567,513,-559,516,-554,516,-556,513",
    "1746,-362,1753,-372,1754,-365,1758,-368,1760,-376,1768,-379,1774,-380,1780,-376,1785,-377,1780,-392,1772,-391,1769,-394,1770,-399,1760,-413,1752,-417,1747,-413,1752,-405,1749,-399,1738,-395,1739,-391,1746,-388,1747,-374,1743,-365,1731,-352,1726,-345,1730,-345,1736,-350,1743,-353",
    "1058,-59,1047,-59,1039,-50,1026,-42,1014,-28,1001,-7,993,2,986,18,977,25,972,33,954,50,953,55,975,52,1006,21,1017,21,1025,14,1031,6,1038,1,1034,-7,1044,-11,1049,-23,1056,-24,1061,-31,1059,-43",
    "1264,84,1265,72,1262,63,1258,73,1254,68,1257,60,1254,56,1242,62,1239,69,1242,74,1236,78,1233,74,1228,75,1221,69,1219,72,1223,80,1235,87,1238,82,1246,85,1248,90,1255,90,1254,98,1262,93,1263,88",
    "1730,-409,1732,-413,1740,-409,1742,-413,1742,-418,1727,-434,1731,-439,1723,-439,1715,-442,1706,-459,1693,-466,1684,-466,1678,-463,1667,-462,1665,-459,1670,-451,1683,-441,1705,-430,1719,-415,1721,-410,1728,-405",
    "-1750,666,-1743,663,-1746,671,-1719,669,-1699,660,-1709,655,-1725,654,-1726,645,-1730,643,-1739,643,-1760,649,-1762,654,-1772,655,-1784,654,-1789,657,-1787,661,-1799,659,-1794,654,-1800,650,-1800,690,-1749,672",
    "575,707,537,708,534,712,516,715,515,720,525,722,524,728,544,736,535,737,559,746,556,751,612,763,645,764,662,768,682,769,689,765,682,762,616,753,585,743,554,724,556,715",
    "-947,771,-936,768,-916,768,-907,764,-910,761,-892,756,-864,755,-828,758,-811,757,-801,753,-798,749,-805,747,-819,744,-832,746,-882,744,-924,748,-929,759,-939,763,-960,764,-971,768,-967,772",
    "-1082,762,-1078,758,-1059,760,-1057,755,-1063,750,-1097,748,-1122,744,-1137,744,-1139,747,-1118,752,-1163,750,-1177,752,-1163,762,-1154,765,-1126,761,-1108,755,-1091,755,-1105,764,-1096,768,-1085,767",
    "-678,-538,-664,-544,-650,-547,-655,-552,-664,-552,-670,-549,-673,-553,-681,-556,-692,-555,-710,-551,-723,-545,-733,-540,-747,-528,-711,-541,-706,-536,-703,-529,-693,-525,-686,-526,-682,-531",
    "1436,507,1447,490,1432,493,1426,479,1435,468,1435,461,1427,467,1421,460,1419,468,1419,489,1421,496,1422,510,1416,519,1417,533,1426,538,1422,542,1427,544,1433,527,1432,518",
    "1086,-68,1105,-69,1108,-65,1126,-69,1130,-76,1145,-78,1157,-84,1146,-88,1135,-83,1115,-83,1094,-77,1083,-78,1065,-74,1063,-69,1054,-69,1061,-59,1073,-60,1085,-64",
    "-870,797,-858,793,-872,790,-890,783,-908,782,-929,783,-940,788,-939,791,-931,794,-950,794,-961,797,-967,802,-953,809,-943,810,-947,812,-924,813,-911,807,-878,803",
    "-145,665,-147,658,-136,651,-149,644,-187,635,-228,640,-218,644,-240,649,-222,651,-222,654,-243,656,-237,663,-221,664,-206,657,-191,663,-178,660,-162,665",
    "183,797,215,790,190,786,185,778,176,776,171,768,159,768,138,774,147,777,132,780,112,789,104,797,132,800,137,797,151,797,155,800,170,801",
    "1520,-55,1515,-56,1513,-58,1502,-63,1497,-63,1483,-57,1484,-54,1498,-55,1501,-50,1502,-55,1508,-55,1516,-48,1515,-42,1521,-41,1523,-43,1523,-49",
    "-852,657,-850,652,-845,654,-816,645,-816,640,-808,641,-801,637,-810,634,-825,637,-831,641,-855,631,-859,636,-872,635,-864,640,-859,657",
    "1454,-408,1464,-411,1477,-408,1483,-409,1484,-421,1480,-424,1479,-432,1476,-429,1469,-436,1460,-435,1454,-427,1453,-420,1447,-412,1447,-407",
    "1439,442,1446,440,1453,444,1455,433,1441,430,1432,420,1416,427,1411,416,1400,416,1398,426,1403,433,1414,434,1420,456,1431,445",
    "-1004,738,-992,736,-974,738,-971,735,-981,730,-965,726,-967,717,-984,713,-993,714,-1000,717,-1025,725,-1025,728,-1004,727,-1015,734",
    "1287,11,1286,3,1281,4,1280,-3,1284,-8,1281,-9,1277,-3,1274,10,1276,18,1279,22,1280,16,1286,15",
    "1255,122,1258,110,1250,113,1253,104,1248,101,1248,108,1245,109,1243,115,1249,114,1249,118,1243,126,1252,125",
    "-1235,485,-1240,484,-1257,488,-1260,492,-1269,495,-1270,498,-1281,500,-1284,505,-1284,508,-1258,503,-1249,495,-1239,491",
    "-985,767,-977,763,-977,757,-982,750,-998,749,-1009,751,-1009,756,-1025,756,-1026,763,-1015,763,-1000,766,-986,766",
    "1346,341,1348,338,1342,332,1338,335,1333,333,1330,327,1324,330,1324,335,1329,341,1335,339,1339,344",
    "-1205,714,-1231,709,-1236,713,-1259,719,-1239,737,-1249,743,-1215,744,-1176,742,-1155,735,-1192,725,-1205,718",
    "254,804,274,801,259,795,230,794,201,796,199,798,185,799,174,803,205,806,219,804,229,807",
    "511,805,489,803,488,802,476,800,465,802,471,806,448,806,483,808,485,805,500,809,515,807",
    "-68,523,-86,517,-100,518,-92,529,-97,539,-76,551,-67,552,-57,546,-62,539,-60,532",
    "999,789,978,788,950,790,933,794,925,801,912,803,938,810,959,813,979,807,1002,798",
    "-586,-511,-578,-516,-580,-519,-594,-522,-598,-518,-607,-523,-612,-518,-600,-512,-592,-515",
    "1244,-101,1236,-104,1235,-102,1240,-93,1250,-89,1251,-87,1270,-83,1273,-84,1251,-94",
    "346,357,339,352,340,350,330,346,325,347,323,351,328,351,329,354,337,354",
    "237,357,242,354,258,354,257,352,263,353,262,350,247,349,247,351,235,353",
    "92,412,98,405,97,392,92,392,88,389,84,392,84,404,82,410,87,409",
    "-932,728,-943,720,-954,721,-960,729,-960,734,-955,739,-945,741,-905,739,-920,730",
    "1784,-173,1787,-176,1786,-182,1779,-183,1774,-182,1773,-177,1777,-174,1781,-175",
    "1229,-81,1228,-86,1213,-89,1199,-88,1199,-84,1207,-82,1213,-85,1220,-85",
    "1559,-68,1556,-69,1552,-65,1547,-59,1545,-51,1547,-50,1548,-53,1560,-65",
    "1531,-45,1528,-48,1524,-38,1514,-30,1507,-27,1509,-25,1515,-28,1530,-40",
    "812,62,803,60,799,68,797,82,801,98,808,93,818,75,816,65",
    "1240,103,1230,90,1224,97,1228,103,1229,109,1235,109,1233,103,1241,112",
    "-769,179,-772,177,-783,182,-782,185,-778,185,-769,184,-764,182,-762,179",
    "1103,187,1095,182,1087,185,1086,194,1091,198,1108,201,1110,197,1106,193",
    "-1555,191,-1557,189,-1559,191,-1561,197,-1559,203,-1552,200,-1548,195,-1552,192",
    "1212,228,1207,220,1202,228,1201,236,1207,245,1215,253,1220,250,1218,244",
    "1451,756,1443,748,1406,748,1390,746,1370,753,1375,759,1388,761,1415,761",
    "-1162,776,-1163,769,-1171,765,-1199,761,-1215,759,-1229,761,-1191,775,-1176,775",
    "-1001,783,-997,779,-1029,783,-1052,784,-1042,787,-1054,789,-1055,793,-1008,788",
    "1179,-81,1183,-84,1189,-83,1191,-87,1167,-90,1171,-85,1176,-84",
    "1185,93,1172,84,1177,91,1190,104,1195,114,1197,106,1190,100",
    "-775,238,-778,237,-780,243,-784,246,-782,252,-779,252,-775,243",
    "155,382,152,374,153,371,151,366,124,376,126,381,148,381",
    "-637,466,-620,464,-625,460,-629,460,-641,464,-644,467,-640,470",
    "-1327,540,-1317,541,-1320,530,-1312,522,-1316,522,-1331,534,-1332,542",
    "-1530,571,-1540,567,-1545,570,-1547,575,-1532,580,-1526,579,-1521,576",
    "-759,671,-770,671,-772,676,-768,681,-759,683,-751,680,-752,674",
    "-956,691,-963,688,-976,691,-984,690,-998,694,-982,701,-963,695",
    "247,779,225,774,207,777,214,779,208,783,229,785,233,781",
    "-958,781,-973,779,-981,781,-986,785,-986,789,-968,788,-956,784",
    "703,-497,687,-498,689,-486,696,-489,705,-491,706,-493",
    "1671,-222,1667,-224,1648,-211,1640,-201,1645,-201,1666,-217",
    "1599,-83,1599,-85,1591,-81,1582,-74,1584,-73,1596,-80",
    "1305,-31,1308,-39,1300,-34,1279,-34,1281,-28,1294,-28",
    "1219,119,1225,116,1231,116,1231,112,1220,104,1220,114",
    "96,422,92,414,88,416,85,423,87,426,94,430",
    "-793,622,-797,616,-801,617,-803,621,-799,624,-795,624",
    "-819,627,-831,622,-838,622,-840,625,-833,629,-819,629",
    "-1787,709,-1800,708,-1799,716,-1790,716,-1776,713,-1777,711",
    "-763,731,-763,728,-798,728,-809,733,-808,737,-781,737",
    "1507,751,1496,747,1480,748,1461,752,1464,755,1482,753",
    "-936,750,-942,746,-968,749,-963,754,-949,756,-940,753",
    "-1102,777,-1121,774,-1135,777,-1127,781,-1113,782,-1099,780",
    "1794,-168,1787,-170,1786,-166,1800,-161,1800,-166",
    "1207,-102,1203,-103,1190,-96,1199,-94,1208,-100",
    "1347,-62,1342,-69,1341,-61,1345,-54,1347,-57",
    "1272,-35,1269,-38,1262,-36,1260,-32,1270,-31",
    "-609,101,-620,101,-617,104,-617,108,-609,109",
    "-656,182,-658,180,-672,179,-671,185,-658,184",
    "-618,491,-636,494,-645,499,-629,497,-618,493",
    "127,556,121,548,110,554,109,558,124,561",
    "-1656,599,-1662,598,-1675,602,-1665,604,-1657,603",
    "-1717,638,-1687,633,-1695,630,-1707,634,-1718,634",
    "1436,732,1399,734,1408,738,1421,739,1435,735",
    "-938,775,-962,776,-964,778,-944,778,-937,776",
    "-1097,786,-1125,784,-1125,786,-1115,788,-1110,788",
    "1051,783,994,779,1013,792,1021,793,1054,787",
    "1215,131,1213,122,1203,135,1212,134",
    "1800,708,1789,708,1787,711,1800,715",
    "-1045,734,-1054,728,-1069,735,-1053,736",
  ];
  let landRings = null;

  function svcIndex(service) {
    const i = MAP_SERVICES.indexOf(service);
    if (i >= 0) return i % MAP_SVC_CLASS.length;
    let h = 0;
    for (const c of str(service)) h = (h * 31 + c.charCodeAt(0)) % 997;
    return h % MAP_SVC_CLASS.length;
  }

  function easeInOut(t) {
    return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
  }

  function viewMap(route, main) {
    setTitle("Map");
    const m = {
      gen: state.gen, win: "15m", cursor: null, logId: null, busy: false, timer: null,
      raf: 0, last: 0, t: 0, bee: BEE, small: false, req: 0, loading: 0, paused: false, hide: false, off: new Set(),
      still: false, w: 0, h: 0, dpr: 1, colors: {}, land: null, sheet: null,
      sensor: null, sources: new Map(), docks: [], ports: new Map(), feed: [],
      queue: [], flights: [], pulses: [], hover: null, rows: new Map(), shownFlying: -1,
    };
    const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
    const scheme = window.matchMedia("(prefers-color-scheme: dark)");
    m.still = motion.matches;

    const pause = button("Pause", () => {
      m.paused = !m.paused;
      pause.textContent = m.paused ? "Resume" : "Pause";
      pause.setAttribute("aria-pressed", m.paused ? "true" : "false");
      kick(m);
    }, "btn-small");
    pause.setAttribute("aria-pressed", "false");
    const winGroup = segmented(MAP_WINDOWS, m.win, (value) => {
      m.win = value;
      [...winGroup.children].forEach((b, i) => b.setAttribute("aria-pressed", MAP_WINDOWS[i][0] === value ? "true" : "false"));
      loadMap(m);
    });
    winGroup.setAttribute("aria-label", "Time window");
    const hideBox = el("input", { attrs: { type: "checkbox" } });
    hideBox.addEventListener("change", () => {
      m.hide = hideBox.checked;
      drawFeed(m);
      kick(m);
    });
    const hideField = el("label", "map-check", hideBox, el("span", { text: "Hide addresses" }));

    m.canvas = el("canvas", { cls: "map-canvas", attrs: { role: "img", "aria-label": "World map of attack sources" } });
    m.wrap = el("div", "map-wrap", m.canvas);
    m.legend = el("div", { cls: "map-legend", attrs: { role: "group", "aria-label": "Services shown" } });
    m.counters = el("div", "map-counters");
    m.flyingNode = el("div", "tile-value");
    m.note = el("div", { cls: "stack", attrs: { "aria-live": "polite" } });
    m.list = el("ol", { cls: "map-feed-list", attrs: { "aria-label": "Events, newest first" } });
    m.feedNote = el("div", { cls: "map-feed-note muted" });
    const feed = el("section", { cls: "map-feed", attrs: { "aria-label": "Live events" } },
      el("div", "section-head", el("h2", { text: "Live events" })), m.feedNote, m.list);
    main.append(pageHead("Map", winGroup, hideField, pause),
      intro("Where attacks come from and which service each one reached, as they happen. " +
        "Each bee is one event flying from its source to the sensor; the feed lists the same events as text."),
      m.note, m.counters,
      el("div", "map-layout", el("div", "map-stage", m.wrap, m.legend), feed));

    m.canvas.addEventListener("pointermove", (ev) => {
      const r = m.canvas.getBoundingClientRect();
      setHover(m, sourceAt(m, ev.clientX - r.left, ev.clientY - r.top));
    });
    m.canvas.addEventListener("pointerleave", () => setHover(m, null));
    m.canvas.addEventListener("click", (ev) => {
      const r = m.canvas.getBoundingClientRect();
      openSource(sourceAt(m, ev.clientX - r.left, ev.clientY - r.top));
    });

    const onTheme = () => {
      m.colors = {};
      m.land = m.sheet = null;
      kick(m);
    };
    const onMotion = () => {
      m.still = motion.matches;
      m.flights = [];
      kick(m);
    };
    const onVisible = () => {
      if (!document.hidden && alive(m)) {
        schedule(m, 0);
        kick(m);
      }
    };
    const resize = new ResizeObserver(() => sizeCanvas(m));
    resize.observe(m.wrap);
    scheme.addEventListener("change", onTheme);
    motion.addEventListener("change", onMotion);
    document.addEventListener("visibilitychange", onVisible);
    m.stop = () => {
      m.gen = -1;
      resize.disconnect();
      scheme.removeEventListener("change", onTheme);
      motion.removeEventListener("change", onMotion);
      document.removeEventListener("visibilitychange", onVisible);
      clearTimeout(m.timer);
      cancelAnimationFrame(m.raf);
    };
    return {
      refresh: (kind) => kind === "poll" ? true : loadMap(m),
      stop: m.stop,
    };
  }

  function alive(m) {
    return m.gen === state.gen && !state.signedOut;
  }

  function schedule(m, delay) {
    clearTimeout(m.timer);
    if (alive(m) && !document.hidden) m.timer = setTimeout(() => pollMap(m), delay);
  }

  // A fresh window: everything on the map is replaced. Each load or poll takes a request
  // number; an answer to anything but the latest request (an earlier window, or a poll
  // overtaken by a reload) is dropped.
  async function loadMap(m) {
    clearTimeout(m.timer);
    const req = ++m.req;
    m.loading = req;
    let d;
    try {
      d = obj(await apiGet(API.map, { window: m.win }));
    } catch (err) {
      if (m.loading === req) m.loading = 0;
      if (!alive(m) || req !== m.req) return false;
      setKids(m.note, errorState(err, () => loadMap(m)));
      return false;
    }
    if (m.loading === req) m.loading = 0;
    if (!alive(m) || req !== m.req) return false;
    setKids(m.note);
    m.sources.clear();
    m.ports.clear();
    m.feed = [];
    m.queue = [];
    m.flights = [];
    m.pulses = [];
    ingest(m, d, true);
    schedule(m, MAP_POLL_MS);
    return true;
  }

  async function pollMap(m) {
    // A window load in progress owns the next answer; polling resumes after it.
    if (!alive(m) || m.busy || m.loading || document.hidden) return;
    if (m.cursor === null) {
      loadMap(m);
      return;
    }
    m.busy = true;
    const req = ++m.req;
    let ok = true;
    try {
      const d = obj(await apiGet(API.map, { window: m.win, after: m.cursor, log_id: m.logId }));
      if (req !== m.req) {
        m.busy = false;
        return;
      }
      if (alive(m)) ingest(m, d, false);
    } catch (err) {
      ok = false;
      if (req !== m.req) {
        m.busy = false;
        return;
      }
      if (alive(m) && err.status === 409) {
        // The log was rotated or replaced (or the console restarted): start over.
        m.busy = false;
        if (await loadMap(m)) setKids(m.note, notice("ok", "The event log was rotated or replaced, so the map was reloaded."));
        return;
      }
    }
    m.busy = false;
    if (alive(m)) {
      markUpdated(ok);
      schedule(m, MAP_POLL_MS);
    }
  }

  function ingest(m, d, fresh) {
    m.cursor = typeof d.newest === "number" ? d.newest : null;
    m.logId = str(d.log_id);
    const s = obj(d.sensor);
    const at = arr(s.point);
    m.sensor = { label: str(s.label), lat: Number(at[0]) || 0, lon: Number(at[1]) || 0 };
    // Every answer (load or poll) lists the sources of the whole window as it is now, so the
    // map is rebuilt from it: a source whose events have aged out goes, unless a bee or ring
    // of its own is still on screen or queued.
    const before = m.sources;
    m.sources = new Map();
    for (const src of arr(d.sources)) {
      const o = obj(src);
      if (!str(o.src)) continue;
      const known = before.get(o.src);
      const p = arr(o.point);
      m.sources.set(o.src, Object.assign(known || { seen: -1e9 }, {
        src: o.src, events: Number(o.events) || 0, place: str(o.place),
        judgement: str(o.judgement), lat: p.length === 2 ? Number(p[0]) : null, lon: p.length === 2 ? Number(p[1]) : null,
      }));
    }
    const items = arr(d.items).map(obj).filter((it) => typeof it.offset === "number");
    for (const it of items) {
      if (!m.sources.has(str(it.src)) && str(it.src)) {
        const p = arr(it.point);
        m.sources.set(it.src, Object.assign(before.get(it.src) || { seen: -1e9 }, { src: it.src, events: 1,
          place: str(it.place), judgement: str(it.judgement),
          lat: p.length === 2 ? Number(p[0]) : null, lon: p.length === 2 ? Number(p[1]) : null }));
      }
      if (Number.isInteger(it.dst_port)) m.ports.set(str(it.service), it.dst_port);
    }
    const busy = new Set([...m.flights.map((f) => f.src.src), ...m.pulses.filter((q) => q.src).map((q) => q.src.src),
      ...m.queue.map((q) => str(q.it.src))]);
    for (const [key, s] of before) {
      if (!m.sources.has(key) && busy.has(key)) m.sources.set(key, s);
    }
    trimSources(m);
    const totals = obj(d.totals);
    const services = Object.entries(obj(totals.services)).filter((e) => PROTOCOL_RE.test(e[0]));
    for (const it of items) {
      if (PROTOCOL_RE.test(str(it.service)) && !services.some((e) => e[0] === it.service)) services.push([it.service, 0]);
    }
    m.docks = services.slice(0, MAP_DOCKS).map((e) => e[0]);
    drawLegend(m);
    drawCounters(m, totals, d);
    if (fresh) {
      m.feed = items.slice(-MAP_FEED).reverse();
      drawFeed(m);
      if (!m.still) {
        items.slice(-MAP_REPLAY).forEach((it, i) => enqueue(m, it, m.t + 300 + i * 450, false));
      }
    } else {
      const times = items.map((it) => parseTime(it.time));
      const first = times.find((t) => t) || null;
      const lastT = times.slice().reverse().find((t) => t) || null;
      const span = first && lastT ? lastT - first : 0;
      const scale = span > MAP_POLL_MS * 0.9 ? MAP_POLL_MS * 0.9 / span : 1;
      items.forEach((it, i) => {
        const t = times[i];
        enqueue(m, it, m.t + (first && t ? (t - first) * scale : i * 80), true);
      });
    }
    const skipped = Number(d.skipped) || 0;
    m.feedNote.textContent = skipped > 0
      ? num(skipped) + " more events arrived than the map draws; they are counted above and listed in Activity." : "";
    m.feedNote.hidden = skipped === 0;
    kick(m);
  }

  function trimSources(m) {
    if (m.sources.size <= MAP_KEEP) return;
    const keep = [...m.sources.values()].sort((a, b) => b.events - a.events || b.seen - a.seen).slice(0, MAP_KEEP);
    m.sources = new Map(keep.map((s) => [s.src, s]));
  }

  function enqueue(m, it, at, toFeed) {
    m.queue.push({ it: it, at: at, feed: toFeed });
    // Too far behind: the oldest go straight to the feed without a flight.
    while (m.queue.length > MAP_QUEUE) release(m, m.queue.shift(), false);
  }

  function release(m, q, fly) {
    const it = q.it;
    const src = m.sources.get(str(it.src));
    if (src) src.seen = m.t;
    if (q.feed) {
      m.feed.unshift(it);
      if (m.feed.length > MAP_FEED) m.feed.length = MAP_FEED;
      addFeedRow(m, it);
    }
    const service = str(it.service);
    if (!fly || m.off.has(service) || !src) return;
    m.pulses.push({ src: src, at: m.t, service: m.still ? service : null });
    if (m.still) return;
    const key = src.src + " " + service;
    const same = m.flights.find((f) => f.key === key && m.t - f.start < f.dur * 0.6);
    if (same) {
      same.count += 1;
      return;
    }
    if (m.flights.length >= MAP_FLYING) {
      const any = m.flights.find((f) => f.service === service) || m.flights[0];
      any.count += 1;
      return;
    }
    m.flights.push({ key: key, src: src, service: service, start: m.t, dur: 0, count: 1, phase: Math.random() * 4 });
  }

  // ---- map: drawing ----

  function sizeCanvas(m) {
    const w = m.wrap.clientWidth;
    const h = m.wrap.clientHeight;
    const dpr = Math.min(3, window.devicePixelRatio || 1);
    if (!w || !h || (w === m.w && h === m.h && dpr === m.dpr)) return;
    m.w = w;
    m.h = h;
    m.dpr = dpr;
    m.bee = Math.max(15, Math.min(BEE, w / 34));
    m.small = w < 600;
    m.canvas.width = Math.round(w * dpr);
    m.canvas.height = Math.round(h * dpr);
    m.land = m.sheet = null;
    kick(m);
  }

  function color(m, name) {
    if (!(name in m.colors)) m.colors[name] = getComputedStyle(m.canvas).getPropertyValue(name).trim() || "#888";
    return m.colors[name];
  }

  function proj(m, lat, lon) {
    return [(lon + 180) / 360 * m.w, (MAP_TOP - lat) / (MAP_TOP - MAP_BOTTOM) * m.h];
  }

  // Where a source is drawn: its place, or a spot in the unlocated lane picked by its text.
  function sourcePos(m, s) {
    if (s.lat !== null && s.lon !== null && isFinite(s.lat) && isFinite(s.lon)) {
      return proj(m, Math.max(MAP_BOTTOM, Math.min(MAP_TOP, s.lat)), s.lon);
    }
    let h = 7;
    for (const c of s.src) h = (h * 33 + c.charCodeAt(0)) % 10007;
    const lane = laneBox(m);
    return [lane[0] + 8 + (h % 97) / 96 * (lane[2] - 16), lane[1] + lane[3] / 2 + ((h >> 3) % 5 - 2) * lane[3] / 14];
  }

  function laneBox(m) {
    const [x, y] = proj(m, -47, -178);
    const [x2, y2] = proj(m, -57, -128);
    return [x, y, x2 - x, y2 - y];
  }

  function potPos(m) {
    const s = m.sensor || { lat: 0, lon: 0 };
    const [x, y] = proj(m, s.lat, s.lon);
    const pad = dockRadius(m) + (m.small ? 30 : 44);
    return [Math.max(pad, Math.min(m.w - pad, x)), Math.max(pad * 0.8, Math.min(m.h - pad * 0.8, y))];
  }

  function dockRadius(m) {
    return Math.max(22, Math.min(64, m.w * 0.046));
  }

  function dockPos(m, service) {
    const i = Math.max(0, m.docks.indexOf(service));
    const n = Math.max(1, m.docks.length);
    const a = -Math.PI / 2 + i * 2 * Math.PI / n;
    const [x, y] = potPos(m);
    const r = dockRadius(m);
    return [x + Math.cos(a) * r, y + Math.sin(a) * r, a];
  }

  function drawLand(m) {
    if (!landRings) landRings = LAND.map((ring) => ring.split(",").map(Number));
    const c = document.createElement("canvas");
    c.width = m.canvas.width;
    c.height = m.canvas.height;
    const g = c.getContext("2d");
    g.setTransform(m.dpr, 0, 0, m.dpr, 0, 0);
    g.strokeStyle = color(m, "--map-grid");
    g.lineWidth = 1;
    g.beginPath();
    for (let lon = -150; lon < 180; lon += 30) {
      const x = Math.round(proj(m, 0, lon)[0]) + 0.5;
      g.moveTo(x, 0);
      g.lineTo(x, m.h);
    }
    for (let lat = -30; lat <= 60; lat += 30) {
      const y = Math.round(proj(m, lat, 0)[1]) + 0.5;
      g.moveTo(0, y);
      g.lineTo(m.w, y);
    }
    g.stroke();
    g.beginPath();
    for (const ring of landRings) {
      for (let i = 0; i + 1 < ring.length; i += 2) {
        const [x, y] = proj(m, ring[i + 1] / 10, ring[i] / 10);
        if (i === 0) g.moveTo(x, y);
        else g.lineTo(x, y);
      }
      g.closePath();
    }
    g.fillStyle = color(m, "--map-land");
    g.fill();
    g.strokeStyle = color(m, "--map-coast");
    g.lineWidth = 0.75;
    g.lineJoin = "round";
    g.stroke();
    m.land = c;
  }

  // An original bee, drawn once per service colour in four wing positions.
  function drawSheet(m) {
    const k = m.bee / BEE;
    const size = Math.ceil(m.bee * m.dpr);
    const c = document.createElement("canvas");
    c.width = size * 4;
    c.height = size * (MAP_SVC_CLASS.length + 1);
    const g = c.getContext("2d");
    const ink = color(m, "--map-bee-ink");
    for (let row = 0; row <= MAP_SVC_CLASS.length; row++) {
      const body = row < MAP_SVC_CLASS.length ? color(m, "--map-svc-" + row) : color(m, "--unknown");
      for (let f = 0; f < 4; f++) {
        g.setTransform(m.dpr * k, 0, 0, m.dpr * k, f * size + size / 2, row * size + size / 2);
        const lift = [1, 0.72, 0.4, 0.72][f];
        g.fillStyle = color(m, "--map-wing");
        g.strokeStyle = ink;
        g.lineWidth = 0.8;
        for (const side of [-1, 1]) {
          g.beginPath();
          g.ellipse(-1, side * (3.5 + 3.5 * lift), 5.2, 3.6 * lift + 0.6, side * 0.5, 0, 2 * Math.PI);
          g.fill();
          g.stroke();
        }
        g.beginPath();
        g.ellipse(-1.5, 0, 7.5, 5, 0, 0, 2 * Math.PI);
        g.fillStyle = body;
        g.fill();
        g.save();
        g.clip();
        g.fillStyle = ink;
        for (const x of [-5.5, -1.5, 2.5]) g.fillRect(x, -6, 1.8, 12);
        g.restore();
        g.lineWidth = 1;
        g.stroke();
        g.beginPath();
        g.moveTo(-9, -1.2);
        g.lineTo(-11.5, 0);
        g.lineTo(-9, 1.2);
        g.fill();
        g.beginPath();
        g.arc(7.2, 0, 3.3, 0, 2 * Math.PI);
        g.fill();
        g.fillStyle = color(m, "--map-wing");
        g.beginPath();
        g.arc(8.4, -1.2, 0.9, 0, 2 * Math.PI);
        g.fill();
      }
    }
    m.sheet = { c: c, size: size };
  }

  function kick(m) {
    if (!m.raf && alive(m)) m.raf = requestAnimationFrame((ts) => frame(m, ts));
  }

  function frame(m, ts) {
    m.raf = 0;
    if (!alive(m) || !m.w) return;
    const dt = m.last ? Math.min(100, ts - m.last) : 0;
    m.last = ts;
    if (!m.paused) m.t += dt;
    while (!m.paused && m.queue.length && m.queue[0].at <= m.t) release(m, m.queue.shift(), true);
    if (!m.land) drawLand(m);
    if (!m.sheet) drawSheet(m);
    const g = m.canvas.getContext("2d");
    g.setTransform(1, 0, 0, 1, 0, 0);
    g.clearRect(0, 0, m.canvas.width, m.canvas.height);
    g.drawImage(m.land, 0, 0);
    g.setTransform(m.dpr, 0, 0, m.dpr, 0, 0);
    drawLane(m, g);
    drawSources(m, g);
    drawFlights(m, g, true);
    drawPot(m, g);
    drawPulses(m, g);
    drawFlights(m, g, false);
    drawTip(m, g);
    m.flights = m.flights.filter((f) => !f.dur || m.t - f.start < f.dur);
    m.pulses = m.pulses.filter((p) => m.t - p.at < 1400);
    if (m.flights.length !== m.shownFlying) {
      m.shownFlying = m.flights.length;
      m.flyingNode.textContent = num(m.flights.length);
    }
    const busy = !m.paused && (m.flights.length || m.pulses.length || m.queue.length);
    if (busy && !document.hidden) kick(m);
    else m.last = 0;
  }

  function drawLane(m, g) {
    if (![...m.sources.values()].some((s) => s.lat === null)) return;
    const [x, y, w, h] = laneBox(m);
    g.setLineDash([4, 4]);
    g.strokeStyle = color(m, "--map-coast");
    g.lineWidth = 1;
    g.strokeRect(x + 0.5, y + 0.5, w, h);
    g.setLineDash([]);
    g.fillStyle = color(m, "--text-muted");
    g.font = "11px " + color(m, "--font-ui");
    g.textAlign = "left";
    g.textBaseline = "bottom";
    g.fillText("Unlocated", x + 2, y - 3);
  }

  function dotRadius(s) {
    return Math.min(8, 2 + 1.25 * Math.log2(1 + s.events));
  }

  function drawSources(m, g) {
    const list = [...m.sources.values()].sort((a, b) => b.events - a.events);
    for (const s of list) {
      const [x, y] = sourcePos(m, s);
      const r = dotRadius(s);
      const judged = lookup(MAP_JUDGEMENT_VAR, s.judgement, null);
      g.globalAlpha = judged ? 0.9 : 0.6;
      g.fillStyle = color(m, judged || "--unknown");
      g.beginPath();
      g.arc(x, y, r, 0, 2 * Math.PI);
      g.fill();
      g.globalAlpha = 1;
      g.strokeStyle = color(m, "--surface");
      g.lineWidth = 1;
      g.stroke();
      if (s.src === m.hover) {
        g.strokeStyle = color(m, "--text");
        g.lineWidth = 2;
        g.beginPath();
        g.arc(x, y, r + 3, 0, 2 * Math.PI);
        g.stroke();
      }
    }
  }

  function flightPath(m, f) {
    const [x0, y0] = sourcePos(m, f.src);
    const [x1, y1] = dockPos(m, f.service);
    const dx = x1 - x0;
    const dy = y1 - y0;
    const dist = Math.hypot(dx, dy) || 1;
    const bend = Math.min(dist * 0.28, m.h * 0.3);
    // Bend towards the top of the map so arcs read as flights, not as lines.
    const sx = dx >= 0 ? 1 : -1;
    const cx = (x0 + x1) / 2 + (dy / dist) * bend * sx;
    const cy = (y0 + y1) / 2 - Math.abs(dx / dist) * bend;
    if (!f.dur) f.dur = Math.max(1300, Math.min(3400, 900 + dist * 2.6));
    return [x0, y0, cx, cy, x1, y1];
  }

  function bezier(p, u) {
    const a = (1 - u) * (1 - u);
    const b = 2 * (1 - u) * u;
    const c = u * u;
    return [a * p[0] + b * p[2] + c * p[4], a * p[1] + b * p[3] + c * p[5]];
  }

  function drawFlights(m, g, trails) {
    const sheet = m.sheet;
    for (const f of m.flights) {
      const p = flightPath(m, f);
      const u = easeInOut(Math.min(1, (m.t - f.start) / f.dur));
      const idx = svcIndex(f.service);
      if (trails) {
        g.strokeStyle = color(m, "--map-svc-" + idx);
        g.lineWidth = 2;
        g.lineCap = "round";
        let prev = bezier(p, Math.max(0, u - 0.16));
        for (let k = 1; k <= 8; k++) {
          const next = bezier(p, Math.max(0, u - 0.16 + 0.02 * k));
          g.globalAlpha = 0.07 * k;
          g.beginPath();
          g.moveTo(prev[0], prev[1]);
          g.lineTo(next[0], next[1]);
          g.stroke();
          prev = next;
        }
        g.globalAlpha = 1;
        continue;
      }
      const [x, y] = bezier(p, u);
      const [ax, ay] = bezier(p, Math.min(1, u + 0.01));
      const angle = Math.atan2(ay - y, ax - x);
      const frameNo = Math.floor((m.t + f.phase * 40) / 40) % 4;
      g.save();
      g.translate(x, y);
      g.rotate(isFinite(angle) ? angle : 0);
      g.drawImage(sheet.c, frameNo * sheet.size, idx * sheet.size, sheet.size, sheet.size, -m.bee / 2, -m.bee / 2, m.bee, m.bee);
      g.restore();
      if (f.count > 1) {
        g.font = "600 11px " + color(m, "--font-ui");
        g.textAlign = "left";
        g.textBaseline = "middle";
        g.lineWidth = 3;
        g.strokeStyle = color(m, "--surface");
        g.strokeText("×" + f.count, x + m.bee * 0.4, y - m.bee * 0.4);
        g.fillStyle = color(m, "--text");
        g.fillText("×" + f.count, x + m.bee * 0.4, y - m.bee * 0.4);
      }
      if (m.t - f.start >= f.dur - 16 && !f.landed) {
        f.landed = true;
        m.pulses.push({ dock: f.service, at: m.t });
      }
    }
  }

  function drawPulses(m, g) {
    for (const p of m.pulses) {
      const k = Math.min(1, (m.t - p.at) / (p.dock ? 700 : 1400));
      if (p.dock) {
        const [x, y] = dockPos(m, p.dock);
        g.strokeStyle = color(m, "--map-svc-" + svcIndex(p.dock));
        g.globalAlpha = 1 - k;
        g.lineWidth = 2;
        g.beginPath();
        g.arc(x, y, 5 + (m.small ? 8 : 13) * easeInOut(k), 0, 2 * Math.PI);
        g.stroke();
      } else if (p.src) {
        // A new event at a source: a ring that grows (or, with reduced motion, fades).
        const [x, y] = sourcePos(m, p.src);
        const r = dotRadius(p.src);
        g.strokeStyle = color(m, p.service ? "--map-svc-" + svcIndex(p.service) : "--text-muted");
        g.globalAlpha = (1 - k) * 0.9;
        g.lineWidth = 1.5;
        g.beginPath();
        g.arc(x, y, m.still ? r + 3 : r + 2 + 10 * k, 0, 2 * Math.PI);
        g.stroke();
      }
      g.globalAlpha = 1;
    }
  }

  // The sensor: a honey pot with one labelled dock per service around it.
  function drawPot(m, g) {
    const [x, y] = potPos(m);
    const r = dockRadius(m);
    // A pad under the ring keeps the docks readable over nearby sources.
    g.fillStyle = color(m, "--map-water");
    g.globalAlpha = 0.82;
    g.beginPath();
    g.arc(x, y, r + 6, 0, 2 * Math.PI);
    g.fill();
    g.globalAlpha = 1;
    g.strokeStyle = color(m, "--map-coast");
    g.lineWidth = 1;
    g.setLineDash([2, 3]);
    g.beginPath();
    g.arc(x, y, r, 0, 2 * Math.PI);
    g.stroke();
    g.setLineDash([]);
    g.fillStyle = color(m, "--map-pot");
    g.strokeStyle = color(m, "--map-pot-ink");
    g.lineWidth = 1.5;
    g.beginPath();
    g.moveTo(x - 7, y - 8);
    g.bezierCurveTo(x - 15, y - 6, x - 14, y + 9, x - 6, y + 10);
    g.lineTo(x + 6, y + 10);
    g.bezierCurveTo(x + 14, y + 9, x + 15, y - 6, x + 7, y - 8);
    g.closePath();
    g.fill();
    g.stroke();
    g.fillStyle = color(m, "--map-pot-ink");
    g.fillRect(x - 9, y - 11, 18, 3.5);
    g.beginPath();
    g.ellipse(x + 3, y - 5, 2, 3.2, 0, 0, 2 * Math.PI);
    g.fill();
    const px = m.small ? 10 : 11;
    g.font = "600 " + (px + 1) + "px " + color(m, "--font-ui");
    g.textAlign = "center";
    g.textBaseline = "top";
    label(m, g, m.sensor ? m.sensor.label : "", x, y + r + px * 2 + 3);
    g.font = px + "px " + color(m, "--font-ui");
    for (const service of m.docks) {
      const [dx, dy, a] = dockPos(m, service);
      const shown = !m.off.has(service);
      g.globalAlpha = shown ? 1 : 0.35;
      g.fillStyle = color(m, "--map-svc-" + svcIndex(service));
      g.strokeStyle = color(m, "--surface");
      g.lineWidth = 1.5;
      g.beginPath();
      g.arc(dx, dy, 4.5, 0, 2 * Math.PI);
      g.fill();
      g.stroke();
      const c = Math.cos(a);
      const sn = Math.sin(a);
      g.textAlign = c > 0.35 ? "left" : c < -0.35 ? "right" : "center";
      g.textBaseline = sn > 0.35 ? "top" : sn < -0.35 ? "bottom" : "middle";
      const port = m.ports.get(service);
      label(m, g, service.toUpperCase() + (port && !m.small ? " " + port : ""), dx + c * 8, dy + sn * 8);
      g.globalAlpha = 1;
    }
  }

  // Text with a halo in the surface colour so it reads over land, sea and trails.
  function label(m, g, text, x, y) {
    if (!text) return;
    const w = g.measureText(text).width;
    const align = g.textAlign;
    const left = align === "left" ? x : align === "right" ? x - w : x - w / 2;
    const dx = Math.max(2 - left, Math.min(0, m.w - 2 - (left + w)));
    g.lineWidth = 3;
    g.lineJoin = "round";
    g.strokeStyle = color(m, "--surface");
    g.strokeText(text, x + dx, y);
    g.fillStyle = color(m, "--text");
    g.fillText(text, x + dx, y);
  }

  function drawTip(m, g) {
    const s = m.hover ? m.sources.get(m.hover) : null;
    if (!s) return;
    const [x, y] = sourcePos(m, s);
    const lines = [s.place || "Unlocated", m.hide ? null : s.src, plural(s.events, "event", "events") + " in the window"]
      .filter(Boolean).map((t) => t.slice(0, 80));
    g.font = "12px " + color(m, "--font-ui");
    const w = Math.max(...lines.map((t) => g.measureText(t).width)) + 16;
    const h = lines.length * 16 + 10;
    const bx = Math.max(4, Math.min(m.w - w - 4, x + 12));
    const by = Math.max(4, Math.min(m.h - h - 4, y - h - 8));
    g.fillStyle = color(m, "--surface");
    g.strokeStyle = color(m, "--border-strong");
    g.lineWidth = 1;
    g.beginPath();
    g.roundRect(bx + 0.5, by + 0.5, w, h, 4);
    g.fill();
    g.stroke();
    g.fillStyle = color(m, "--text");
    g.textAlign = "left";
    g.textBaseline = "top";
    lines.forEach((t, i) => g.fillText(t, bx + 8, by + 6 + i * 16));
  }

  function sourceAt(m, x, y) {
    let best = null;
    let bestD = Infinity;
    for (const s of m.sources.values()) {
      const [sx, sy] = sourcePos(m, s);
      const d = Math.hypot(sx - x, sy - y);
      if (d <= dotRadius(s) + 5 && d < bestD) {
        best = s.src;
        bestD = d;
      }
    }
    return best;
  }

  function setHover(m, src) {
    if (m.hover === src) return;
    for (const li of m.rows.get(m.hover) || []) li.classList.remove("map-row-hot");
    m.hover = src;
    for (const li of m.rows.get(src) || []) li.classList.add("map-row-hot");
    m.canvas.classList.toggle("map-canvas-hot", Boolean(src));
    kick(m);
  }

  function openSource(src) {
    if (typeof src === "string" && ADDRESS_RE.test(src)) location.hash = activityHref({ src: src, win: "1h" });
  }

  // ---- map: legend, counters and feed ----

  function drawLegend(m) {
    setKids(m.legend, m.docks.map((service) => {
      const b = button(service, () => {
        if (m.off.has(service)) m.off.delete(service);
        else m.off.add(service);
        b.setAttribute("aria-pressed", m.off.has(service) ? "false" : "true");
        drawFeed(m);
        kick(m);
      }, "btn-small map-key " + MAP_SVC_CLASS[svcIndex(service)]);
      b.setAttribute("aria-pressed", m.off.has(service) ? "false" : "true");
      return b;
    }));
  }

  function drawCounters(m, totals, d) {
    const minutes = arr(totals.per_minute).map((x) => Number(obj(x).events) || 0);
    const done = minutes.slice(0, -1);
    const rate = done.length ? done.reduce((a, b) => a + b, 0) / done.length : (minutes[0] || 0);
    const top = (o) => Object.entries(obj(o)).slice(0, 3).map(([k, n]) => k + " " + num(n)).join(" · ") || "-";
    const total = Number(totals.events) || 0;
    m.flyingNode = el("div", "tile-value");
    m.shownFlying = -1;
    setKids(m.counters,
      tile("Events in the last " + lookup(MAP_WINDOW_TEXT, m.win, ""), num(total)),
      tile("Per minute", rate < 10 ? rate.toFixed(1) : num(Math.round(rate))),
      el("div", "tile", el("div", { cls: "tile-label", text: "Top countries" }), el("div", { cls: "map-top", text: top(totals.countries) })),
      el("div", "tile", el("div", { cls: "tile-label", text: "Top services" }), el("div", { cls: "map-top", text: top(totals.services) })),
      el("div", "tile", el("div", { cls: "tile-label", text: "In flight" }), m.flyingNode));
    const located = [...m.sources.values()].filter((s) => s.lat !== null).length;
    m.canvas.setAttribute("aria-label", "World map: " + plural(m.sources.size, "source", "sources") + ", " +
      num(located) + " placed, " + plural(total, "event", "events") + " in the last " + lookup(MAP_WINDOW_TEXT, m.win, "") +
      ". The list of live events beside it is the same information as text.");
    if (d.located === false && !m.note.firstChild) {
      setKids(m.note, notice("warn", "No IP location database is set ([geoip] in config.ini), so every source is in the unlocated lane."));
    }
  }

  function drawFeed(m) {
    m.rows.clear();
    m.list.replaceChildren();
    for (const it of m.feed.slice().reverse()) addFeedRow(m, it);
  }

  function addFeedRow(m, it) {
    const service = str(it.service);
    if (m.off.has(service)) return;
    const src = str(it.src);
    const when = parseTime(it.time);
    const port = Number.isInteger(it.dst_port) ? " " + it.dst_port : "";
    const li = el("li", { cls: "map-row", attrs: { tabindex: "0" } },
      el("div", "map-row-head",
        el("span", { cls: "mono faint", text: when ? clockUtc(when) : "-" }),
        el("span", { cls: "map-svc " + MAP_SVC_CLASS[svcIndex(service)], text: service + port }),
        el("span", { cls: "map-kind", text: kindLabel(it.kind) }),
        it.outcome ? outcomeBadge(it.outcome) : null),
      el("div", "map-row-where",
        el("span", { text: str(it.place) || "Unlocated" }),
        m.hide ? null : el("span", { cls: "mono muted", text: " " + src }),
        it.judgement ? el("span", { text: " " }) : null, it.judgement ? judgementBadge(it.judgement) : null),
      el("div", { cls: "map-row-what mono", text: str(it.summary) }));
    const enter = () => setHover(m, src || null);
    li.addEventListener("mouseenter", enter);
    li.addEventListener("focus", enter);
    li.addEventListener("mouseleave", () => setHover(m, null));
    li.addEventListener("blur", () => setHover(m, null));
    li.addEventListener("click", () => openSource(src));
    li.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") openSource(src);
    });
    if (src) {
      if (!m.rows.has(src)) m.rows.set(src, new Set());
      m.rows.get(src).add(li);
      if (src === m.hover) li.classList.add("map-row-hot");
    }
    m.list.prepend(li);
    while (m.list.children.length > MAP_FEED) {
      const old = m.list.lastElementChild;
      for (const set of m.rows.values()) set.delete(old);
      old.remove();
    }
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
