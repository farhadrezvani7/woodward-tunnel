import { makeT } from "./i18n.js";

const tauri = window.__TAURI__;
const invoke = (cmd, args) => tauri.core.invoke(cmd, args);
const listen = (ev, cb) => tauri.event.listen(ev, cb);

const $ = (id) => document.getElementById(id);
const ICONS = {
  power: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v8"/><path d="M6.3 6.8a8 8 0 1 0 11.4 0"/></svg>',
  busy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-6.2-8.55"/></svg>',
  ok: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg>',
  warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l10 18H2z"/><path d="M12 10v5"/><path d="M12 18v.01"/></svg>',
  add: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14"/><path d="M5 12h14"/></svg>',
};

const PAGE = 100; // rows rendered at once; a filter box and "show more" cover the rest
const FILTER_FROM = 8; // the search box appears from this many servers
const SLOW_AFTER = 15; // seconds of connecting before the "taking long" hint
const ZOOMS = [100, 125, 150, 175, 200];

const state = {
  lang: "fa",
  settings: null,
  profiles: [],
  selected: null,
  status: { state: "idle" },
  info: null,
  showDetails: false,
  editing: null,
  pendingSub: [],
  pendingConnect: null,
  filter: "",
  limit: PAGE,
  importing: false,
  cancelling: false,
  busySince: 0,
  problems: [],
  theme: "auto",
  zoom: 100,
  lastSr: "",
};
let t = makeT("fa");

// Core texts come in both languages: `message` (Persian) and `message_en`.
function pick(o, k) { return (state.lang === "fa" ? o[k] : o[k + "_en"]) || o[k] || ""; }
function setText(el, s) { if (el.textContent !== s) el.textContent = s; }
function fmtNum(n) { return new Intl.NumberFormat(state.lang === "fa" ? "fa-IR" : "en-US").format(n); }
function activeState(s) { return s !== "idle" && s !== "failed"; }
function profileById(id) { return state.profiles.find((x) => x.id === id); }

// ---- local (per-viewer) preferences ----------------------------------------------------------
function saveLocal(k, v) { try { localStorage.setItem("wt." + k, v); } catch (_) { /* optional */ } }
function loadLocal(k) { try { return localStorage.getItem("wt." + k); } catch (_) { return null; } }

function applyTheme() {
  const th = ["light", "dark"].includes(state.theme) ? state.theme : "auto";
  if (th === "auto") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.dataset.theme = th;
}
function applyZoom() {
  document.documentElement.style.fontSize = state.zoom + "%";
  setText($("zoom-val"), fmtNum(state.zoom) + (state.lang === "fa" ? "٪" : "%"));
}
function setZoom(z) {
  const i = Math.max(0, Math.min(ZOOMS.length - 1, ZOOMS.indexOf(z)));
  state.zoom = ZOOMS[i];
  saveLocal("zoom", String(state.zoom));
  applyZoom();
}
function stepZoom(d) {
  let i = ZOOMS.findIndex((z) => z >= state.zoom);
  if (i < 0) i = ZOOMS.length - 1;
  setZoom(ZOOMS[Math.max(0, Math.min(ZOOMS.length - 1, i + d))]);
}

// ---- messages ---------------------------------------------------------------------------------
function toast(msg, opts = {}) {
  const { bad = false, action = null, ttl = bad || action ? 12000 : 5000 } = opts;
  const el = document.createElement("div");
  el.className = "toast" + (bad ? " bad" : "");
  el.setAttribute("role", bad ? "alert" : "status");
  const text = document.createElement("span");
  text.className = "toast-text";
  text.textContent = msg;
  el.append(text);
  if (action) {
    const a = document.createElement("button");
    a.type = "button"; a.textContent = action.label;
    a.addEventListener("click", () => { el.remove(); action.run(); });
    el.append(a);
  }
  if (ttl > 0) {
    const x = document.createElement("button");
    x.type = "button"; x.className = "toast-x"; x.textContent = "×";
    x.setAttribute("aria-label", t("toastClose"));
    x.addEventListener("click", () => el.remove());
    el.append(x);
    setTimeout(() => el.remove(), ttl);
  }
  $("toasts").append(el);
  return () => el.remove();
}

// A modal dialog hides everything behind it, toasts included: errors raised while one is open go
// inside it.
function report(msg) {
  const d = document.querySelector("dialog[open]");
  const box = d && d.querySelector(".dlg-error");
  if (box) { box.textContent = msg; box.hidden = false; return; }
  toast(msg, { bad: true });
}
function clearDialogError(d) {
  d.querySelectorAll(".dlg-error, .dlg-ok").forEach((e) => { e.hidden = true; e.textContent = ""; });
}

function errText(e) {
  const code = e && e.code ? e.code : "unknown";
  if (code === "bad_settings" && e.detail && t("e_bad_settings_" + e.detail) !== "e_bad_settings_" + e.detail) return t("e_bad_settings_" + e.detail);
  return t("e_" + code);
}
function fetchErrText(e) {
  let s = e && e.detail ? pick(e, "detail") : errText(e);
  if (navigator.onLine === false) s += " " + t("offline");
  return s;
}

function srAnnounce(s) {
  if (s === state.lastSr) return;
  state.lastSr = s;
  setText($("sr-live"), s);
}

// ---- i18n ---------------------------------------------------------------------------------
function applyLang() {
  t = makeT(state.lang);
  document.documentElement.lang = state.lang;
  document.documentElement.dir = state.lang === "fa" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll("[data-i18n-ph]").forEach((el) => { el.placeholder = t(el.dataset.i18nPh); });
  document.querySelectorAll("[data-i18n-aria]").forEach((el) => { el.setAttribute("aria-label", t(el.dataset.i18nAria)); });
  $("lang-btn").textContent = t("langBtn");
  $("lang-btn").setAttribute("lang", state.lang === "fa" ? "en" : "fa");
  applyZoom();
  renderBanner();
  render();
}

// ---- rendering ----------------------------------------------------------------------------
function render() {
  renderStatus();
  renderList();
}

function renderBanner() {
  const b = $("banner");
  const memory = state.info && state.info.secrets !== "os";
  b.hidden = !memory;
  if (memory) setText(b, state.info.platform === "linux" ? t("secretsMemory_linux") : t("secretsMemory"));
}

function renderStatus() {
  const s = state.status;
  const st = s.state;
  const btn = $("connect-btn");
  const noServers = state.profiles.length === 0;
  let icon = ICONS.power, label = t("b_idle"), group = "idle", title = t("s_" + st);
  if (st === "preparing" || st === "connecting") { icon = ICONS.busy; label = t("b_busy"); group = "connecting"; }
  else if (st === "reconnecting") { icon = ICONS.busy; label = t("b_busy"); group = "reconnecting"; }
  else if (st === "connected") { icon = ICONS.ok; label = t("b_connected"); group = "connected"; }
  else if (st === "disconnecting") { icon = ICONS.busy; label = t("b_disconnecting"); group = "connecting"; }
  else if (st === "failed") { icon = ICONS.warn; label = t("b_failed"); group = "failed"; }
  else if (noServers) { icon = ICONS.add; label = t("b_add"); }
  if (state.cancelling && activeState(st)) { label = t("b_cancelling"); title = t("s_cancelling"); }
  btn.dataset.state = group;
  btn.disabled = st === "disconnecting";
  if ($("power-icon").dataset.k !== group + (noServers && st === "idle" ? "+" : "")) {
    $("power-icon").innerHTML = icon;
    $("power-icon").dataset.k = group + (noServers && st === "idle" ? "+" : "");
  }
  setText($("power-label"), label);
  setText($("state-title"), title);

  let d = "";
  const fix = $("fix-btn");
  fix.hidden = true;
  if (st === "failed" || st === "reconnecting") {
    d = pick(s, "message") || "";
    if (st === "reconnecting" && s.attempt > 0) d += ` (${t("attempt", { n: fmtNum(s.attempt) })})`;
    if (st === "failed" && s.failure_code === "permission") fix.hidden = false;
  } else if (st === "connected") {
    const p = profileById(s.profile_id);
    d = p ? p.name : "";
  } else if (st === "idle" && noServers) d = t("noProfile");
  setText($("state-detail"), d);

  $("timer").hidden = !(st === "connected" || ((st === "connecting" || st === "preparing" || st === "reconnecting") && state.busySince));
  $("timer").classList.toggle("elapsed", st !== "connected");

  const insecure = activeState(st) && s.insecure_tls;
  $("insecure").hidden = !insecure;
  if (insecure) setText($("insecure"), t("insecure"));

  const proxyNote = st === "connected" && state.settings && state.settings.mode === "proxy";
  $("mode-note").hidden = !proxyNote;
  if (proxyNote) setText($("mode-note"), t("proxyNote", { port: state.settings.socks_port }));

  renderKillSwitch();
  $("adv-warn").hidden = !activeState(st);
  tickTimer();
  srAnnounce([title, d].filter(Boolean).join(". "));
}

// Leak protection: the core says when rules are loaded while nothing is connected (the network is
// blocked on purpose) or when rules of a crashed run remain.
function renderKillSwitch() {
  const s = state.status, st = s.state;
  let text = "", btn = "", cmd = "";
  if (s.kill_switch_leftover && (st === "idle" || st === "failed")) { text = t("ksLeftover"); btn = t("ksClear"); cmd = "clear_leftover_rules"; }
  else if (s.kill_switch_active && st !== "connected") { text = t("ksActive"); btn = t("ksAllow"); cmd = "allow_direct"; }
  if (text && s.kill_switch_error) text += " " + t("ksError", { e: s.kill_switch_error });
  $("ks").hidden = !text;
  if (text) { setText($("ks-text"), text); setText($("ks-btn"), btn); $("ks-btn").dataset.cmd = cmd; }
}
$("ks-btn").addEventListener("click", async () => {
  try { await invoke($("ks-btn").dataset.cmd); } catch (e) { toast(errText(e), { bad: true }); }
});

function two(n) { return String(n).padStart(2, "0"); }
function clock(secs) {
  const h = Math.floor(secs / 3600), m = Math.floor((secs % 3600) / 60), sec = secs % 60;
  const txt = `${two(h)}:${two(m)}:${two(sec)}`;
  return state.lang === "fa" ? txt.replace(/\d/g, (c) => "۰۱۲۳۴۵۶۷۸۹"[c]) : txt;
}
function tickTimer() {
  const s = state.status;
  if (s.state === "connected" && s.connected_since) {
    setText($("timer-text"), clock(Math.max(0, Math.floor((Date.now() - s.connected_since) / 1000))));
  } else if (state.busySince && ["connecting", "preparing", "reconnecting"].includes(s.state)) {
    const secs = Math.max(0, Math.floor((Date.now() - state.busySince) / 1000));
    setText($("timer-text"), clock(secs));
    if (secs >= SLOW_AFTER && !state.cancelling && s.state !== "reconnecting") setText($("state-detail"), t("connectSlow"));
  }
}
setInterval(tickTimer, 1000);

function visibleProfiles() {
  const q = state.filter.trim().toLowerCase();
  if (!q) return state.profiles;
  return state.profiles.filter((p) => `${p.name} ${p.group} ${p.protocol} ${p.host}`.toLowerCase().includes(q));
}

function renderList() {
  const ul = $("list");
  const focusKey = document.activeElement && ul.contains(document.activeElement) ? document.activeElement.dataset.fk : null;
  ul.textContent = "";
  const total = state.profiles.length;
  const empty = $("empty");
  empty.hidden = total > 0;
  if (!empty.hidden) empty.textContent = t("empty");
  $("filter-wrap").hidden = total < FILTER_FROM && !state.filter;

  const all = visibleProfiles();
  // Keep the chosen server on screen even when it sits beyond the first page.
  const selIdx = all.findIndex((p) => p.id === state.selected);
  if (selIdx >= state.limit) state.limit = selIdx + 1;
  const shown = all.slice(0, state.limit);
  if (!$("filter-wrap").hidden) {
    setText($("count"), all.length === total ? t("count", { shown: fmtNum(shown.length), total: fmtNum(total) }) : (all.length ? t("count", { shown: fmtNum(all.length), total: fmtNum(total) }) : t("noMatch")));
  }
  const more = $("more");
  more.hidden = shown.length >= all.length;

  for (const p of shown) {
    const li = document.createElement("li");
    li.className = "row";
    li.dataset.selected = String(p.id === state.selected);

    const main = document.createElement("button");
    main.type = "button";
    main.className = "row-main";
    main.dataset.fk = "main:" + p.id;
    main.setAttribute("aria-pressed", String(p.id === state.selected));
    const mark = document.createElement("span"); mark.className = "mark"; mark.setAttribute("aria-hidden", "true");
    const badge = document.createElement("span"); badge.className = "badge"; badge.textContent = p.protocol;
    const text = document.createElement("span"); text.className = "row-text";
    const name = document.createElement("span"); name.className = "row-name"; name.textContent = p.name;
    text.append(name);
    const sub = [p.group, state.showDetails ? `${p.host}:${p.port}` : ""].filter(Boolean).join(" · ");
    if (sub) { const s = document.createElement("span"); s.className = "row-sub"; s.textContent = sub; s.setAttribute("dir", "auto"); text.append(s); }
    main.append(mark, badge, text);
    main.addEventListener("click", () => selectProfile(p.id));

    const edit = document.createElement("button");
    edit.type = "button"; edit.className = "row-edit"; edit.textContent = t("edit");
    edit.dataset.fk = "edit:" + p.id;
    edit.setAttribute("aria-label", `${t("edit")}: ${p.name}`);
    edit.addEventListener("click", () => openEdit(p));
    li.append(main, edit);
    ul.append(li);
  }
  if (focusKey) {
    const again = [...ul.querySelectorAll("[data-fk]")].find((e) => e.dataset.fk === focusKey);
    if (again) again.focus();
  }
}

$("more").addEventListener("click", () => { state.limit += PAGE; renderList(); });
$("filter").addEventListener("input", (e) => { state.filter = e.target.value; state.limit = PAGE; renderList(); });
$("filter").addEventListener("keydown", (e) => {
  if (e.key === "Escape" && e.target.value) { e.preventDefault(); e.target.value = ""; state.filter = ""; renderList(); }
});
// Arrow keys move through the list (a long list is painful to tab through).
$("list").addEventListener("keydown", (e) => {
  if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) return;
  const mains = [...$("list").querySelectorAll(".row-main")];
  const i = mains.indexOf(document.activeElement);
  if (i < 0) return;
  e.preventDefault();
  const n = e.key === "Home" ? 0 : e.key === "End" ? mains.length - 1 : Math.max(0, Math.min(mains.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)));
  mains[n].focus();
});

// ---- data ---------------------------------------------------------------------------------
async function refreshProfiles() {
  state.profiles = await invoke("list_profiles");
  if (!profileById(state.selected)) {
    const last = state.settings && state.settings.last_profile;
    state.selected = profileById(last) ? last : (state.profiles[0] ? state.profiles[0].id : null);
  }
  render();
}

function selectProfile(id) {
  const was = state.selected;
  state.selected = id;
  render();
  // Choosing another server while connected switches to it.
  if (activeState(state.status.state) && state.status.profile_id !== id && was !== id) {
    const p = profileById(id);
    toast(t("switching", { name: p ? p.name : "" }));
    doConnect(id);
  }
}

async function doConnect(id) {
  if (!id) {
    if (!state.profiles.length) openPaste(); else toast(t("pickProfile"), { bad: true });
    return;
  }
  state.cancelling = false;
  try {
    await invoke("connect", { id });
  } catch (e) {
    if (e && e.code === "needs_privilege") { state.pendingConnect = id; openDialog("dlg-priv"); return; }
    toast(errText(e), { bad: true });
  }
}

function cancelOrDisconnect() {
  state.cancelling = true;
  renderStatus();
  // Fire and forget: the UI must never wait on the engine.
  invoke("disconnect").catch((e) => { state.cancelling = false; renderStatus(); toast(errText(e), { bad: true }); });
}

$("connect-btn").addEventListener("click", () => {
  const st = state.status.state;
  if (st === "idle" || st === "failed") doConnect(state.selected);
  else if (st !== "disconnecting") cancelOrDisconnect();
});
$("fix-btn").addEventListener("click", () => { state.pendingConnect = state.selected; openDialog("dlg-priv"); });

function onStatus(next) {
  const prev = state.status.state;
  state.status = next;
  const st = next.state;
  if (!activeState(st)) { state.cancelling = false; state.busySince = 0; }
  else if (["connecting", "preparing", "reconnecting"].includes(st)) { if (!state.busySince || !activeState(prev)) state.busySince = Date.now(); }
  else state.busySince = 0;
  // The tray (or another window) can connect a different server than the one selected here.
  if (activeState(st) && next.profile_id && next.profile_id !== state.selected && profileById(next.profile_id)) {
    state.selected = next.profile_id;
    renderList();
  }
  renderStatus();
}

// ---- import -------------------------------------------------------------------------------
function setImporting(on) {
  state.importing = on;
  $("add-file").disabled = on;
  $("add-paste").disabled = on;
}

async function withImport(fn) {
  if (state.importing) return;
  setImporting(true);
  const done = toast(t("importing"), { ttl: 0 });
  try { return await fn(); } finally { done(); setImporting(false); }
}

function showProblems(list) {
  state.problems = list;
  const ul = $("problems-list");
  ul.textContent = "";
  setText($("problems-intro"), t("problemsIntro", { n: fmtNum(list.length) }));
  for (const p of list.slice(0, 200)) {
    const li = document.createElement("li");
    if (p.label) {
      const l = document.createElement("span");
      l.className = "p-label"; l.setAttribute("dir", "auto"); l.textContent = p.label;
      li.append(l);
    }
    const m = document.createElement("span");
    m.textContent = pick(p, "message");
    li.append(m);
    ul.append(li);
  }
  if (list.length > 200) {
    const li = document.createElement("li");
    li.textContent = t("problemsMore", { n: fmtNum(list.length - 200) });
    ul.append(li);
  }
  openDialog("dlg-problems");
}

async function handleImport(dto, kind) {
  if (!dto) return;
  const added = dto.added.length, dup = dto.duplicates, prob = dto.problems.length;
  const hasSub = dto.subscription_urls.length > 0;
  await refreshProfiles();
  if (added) {
    if (!activeState(state.status.state)) state.selected = dto.added[0].id;
    state.filter = ""; $("filter").value = "";
    renderList();
    const row = [...$("list").querySelectorAll(".row-main")].find((e) => e.dataset.fk === "main:" + dto.added[0].id);
    if (row && row.scrollIntoView) row.scrollIntoView({ block: "nearest" });
  }
  const parts = [];
  if (added) parts.push(t(kind === "sub" ? "imp_sub" : "imp_added", { n: fmtNum(added) }));
  if (dup) parts.push(t("imp_dup", { n: fmtNum(dup) }));
  if (prob && added) parts.push(t("imp_problem", { n: fmtNum(prob) }));
  if (!added && !dup && !prob && !hasSub) parts.push(t("imp_none"));
  if (parts.length) {
    toast(parts.join(" "), { bad: !added && !dup, action: prob && added ? { label: t("imp_view"), run: () => showProblems(dto.problems) } : null });
  }
  if (prob && !added) showProblems(dto.problems);
  if (hasSub) { state.pendingSub.push(...dto.subscription_urls.filter((u) => !state.pendingSub.includes(u))); askNextSubscription(); }
}

function hostOf(url) {
  try { return new URL(url).host; } catch (_) { return ""; }
}
function shortUrl(u) { return u.length > 300 ? u.slice(0, 300) + "…" : u; }

function askNextSubscription() {
  if ($("dlg-sub").open || !state.pendingSub.length) return;
  const url = state.pendingSub.shift();
  setText($("sub-text"), t("subText"));
  setText($("sub-host"), t("subHost", { host: hostOf(url) || "?" }));
  setText($("sub-url"), shortUrl(url));
  $("dlg-sub").dataset.url = url;
  openDialog("dlg-sub");
}
$("sub-ok").addEventListener("click", async () => {
  const url = $("dlg-sub").dataset.url;
  $("dlg-sub").close();
  if (state.importing) return;
  setImporting(true);
  const done = toast(t("downloading"), { ttl: 0 });
  try {
    await handleImport(await invoke("import_subscription", { url }), "sub");
  } catch (e) { toast(fetchErrText(e), { bad: true }); }
  finally { done(); setImporting(false); }
  askNextSubscription();
});
$("dlg-sub").addEventListener("close", () => setTimeout(askNextSubscription, 0));

$("add-file").addEventListener("click", () => withImport(async () => {
  try { await handleImport(await invoke("pick_and_import")); } catch (e) { toast(errText(e), { bad: true }); }
}));

async function importText(text) {
  if (!text || !text.trim()) return;
  await withImport(async () => {
    try { await handleImport(await invoke("import_text", { text })); } catch (e) { toast(errText(e), { bad: true }); }
  });
}
function openPaste() {
  $("paste-text").value = "";
  openDialog("dlg-paste");
}
$("add-paste").addEventListener("click", async () => {
  try {
    const text = await navigator.clipboard.readText();
    if (text && text.trim()) { await importText(text); return; }
  } catch (_) { /* the webview may deny clipboard reads: use the paste box */ }
  openPaste();
});
$("paste-ok").addEventListener("click", async () => {
  const text = $("paste-text").value;
  if (!text.trim()) { report(t("pasteEmpty")); return; }
  $("dlg-paste").close();
  $("paste-text").value = "";
  await importText(text);
});
document.addEventListener("paste", (ev) => {
  if (document.querySelector("dialog[open]") || /^(INPUT|TEXTAREA)$/.test((ev.target || {}).tagName || "")) return;
  const text = ev.clipboardData && ev.clipboardData.getData("text");
  if (text && text.trim()) { ev.preventDefault(); importText(text); }
});

// ---- edit / delete ------------------------------------------------------------------------
function openEdit(p) {
  state.editing = p;
  $("edit-name").value = p.name;
  $("edit-group").value = p.group || "";
  openDialog("dlg-edit");
}
$("edit-ok").addEventListener("click", async () => {
  const p = state.editing; if (!p) return;
  const name = $("edit-name").value.trim(), group = $("edit-group").value.trim();
  if (!name) { report(t("e_bad_name")); $("edit-name").focus(); return; }
  try {
    if (name !== p.name) await invoke("rename_profile", { id: p.id, name });
    if (group !== (p.group || "")) await invoke("set_profile_group", { id: p.id, group });
    $("dlg-edit").close();
    await refreshProfiles();
  } catch (e) { report(errText(e)); }
});
$("edit-del").addEventListener("click", () => {
  const p = state.editing; if (!p) return;
  $("dlg-edit").close();
  const connected = activeState(state.status.state) && state.status.profile_id === p.id;
  setText($("del-text"), t("delText", { name: p.name }) + (connected ? " " + t("delConnected") : ""));
  openDialog("dlg-del");
});
$("del-ok").addEventListener("click", async () => {
  const p = state.editing; if (!p) return;
  try {
    await invoke("delete_profile", { id: p.id });
    $("dlg-del").close();
    await refreshProfiles();
    // The edit button that opened this is gone: put focus somewhere sensible.
    const first = $("list").querySelector(".row-main");
    (first || $("add-paste")).focus();
  } catch (e) { report(errText(e)); }
});

// ---- permission ---------------------------------------------------------------------------
$("priv-ok").addEventListener("click", async () => {
  $("dlg-priv").close();
  try {
    await invoke("grant_privilege");
    const id = state.pendingConnect; state.pendingConnect = null;
    if (id) doConnect(id);
  } catch (e) { toast(t("privFailed"), { bad: true }); }
});

// ---- settings -----------------------------------------------------------------------------
$("adv-btn").addEventListener("click", async () => {
  try {
    state.settings = await invoke("get_settings");
    const s = state.settings;
    document.querySelectorAll('input[name="mode"]').forEach((r) => { r.checked = r.value === s.mode; });
    document.querySelectorAll('input[name="theme"]').forEach((r) => { r.checked = r.value === state.theme; });
    $("adv-port").value = s.socks_port;
    $("adv-dns").value = s.dns.join(", ");
    $("adv-details").checked = state.showDetails;
    $("adv-leak").checked = s.leak_protection !== false;
    $("adv-launch").checked = !!s.connect_on_launch;
    $("adv-minimized").checked = !!s.start_minimized;
    $("adv-tray").checked = s.close_to_tray !== false;
    applyZoom();
    await refreshInfo();
    openDialog("dlg-adv");
  } catch (e) { toast(errText(e), { bad: true }); }
});
async function refreshInfo() {
  const i = await invoke("app_info");
  state.info = i;
  const dl = $("adv-info");
  dl.textContent = "";
  const rows = [
    ["version", i.version], ["platform", i.platform],
    ["sing-box", i.sing_box_found ? "ok" : "missing"],
    ["awg-socks", i.awg_found ? "ok" : "missing"],
    ["openvpn", i.openvpn_found ? "ok" : "missing"],
    ["secure storage", i.secrets === "os" ? "system keychain" : "memory only"],
    ["privilege", i.privilege],
  ];
  for (const [k, v] of rows) {
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd"); dd.textContent = v;
    dl.append(dt, dd);
  }
  $("adv-grant").hidden = i.privilege !== "needs_grant";
  renderBanner();
}
$("adv-grant").addEventListener("click", async () => {
  try { await invoke("grant_privilege"); await refreshInfo(); } catch (e) { report(t("privFailed")); }
});
$("adv-diag").addEventListener("click", async () => {
  try {
    $("diag-text").value = await invoke("diagnostic_report");
    openDialog("dlg-diag");
  } catch (e) { report(errText(e)); }
});
$("diag-copy").addEventListener("click", async () => {
  const ta = $("diag-text");
  try { await navigator.clipboard.writeText(ta.value); }
  catch (_) { ta.focus(); ta.select(); document.execCommand("copy"); }
  // The dialog hides toasts: confirm inside it (and to screen readers).
  const ok = $("diag-ok");
  ok.textContent = t("copied"); ok.hidden = false;
});
$("adv-about").addEventListener("click", async () => {
  const v = (state.info && state.info.version) || "";
  setText($("about-text"), t("aboutText", { v }));
  let txt = t("licensesMissing");
  try { txt = (await invoke("licenses_text")) || txt; } catch (_) { /* not bundled */ }
  $("about-licenses").value = txt;
  openDialog("dlg-about");
});
$("zoom-out").addEventListener("click", () => stepZoom(-1));
$("zoom-in").addEventListener("click", () => stepZoom(1));
document.querySelectorAll('input[name="theme"]').forEach((r) => r.addEventListener("change", () => {
  state.theme = r.value; saveLocal("theme", r.value); applyTheme();
}));
$("adv-save").addEventListener("click", async () => {
  const mode = (document.querySelector('input[name="mode"]:checked') || {}).value || "tun";
  const dns = $("adv-dns").value.split(",").map((x) => x.trim()).filter(Boolean);
  const port = Number($("adv-port").value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) { report(t("e_bad_settings_port")); $("adv-port").focus(); return; }
  const old = state.settings || {};
  const engineChanged = old.mode !== mode || old.socks_port !== port || (old.dns || []).join(",") !== dns.join(",") || (old.leak_protection !== false) !== $("adv-leak").checked;
  const wasActive = activeState(state.status.state);
  try {
    state.settings = await invoke("set_settings", {
      settings: {
        ...old, mode, socks_port: port, dns,
        leak_protection: $("adv-leak").checked,
        connect_on_launch: $("adv-launch").checked,
        start_minimized: $("adv-minimized").checked,
        close_to_tray: $("adv-tray").checked,
      },
    });
    state.showDetails = $("adv-details").checked;
    saveLocal("details", state.showDetails ? "1" : "0");
    $("dlg-adv").close();
    toast(t(engineChanged && wasActive ? "settingsSavedDisc" : "settingsSaved"));
    render();
  } catch (e) { report(errText(e)); }
});

// ---- dialogs ------------------------------------------------------------------------------
function openDialog(id) {
  const d = $(id);
  clearDialogError(d);
  if (!d.open) d.showModal();
}
document.querySelectorAll("dialog [data-close]").forEach((b) => b.addEventListener("click", () => b.closest("dialog").close()));
// Enter in a text field does what the primary button does (and never reloads anything).
document.querySelectorAll("dialog form").forEach((f) => f.addEventListener("submit", (e) => {
  e.preventDefault();
  const p = f.querySelector(".btn.primary");
  if (p && f.closest("dialog").id !== "dlg-sub") p.click();
}));
document.querySelectorAll("dialog").forEach((d) => {
  d.addEventListener("input", () => clearDialogError(d));
  // Return focus to the control that opened a dialog, even if the list was rebuilt meanwhile.
  d.addEventListener("close", () => { if (document.activeElement === document.body || !document.activeElement) restoreFocus(); });
});
function restoreFocus() {
  const ed = state.editing;
  const target = (ed && [...document.querySelectorAll("[data-fk]")].find((e) => e.dataset.fk === "edit:" + ed.id)) || $("connect-btn");
  if (target) target.focus();
}

// Ctrl +/-/0: text size (the webview has no built-in zoom). Context menu only in text fields.
document.addEventListener("keydown", (e) => {
  if (!(e.ctrlKey || e.metaKey) || e.altKey) return;
  if (e.key === "+" || e.key === "=") { e.preventDefault(); stepZoom(1); }
  else if (e.key === "-" || e.key === "_") { e.preventDefault(); stepZoom(-1); }
  else if (e.key === "0") { e.preventDefault(); setZoom(100); }
});
document.addEventListener("contextmenu", (e) => { if (!/^(INPUT|TEXTAREA)$/.test(e.target.tagName)) e.preventDefault(); });

// ---- language -----------------------------------------------------------------------------
async function persistLang() {
  try { state.settings = await invoke("set_settings", { settings: { ...(state.settings || await invoke("get_settings")), lang: state.lang } }); }
  catch (e) { toast(errText(e), { bad: true }); }
}
$("lang-btn").addEventListener("click", async () => {
  state.lang = state.lang === "fa" ? "en" : "fa";
  applyLang();
  await persistLang();
});
function osLang() {
  const l = ((navigator.languages && navigator.languages[0]) || navigator.language || "").toLowerCase();
  return l.startsWith("fa") ? "fa" : "en";
}

// ---- events from the Rust side ---------------------------------------------------------------
listen("status", (ev) => onStatus(ev.payload));
listen("imported", (ev) => handleImport(ev.payload));
listen("app-error", (ev) => {
  const e = ev.payload;
  if (e && e.code === "needs_privilege") { state.pendingConnect = state.selected; openDialog("dlg-priv"); return; }
  report(errText(e));
});
listen("drag-state", (ev) => { $("drop").hidden = !ev.payload; });
// After the window was hidden in the tray (or the webview reloaded) state may be stale.
async function resync() {
  try {
    onStatus(await invoke("get_status"));
    await refreshProfiles();
  } catch (_) { /* the next event will fix it */ }
}
document.addEventListener("visibilitychange", () => { if (!document.hidden) resync(); });
window.addEventListener("focus", resync);
window.addEventListener("online", () => { if (state.status.state === "failed") renderStatus(); });

// ---- start ----------------------------------------------------------------------------------
(async function init() {
  state.showDetails = loadLocal("details") === "1";
  state.theme = ["light", "dark"].includes(loadLocal("theme")) ? loadLocal("theme") : "auto";
  const z = Number(loadLocal("zoom"));
  state.zoom = ZOOMS.includes(z) ? z : 100;
  applyTheme();
  try {
    // The backend starts on its own thread (secure storage can take a moment): retry quietly.
    for (let i = 0; ; i++) {
      try { state.settings = await invoke("get_settings"); break; }
      catch (e) {
        if (i >= 120) throw e;
        if (i === 2) { applyLang(); setText($("state-detail"), t("starting")); }
        await new Promise((r) => setTimeout(r, 250));
      }
    }
    if (state.settings.lang === "auto") {
      state.lang = osLang();
      await persistLang();
    } else state.lang = state.settings.lang === "en" ? "en" : "fa";
    state.status = await invoke("get_status");
    if (activeState(state.status.state) && state.status.state !== "connected") state.busySince = Date.now();
    state.info = await invoke("app_info");
    applyLang();
    await refreshProfiles();
    if (state.status.profile_id && profileById(state.status.profile_id) && activeState(state.status.state)) state.selected = state.status.profile_id;
    render();
    if (state.status.state === "idle" && state.selected && await invoke("take_startup_connect")) doConnect(state.selected);
  } catch (e) {
    applyLang();
    toast(errText(e), { bad: true });
  }
})();
