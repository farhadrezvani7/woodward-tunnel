import { makeT, coreMessage } from "./i18n.js";

const tauri = window.__TAURI__;
const invoke = (cmd, args) => tauri.core.invoke(cmd, args);
const listen = (ev, cb) => tauri.event.listen(ev, cb);

const $ = (id) => document.getElementById(id);
const ICONS = {
  power: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v8"/><path d="M6.3 6.8a8 8 0 1 0 11.4 0"/></svg>',
  busy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-6.2-8.55"/></svg>',
  ok: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg>',
  warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l10 18H2z"/><path d="M12 10v5"/><path d="M12 18v.01"/></svg>',
};

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
};
let t = makeT("fa");

function setText(el, s) { if (el.textContent !== s) el.textContent = s; }
function fmtNum(n) { return new Intl.NumberFormat(state.lang === "fa" ? "fa-IR" : "en-US").format(n); }

// ---- toasts -------------------------------------------------------------------------------
function toast(msg, bad = false) {
  const el = document.createElement("div");
  el.className = "toast" + (bad ? " bad" : "");
  el.textContent = msg;
  $("toasts").append(el);
  setTimeout(() => el.remove(), bad ? 7000 : 4500);
}
function errText(e) {
  const code = e && e.code ? e.code : "unknown";
  return t("e_" + code);
}

// ---- i18n ---------------------------------------------------------------------------------
function applyLang() {
  t = makeT(state.lang);
  document.documentElement.lang = state.lang;
  document.documentElement.dir = state.lang === "fa" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  $("lang-btn").textContent = t("langBtn");
  $("lang-btn").setAttribute("lang", state.lang === "fa" ? "en" : "fa");
  render();
}

// ---- rendering ----------------------------------------------------------------------------
function activeState(s) { return s !== "idle" && s !== "failed"; }

function render() {
  renderStatus();
  renderList();
}

function renderStatus() {
  const s = state.status;
  const st = s.state;
  const btn = $("connect-btn");
  let icon = ICONS.power, label = t("b_idle"), group = "idle";
  if (st === "preparing" || st === "connecting") { icon = ICONS.busy; label = t("b_busy"); group = "connecting"; }
  else if (st === "reconnecting") { icon = ICONS.busy; label = t("b_busy"); group = "reconnecting"; }
  else if (st === "connected") { icon = ICONS.ok; label = t("b_connected"); group = "connected"; }
  else if (st === "disconnecting") { icon = ICONS.busy; label = t("b_disconnecting"); group = "connecting"; }
  else if (st === "failed") { icon = ICONS.warn; label = t("b_failed"); group = "failed"; }
  btn.dataset.state = group;
  btn.disabled = st === "disconnecting";
  if ($("power-icon").dataset.k !== group) { $("power-icon").innerHTML = icon; $("power-icon").dataset.k = group; }
  setText($("power-label"), label);
  setText($("state-title"), t("s_" + st));

  const detail = $("state-detail");
  let d = "";
  if (st === "failed" || st === "reconnecting") d = coreMessage(state.lang, s.message, t) || "";
  else if (st === "connected") d = selectedName() || "";
  else if (st === "connecting" && s.attempt > 1) d = fmtNum(s.attempt);
  else if (st === "idle" && state.profiles.length === 0) d = t("noProfile");
  setText(detail, d);

  $("timer").hidden = st !== "connected";
  $("insecure").hidden = !(activeState(st) && s.insecure_tls);
  if (!$("insecure").hidden) setText($("insecure"), t("insecure"));
  tickTimer();
}

function selectedName() {
  const p = state.profiles.find((x) => x.id === state.selected);
  return p ? p.name : "";
}

function tickTimer() {
  const s = state.status;
  if (s.state !== "connected" || !s.connected_since) return;
  let secs = Math.max(0, Math.floor((Date.now() - s.connected_since) / 1000));
  const h = Math.floor(secs / 3600); secs %= 3600;
  const m = Math.floor(secs / 60); secs %= 60;
  const two = (n) => String(n).padStart(2, "0");
  const txt = `${two(h)}:${two(m)}:${two(secs)}`;
  setText($("timer-text"), state.lang === "fa" ? txt.replace(/\d/g, (c) => "۰۱۲۳۴۵۶۷۸۹"[c]) : txt);
}
setInterval(tickTimer, 1000);

function renderList() {
  const ul = $("list");
  ul.textContent = "";
  const empty = $("empty");
  empty.hidden = state.profiles.length > 0;
  if (!empty.hidden) empty.textContent = t("empty");
  for (const p of state.profiles) {
    const li = document.createElement("li");
    li.className = "row";
    li.dataset.selected = String(p.id === state.selected);

    const main = document.createElement("button");
    main.type = "button";
    main.className = "row-main";
    main.setAttribute("aria-pressed", String(p.id === state.selected));
    const mark = document.createElement("span"); mark.className = "mark"; mark.setAttribute("aria-hidden", "true");
    const badge = document.createElement("span"); badge.className = "badge"; badge.textContent = p.protocol;
    const text = document.createElement("span"); text.className = "row-text";
    const name = document.createElement("span"); name.className = "row-name"; name.textContent = p.name;
    text.append(name);
    const sub = [p.group, state.showDetails ? `${p.host}:${p.port}` : ""].filter(Boolean).join(" · ");
    if (sub) { const s = document.createElement("span"); s.className = "row-sub"; s.textContent = sub; text.append(s); }
    main.append(mark, badge, text);
    main.addEventListener("click", () => selectProfile(p.id));

    const edit = document.createElement("button");
    edit.type = "button"; edit.className = "row-edit"; edit.textContent = t("edit");
    edit.setAttribute("aria-label", `${t("edit")}: ${p.name}`);
    edit.addEventListener("click", () => openEdit(p));
    li.append(main, edit);
    ul.append(li);
  }
}

// ---- data ---------------------------------------------------------------------------------
async function refreshProfiles() {
  state.profiles = await invoke("list_profiles");
  if (!state.profiles.some((p) => p.id === state.selected)) {
    const last = state.settings && state.settings.last_profile;
    state.selected = state.profiles.some((p) => p.id === last) ? last : (state.profiles[0] ? state.profiles[0].id : null);
  }
  render();
}

async function selectProfile(id) {
  state.selected = id;
  render();
  // Choosing another server while connected switches to it.
  if (activeState(state.status.state) && state.status.profile_id !== id) doConnect(id);
}

async function doConnect(id) {
  if (!id) { toast(state.profiles.length ? t("pickProfile") : t("noProfile"), true); return; }
  try {
    await invoke("connect", { id });
  } catch (e) {
    if (e && e.code === "needs_privilege") { state.pendingConnect = id; openDialog("dlg-priv"); return; }
    toast(errText(e), true);
  }
}

$("connect-btn").addEventListener("click", () => {
  const st = state.status.state;
  if (st === "idle" || st === "failed") doConnect(state.selected);
  else if (st !== "disconnecting") invoke("disconnect").catch((e) => toast(errText(e), true));
});

// ---- import -------------------------------------------------------------------------------
async function handleImport(dto) {
  if (!dto) return;
  const parts = [];
  if (dto.added.length) parts.push(t("imp_added", { n: fmtNum(dto.added.length) }));
  if (dto.duplicates) parts.push(t("imp_dup", { n: fmtNum(dto.duplicates) }));
  if (dto.problems.length) {
    const msgs = [...new Set(dto.problems.map((p) => p.message))].slice(0, 2).join(" ");
    parts.push(t("imp_problem", { n: fmtNum(dto.problems.length), msg: msgs }));
  }
  if (!parts.length && !dto.subscription_urls.length) parts.push(t("imp_none"));
  if (parts.length) toast(parts.join(" "), !dto.added.length && !dto.duplicates);
  await refreshProfiles();
  if (dto.added.length && !activeState(state.status.state)) state.selected = dto.added[0].id;
  render();
  if (dto.subscription_urls.length) { state.pendingSub.push(...dto.subscription_urls); askNextSubscription(); }
}

function askNextSubscription() {
  if ($("dlg-sub").open || !state.pendingSub.length) return;
  const url = state.pendingSub.shift();
  $("sub-text").textContent = t("subText");
  $("sub-url").textContent = url;
  $("dlg-sub").dataset.url = url;
  openDialog("dlg-sub");
}
$("sub-ok").addEventListener("click", async () => {
  const url = $("dlg-sub").dataset.url;
  $("dlg-sub").close();
  try {
    const dto = await invoke("import_subscription", { url });
    toast(t("imp_sub", { n: fmtNum(dto.added.length) }));
    await refreshProfiles();
  } catch (e) { toast(e && e.detail ? e.detail : errText(e), true); }
  askNextSubscription();
});
$("dlg-sub").addEventListener("close", () => setTimeout(askNextSubscription, 0));

$("add-file").addEventListener("click", async () => {
  try { await handleImport(await invoke("pick_and_import")); } catch (e) { toast(errText(e), true); }
});

async function importText(text) {
  if (!text || !text.trim()) return;
  try { await handleImport(await invoke("import_text", { text })); } catch (e) { toast(errText(e), true); }
}
$("add-paste").addEventListener("click", async () => {
  try {
    const text = await navigator.clipboard.readText();
    if (text && text.trim()) { await importText(text); return; }
  } catch (_) { /* the webview may deny clipboard reads: use the paste box */ }
  $("paste-text").value = "";
  openDialog("dlg-paste");
});
$("paste-ok").addEventListener("click", async () => {
  const text = $("paste-text").value;
  $("dlg-paste").close();
  $("paste-text").value = "";
  await importText(text);
});
document.addEventListener("paste", (ev) => {
  if (document.querySelector("dialog[open]")) return;
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
  try {
    const name = $("edit-name").value.trim(), group = $("edit-group").value.trim();
    if (name !== p.name) await invoke("rename_profile", { id: p.id, name });
    if (group !== (p.group || "")) await invoke("set_profile_group", { id: p.id, group });
    $("dlg-edit").close();
    await refreshProfiles();
  } catch (e) { toast(errText(e), true); }
});
$("edit-del").addEventListener("click", () => {
  const p = state.editing; if (!p) return;
  $("dlg-edit").close();
  $("del-text").textContent = t("delText", { name: p.name });
  openDialog("dlg-del");
});
$("del-ok").addEventListener("click", async () => {
  const p = state.editing; if (!p) return;
  $("dlg-del").close();
  try { await invoke("delete_profile", { id: p.id }); await refreshProfiles(); } catch (e) { toast(errText(e), true); }
});

// ---- permission ---------------------------------------------------------------------------
$("priv-ok").addEventListener("click", async () => {
  $("dlg-priv").close();
  try {
    await invoke("grant_privilege");
    const id = state.pendingConnect; state.pendingConnect = null;
    if (id) doConnect(id);
  } catch (e) { toast(t("privFailed"), true); }
});

// ---- advanced -----------------------------------------------------------------------------
$("adv-btn").addEventListener("click", async () => {
  state.settings = await invoke("get_settings");
  const s = state.settings;
  document.querySelectorAll('input[name="mode"]').forEach((r) => { r.checked = r.value === s.mode; });
  $("adv-port").value = s.socks_port;
  $("adv-dns").value = s.dns.join(", ");
  $("adv-details").checked = state.showDetails;
  await refreshInfo();
  openDialog("dlg-adv");
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
  if (i.secrets !== "os" && !state.warnedSecrets) { state.warnedSecrets = true; toast(t("secretsMemory"), true); }
}
$("adv-grant").addEventListener("click", async () => {
  try { await invoke("grant_privilege"); await refreshInfo(); } catch (e) { toast(t("privFailed"), true); }
});
$("adv-save").addEventListener("click", async () => {
  const mode = (document.querySelector('input[name="mode"]:checked') || {}).value || "tun";
  const dns = $("adv-dns").value.split(",").map((x) => x.trim()).filter(Boolean);
  try {
    state.settings = await invoke("set_settings", { settings: { ...state.settings, mode, socks_port: Number($("adv-port").value), dns } });
    state.showDetails = $("adv-details").checked;
    saveLocal("details", state.showDetails ? "1" : "0");
    $("dlg-adv").close();
    toast(t("settingsSaved"));
    render();
  } catch (e) { toast(errText(e), true); }
});

// ---- dialogs ------------------------------------------------------------------------------
function openDialog(id) { const d = $(id); if (!d.open) d.showModal(); }
document.querySelectorAll("dialog [data-close]").forEach((b) => b.addEventListener("click", () => b.closest("dialog").close()));
document.querySelectorAll("dialog form").forEach((f) => f.addEventListener("submit", (e) => e.preventDefault()));

// ---- language -----------------------------------------------------------------------------
function saveLocal(k, v) { try { localStorage.setItem("wt." + k, v); } catch (_) { /* optional */ } }
function loadLocal(k) { try { return localStorage.getItem("wt." + k); } catch (_) { return null; } }
$("lang-btn").addEventListener("click", async () => {
  state.lang = state.lang === "fa" ? "en" : "fa";
  applyLang();
  try { state.settings = await invoke("set_settings", { settings: { ...(state.settings || await invoke("get_settings")), lang: state.lang } }); } catch (e) { toast(errText(e), true); }
});

// ---- events from the Rust side ---------------------------------------------------------------
listen("status", (ev) => { state.status = ev.payload; renderStatus(); });
listen("imported", (ev) => handleImport(ev.payload));
listen("app-error", (ev) => toast(errText(ev.payload), true));
listen("drag-state", (ev) => { $("drop").hidden = !ev.payload; });

// ---- start ----------------------------------------------------------------------------------
(async function init() {
  state.showDetails = loadLocal("details") === "1";
  try {
    state.settings = await invoke("get_settings");
    state.lang = state.settings.lang === "en" ? "en" : "fa";
    state.status = await invoke("get_status");
    applyLang();
    await refreshProfiles();
    const info = await invoke("app_info");
    if (info.secrets !== "os") toast(t("secretsMemory"), true);
    if (state.status.profile_id) state.selected = state.status.profile_id;
    render();
  } catch (e) {
    applyLang();
    toast(errText(e), true);
  }
})();
