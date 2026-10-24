// Runs the real UI (ui/index.html + ui/app.js) in jsdom with a scripted stand-in for the Tauri
// bridge. Nothing here talks to the Rust side: backend behaviour is covered by the cargo tests.
import { JSDOM } from "jsdom";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const ui = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "ui");
let counter = 0;
let previous = null; // tests run one after another: the previous window's timers must not outlive it

export const sleep = (ms = 0) => new Promise((r) => setTimeout(r, ms));
export async function flush(n = 6) { for (let i = 0; i < n; i++) await sleep(0); }

export function mkProfiles(n, f = (i) => ({})) {
  return Array.from({ length: n }, (_, i) => ({ id: (i + 1).toString(16).padStart(32, "0"), name: `Server ${i + 1}`, protocol: "VLESS", group: "", host: `h${i}.example.com`, port: 443, ...f(i) }));
}

/** Boot the UI. `api` maps command names to a value or function(args). Unlisted commands fail loudly. */
export async function boot({ profiles = [], settings = {}, status = { state: "idle", attempt: 0, insecure_tls: false }, info = {}, api = {}, language = "fa-IR" } = {}) {
  const html = readFileSync(path.join(ui, "index.html"), "utf8").replace(/<script[^>]*><\/script>/, "");
  const dom = new JSDOM(html, { url: "http://localhost/", pretendToBeVisual: true });
  const w = dom.window;
  if (previous) { try { previous.close(); } catch (_) { /* already closed */ } }
  previous = w;
  Object.defineProperty(w.navigator, "language", { value: language, configurable: true });
  Object.defineProperty(w.navigator, "languages", { value: [language], configurable: true });
  // jsdom has no modal dialogs.
  w.HTMLDialogElement.prototype.showModal = function () { this.setAttribute("open", ""); };
  w.HTMLDialogElement.prototype.close = function () { if (this.hasAttribute("open")) { this.removeAttribute("open"); this.dispatchEvent(new w.Event("close")); } };
  w.HTMLElement.prototype.scrollIntoView = () => {};

  const calls = [];
  const handlers = {};
  const cfg = { lang: "fa", mode: "tun", socks_port: 10808, dns: [], last_profile: null, connect_on_launch: false, start_minimized: false, close_to_tray: true, ...settings };
  const data = { profiles, status, settings: cfg };
  const defaults = {
    get_settings: () => data.settings,
    set_settings: ({ settings: s }) => { data.settings = { ...s }; return data.settings; },
    get_status: () => data.status,
    list_profiles: () => data.profiles,
    app_info: () => ({ version: "9.9.9", platform: "linux", sing_box_found: true, awg_found: true, openvpn_found: false, secrets: "os", privilege: "ok", data_dir: "/x", os_lang: "fa", ...info }),
    take_startup_connect: () => false,
    licenses_text: () => "Third party notices test text",
    rename_profile: null, set_profile_group: null, delete_profile: null,
    disconnect: () => null, allow_direct: null, clear_leftover_rules: null,
    connect: () => null,
  };
  w.__TAURI__ = {
    core: {
      invoke: async (cmd, args) => {
        calls.push({ cmd, args });
        const h = cmd in api ? api[cmd] : defaults[cmd];
        if (h === undefined) throw { code: "internal", detail: "unmocked " + cmd };
        const v = typeof h === "function" ? await h(args) : h;
        if (v && v.__throw) throw v.__throw;
        return v;
      },
    },
    event: { listen: async (ev, cb) => { (handlers[ev] ||= []).push(cb); return () => {}; } },
  };
  const g = globalThis;
  for (const k of ["window", "document", "navigator", "localStorage", "Intl"]) {
    if (k === "Intl") continue;
    Object.defineProperty(g, k, { value: w[k === "window" ? "window" : k], configurable: true, writable: true });
  }
  g.setInterval = w.setInterval.bind(w); g.clearInterval = w.clearInterval.bind(w);
  g.URL = w.URL;
  await import(`../ui/app.js?run=${++counter}`);
  await flush();
  const $ = (id) => w.document.getElementById(id);
  const api2 = {
    w, $, calls, data,
    emit: async (ev, payload) => { for (const cb of handlers[ev] || []) cb({ payload }); await flush(); },
    click: async (el) => { (typeof el === "string" ? $(el) : el).click(); await flush(); },
    text: (id) => $(id).textContent,
    rows: () => [...w.document.querySelectorAll("#list .row")],
    toasts: () => [...w.document.querySelectorAll("#toasts .toast")].map((t) => t.querySelector(".toast-text").textContent),
    called: (cmd) => calls.filter((c) => c.cmd === cmd),
    close: () => w.close(),
  };
  return api2;
}

export const st = (state, extra = {}) => ({ state, profile_id: null, connected_since: null, message: null, message_en: null, failure_code: null, attempt: 0, insecure_tls: false, ...extra });
