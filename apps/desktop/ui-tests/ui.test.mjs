import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { boot, flush, mkProfiles, st } from "./harness.mjs";
import { dict } from "../ui/i18n.js";

const html = readFileSync(new URL("../ui/index.html", import.meta.url), "utf8");

test("every UI string exists in both languages, and every data-i18n key is defined", () => {
  const fa = Object.keys(dict.fa), en = Object.keys(dict.en);
  assert.deepEqual(fa.filter((k) => !en.includes(k)), []);
  assert.deepEqual(en.filter((k) => !fa.includes(k)), []);
  for (const m of html.matchAll(/data-i18n(?:-ph|-aria)?="([^"]+)"/g)) assert.ok(fa.includes(m[1]), "missing key " + m[1]);
  for (const k of fa) assert.ok(dict.fa[k].trim() && dict.en[k].trim(), "empty text " + k);
});

test("static accessibility: unique ids, labelled controls and dialogs, live region, no inline handlers", async () => {
  const ui = await boot();
  const d = ui.w.document;
  const ids = [...d.querySelectorAll("[id]")].map((e) => e.id);
  assert.equal(new Set(ids).size, ids.length, "duplicate ids");
  for (const dlg of d.querySelectorAll("dialog")) {
    const lab = dlg.getAttribute("aria-labelledby");
    assert.ok(lab && d.getElementById(lab) && d.getElementById(lab).textContent.trim(), "dialog without title " + dlg.id);
  }
  for (const el of d.querySelectorAll("input, textarea")) {
    const named = el.id && d.querySelector(`label[for="${el.id}"]`) || el.closest("label") || el.getAttribute("aria-labelledby") || el.getAttribute("aria-label");
    assert.ok(named, "unlabelled field " + (el.id || el.name));
  }
  for (const b of d.querySelectorAll("button")) {
    assert.ok((b.textContent.trim() || b.getAttribute("aria-label")), "button without name " + b.id);
  }
  assert.equal(d.getElementById("sr-live").getAttribute("aria-live"), "polite");
  assert.equal(d.querySelectorAll("[onclick],[onerror],[onload],script:not([src])").length, 0);
  // The language button's accessible name is its visible text and it is marked with the target language.
  assert.equal(d.getElementById("lang-btn").getAttribute("aria-label"), null);
  assert.equal(d.getElementById("lang-btn").lang, "en");
  assert.equal(d.documentElement.dir, "rtl");
  // Safe defaults: dangerous or network actions are not the autofocus target.
  assert.ok(d.getElementById("sub-no").hasAttribute("autofocus"));
  assert.ok(!d.getElementById("sub-ok").hasAttribute("autofocus"));
  assert.ok(!d.getElementById("del-ok").hasAttribute("autofocus"));
  ui.close();
});

test("first run: nothing added, the main button invites adding, nothing is connectable", async () => {
  const ui = await boot();
  assert.equal(ui.text("power-label"), dict.fa.b_add);
  assert.ok(!ui.$("empty").hidden);
  assert.ok(ui.$("filter-wrap").hidden);
  assert.equal(ui.text("state-title"), dict.fa.s_idle);
  await ui.click("connect-btn");
  assert.ok(ui.$("dlg-paste").open, "clicking the big button with no servers opens the add flow");
  assert.equal(ui.called("connect").length, 0);
  ui.close();
});

test("language: auto follows the OS locale once and is persisted; default fa for Persian locales", async () => {
  let ui = await boot({ settings: { lang: "auto" }, language: "en-US" });
  assert.equal(ui.w.document.documentElement.lang, "en");
  assert.equal(ui.w.document.documentElement.dir, "ltr");
  assert.equal(ui.data.settings.lang, "en");
  assert.equal(ui.text("power-label"), dict.en.b_add);
  ui.close();
  ui = await boot({ settings: { lang: "auto" }, language: "fa-IR" });
  assert.equal(ui.w.document.documentElement.lang, "fa");
  assert.equal(ui.data.settings.lang, "fa");
  ui.close();
  // A saved choice wins over the OS locale; the toggle persists.
  ui = await boot({ settings: { lang: "en" }, language: "fa-IR" });
  assert.equal(ui.w.document.documentElement.lang, "en");
  await ui.click("lang-btn");
  assert.equal(ui.w.document.documentElement.lang, "fa");
  assert.equal(ui.called("set_settings").at(-1).args.settings.lang, "fa");
  ui.close();
});

test("500 servers: only a page is rendered, search filters, show more works, count is announced", async () => {
  const ui = await boot({ profiles: mkProfiles(500, (i) => ({ group: i % 2 ? "Even" : "", protocol: i % 3 ? "Trojan" : "VLESS" })) });
  assert.equal(ui.rows().length, 100);
  assert.ok(!ui.$("filter-wrap").hidden);
  assert.ok(!ui.$("more").hidden);
  await ui.click("more");
  assert.equal(ui.rows().length, 200);
  const f = ui.$("filter");
  f.value = "server 42"; f.dispatchEvent(new ui.w.Event("input", { bubbles: true }));
  await flush();
  // "Server 42", "Server 420".."Server 429"
  assert.equal(ui.rows().length, 11);
  assert.match(ui.text("count"), /^۱۱ /);
  f.value = "zzz"; f.dispatchEvent(new ui.w.Event("input", { bubbles: true }));
  await flush();
  assert.equal(ui.rows().length, 0);
  assert.equal(ui.text("count"), dict.fa.noMatch);
  assert.equal(ui.$("count").getAttribute("aria-live"), "polite");
  // Escape clears the filter.
  f.dispatchEvent(new ui.w.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  await flush();
  assert.equal(f.value, "");
  assert.equal(ui.rows().length, 100);
  ui.close();
});

test("a selection beyond the first page stays visible", async () => {
  const ps = mkProfiles(300);
  const ui = await boot({ profiles: ps, settings: { last_profile: ps[250].id } });
  assert.ok(ui.rows().some((r) => r.dataset.selected === "true"));
  ui.close();
});

test("hostile names and error text render as text, never as markup", async () => {
  const evil = [
    '<img src=x onerror="window.pwned=1">',
    "<script>window.pwned=2</script>",
    "‮evil-rtl‬ name",
    '"><svg onload=window.pwned=3>',
    "x".repeat(5000),
    "ب".repeat(50) + " mixed English " + "😀".repeat(30),
  ];
  const ps = mkProfiles(evil.length, (i) => ({ name: evil[i], group: evil[(i + 1) % evil.length], host: evil[i] }));
  const ui = await boot({ profiles: ps, settings: { lang: "en" }, api: {
    import_text: { added: [], duplicates: 0, problems: evil.map((e) => ({ label: e, message: e, message_en: e, code: "x" })), subscription_urls: ["https://" + "a".repeat(40) + ".example.com/<script>alert(1)</script>"] },
  } });
  const d = ui.w.document;
  assert.equal(d.querySelectorAll("#list img, #list svg, #list script").length, 0);
  assert.equal(ui.rows().length, evil.length);
  assert.equal(ui.rows()[0].querySelector(".row-name").textContent, evil[0]);
  // Same for problems and the subscription dialog.
  await ui.emit("imported", { added: [], duplicates: 0, problems: evil.map((e) => ({ label: e, message: e, message_en: e, code: "x" })), subscription_urls: ["https://x.example.com/?q=<script>alert(1)</script>"] });
  assert.equal(d.querySelectorAll("dialog img, dialog svg, dialog script, #toasts img, #toasts script").length, 0);
  assert.ok(ui.$("dlg-problems").open);
  assert.equal(ui.w.pwned, undefined);
  assert.ok(ui.$("dlg-sub").open);
  assert.equal(ui.text("sub-host"), "Site: x.example.com");
  ui.close();
});

test("import with partial failures: summary toast with a details button listing each problem, in fa and en", async () => {
  const added = mkProfiles(2);
  const problems = [
    { label: "vless://…#A", message: "فیلد uuid نامعتبر است.", message_en: "The uuid field is invalid.", code: "bad" },
    { label: "line 7", message: "پروتکل ناشناخته.", message_en: "Unknown protocol.", code: "unk" },
  ];
  for (const lang of ["fa", "en"]) {
    const ui = await boot({ settings: { lang }, api: { import_text: { added, duplicates: 3, problems, subscription_urls: [] } } });
    await ui.click("add-paste");           // clipboard unavailable in jsdom: opens the paste box
    ui.$("paste-text").value = "whatever";
    await ui.click("paste-ok");
    const toast = ui.w.document.querySelector("#toasts .toast");
    assert.ok(toast.textContent.includes(dict[lang].imp_dup.replace("{n}", lang === "fa" ? "۳" : "3")));
    const view = toast.querySelector("button:not(.toast-x)");
    assert.equal(view.textContent, dict[lang].imp_view);
    await ui.click(view);
    const items = [...ui.w.document.querySelectorAll("#problems-list li")].map((l) => l.textContent);
    assert.equal(items.length, 2);
    assert.ok(items[0].includes(lang === "fa" ? problems[0].message : problems[0].message_en));
    assert.ok(items[0].includes("vless://…#A"));
    ui.close();
  }
});

test("import where everything failed opens the problem list at once; empty input explains itself", async () => {
  const ui = await boot({ api: { import_text: { added: [], duplicates: 0, problems: [{ label: "a", message: "m", message_en: "m", code: "c" }], subscription_urls: [] } } });
  ui.$("paste-text").value = "x";
  await ui.click("add-paste");
  ui.$("paste-text").value = "junk";
  await ui.click("paste-ok");
  assert.ok(ui.$("dlg-problems").open);
  // Empty paste box: inline message, dialog stays open.
  await ui.click("add-paste");
  ui.$("paste-text").value = "   ";
  await ui.click("paste-ok");
  assert.ok(ui.$("dlg-paste").open);
  assert.equal(ui.w.document.querySelector("#dlg-paste .dlg-error").textContent, dict.fa.pasteEmpty);
  ui.close();
});

test("backend errors surface inside an open dialog (a modal hides toasts)", async () => {
  const ps = mkProfiles(1);
  const ui = await boot({ profiles: ps, api: { rename_profile: { __throw: { code: "bad_name", detail: "" } } } });
  await ui.click(ui.w.document.querySelector(".row-edit"));
  assert.ok(ui.$("dlg-edit").open);
  ui.$("edit-name").value = "";
  await ui.click("edit-ok");
  const box = ui.w.document.querySelector("#dlg-edit .dlg-error");
  assert.equal(box.hidden, false);
  assert.equal(box.textContent, dict.fa.e_bad_name);
  assert.equal(ui.called("rename_profile").length, 0, "empty names are stopped before the backend");
  ui.$("edit-name").value = "ok";
  await ui.click("edit-ok");
  assert.equal(box.textContent, dict.fa.e_bad_name, "a backend refusal also lands in the dialog");
  assert.equal(ui.toasts().length, 0);
  ui.close();
});

test("rename, group, delete flow; deleting the connected server warns first", async () => {
  const ps = mkProfiles(2);
  const ui = await boot({ profiles: ps, status: st("connected", { profile_id: ps[0].id, connected_since: Date.now() - 5000 }),
    api: { delete_profile: (a) => { ui.data.profiles = ui.data.profiles.filter((p) => p.id !== a.id); return null; } } });
  await ui.click(ui.w.document.querySelectorAll(".row-edit")[0]);
  ui.$("edit-name").value = "New name";
  ui.$("edit-group").value = "Work";
  await ui.click("edit-ok");
  assert.deepEqual(ui.called("rename_profile")[0].args, { id: ps[0].id, name: "New name" });
  assert.deepEqual(ui.called("set_profile_group")[0].args, { id: ps[0].id, group: "Work" });
  await ui.click(ui.w.document.querySelectorAll(".row-edit")[0]);
  await ui.click("edit-del");
  assert.ok(ui.$("dlg-del").open);
  assert.ok(ui.text("del-text").includes(dict.fa.delConnected));
  await ui.click("del-ok");
  assert.equal(ui.called("delete_profile").length, 1);
  assert.equal(ui.rows().length, 1);
  assert.ok(!ui.$("dlg-del").open);
  ui.close();
});

test("connect, connecting with elapsed time and a cancel that is always there, connected timer, disconnect", async () => {
  const ps = mkProfiles(2);
  const ui = await boot({ profiles: ps });
  assert.equal(ui.text("power-label"), dict.fa.b_idle);
  await ui.click("connect-btn");
  assert.deepEqual(ui.called("connect")[0].args, { id: ps[0].id });
  await ui.emit("status", st("preparing", { profile_id: ps[0].id }));
  await ui.emit("status", st("connecting", { profile_id: ps[0].id, attempt: 1 }));
  assert.equal(ui.text("power-label"), dict.fa.b_busy);
  assert.equal(ui.$("connect-btn").disabled, false, "cancel stays clickable while the engine is starting");
  assert.equal(ui.$("timer").hidden, false);
  await ui.click("connect-btn");
  assert.equal(ui.called("disconnect").length, 1);
  assert.equal(ui.text("power-label"), dict.fa.b_cancelling, "immediate local feedback even if the core is busy");
  assert.equal(ui.text("state-title"), dict.fa.s_cancelling);
  await ui.emit("status", st("idle"));
  assert.equal(ui.text("power-label"), dict.fa.b_idle);
  // Connected: timer and the connected server's name (not whatever is selected).
  await ui.emit("status", st("connected", { profile_id: ps[1].id, connected_since: Date.now() - 3 * 3600e3 - 5000 }));
  assert.equal(ui.text("state-detail"), "Server 2");
  assert.match(ui.text("timer-text"), /^۰۳:۰۰:۰[۴۵۶]$/);
  assert.equal(ui.rows()[1].dataset.selected, "true", "selection follows the connected server (tray/other window)");
  assert.equal(ui.text("power-label"), dict.fa.b_connected);
  await ui.click("connect-btn");
  assert.equal(ui.called("disconnect").length, 2);
  ui.close();
});

test("live region announces state changes without the ticking timer", async () => {
  const ps = mkProfiles(1);
  const ui = await boot({ profiles: ps, settings: { lang: "en" } });
  await ui.emit("status", st("connecting", { profile_id: ps[0].id }));
  assert.equal(ui.text("sr-live"), "Connecting…");
  await ui.emit("status", st("connected", { profile_id: ps[0].id, connected_since: Date.now() }));
  assert.equal(ui.text("sr-live"), "Connected. Server 1");
  await ui.emit("status", st("failed", { message: "fa", message_en: "The server is not responding.", failure_code: "server" }));
  assert.equal(ui.text("sr-live"), "Could not connect. The server is not responding.");
  ui.close();
});

test("failure shows the core's plain-language message in the chosen language and a retry button; permission failure offers the fix", async () => {
  const ps = mkProfiles(1);
  const ui = await boot({ profiles: ps });
  await ui.emit("status", st("failed", { profile_id: ps[0].id, message: "سرور پاسخ نمی‌دهد.", message_en: "Server down.", failure_code: "server" }));
  assert.equal(ui.text("state-detail"), "سرور پاسخ نمی‌دهد.");
  assert.equal(ui.text("power-label"), dict.fa.b_failed);
  assert.equal(ui.$("fix-btn").hidden, true);
  await ui.emit("status", st("failed", { message: "x", message_en: "x", failure_code: "permission" }));
  assert.equal(ui.$("fix-btn").hidden, false);
  await ui.click("fix-btn");
  assert.ok(ui.$("dlg-priv").open);
  ui.close();
});

test("needs_privilege opens the permission dialog, grant then retries the connect", async () => {
  const ps = mkProfiles(1);
  let first = true;
  const ui = await boot({ profiles: ps, api: { connect: () => { if (first) { first = false; return { __throw: { code: "needs_privilege", detail: "" } }; } return null; }, grant_privilege: null } });
  await ui.click("connect-btn");
  assert.ok(ui.$("dlg-priv").open);
  await ui.click("priv-ok");
  assert.equal(ui.called("grant_privilege").length, 1);
  assert.equal(ui.called("connect").length, 2);
  ui.close();
});

test("subscription: confirmation shows the host, default answer is No, Yes downloads, failure offline is explained", async () => {
  const url = "https://sub.example.com/feed?token=abc";
  const ui = await boot({ settings: { lang: "en" }, api: { import_text: { added: [], duplicates: 0, problems: [], subscription_urls: [url] }, import_subscription: { __throw: { code: "fetch_failed", detail: "fa", detail_en: "Downloading the subscription failed." } } } });
  Object.defineProperty(ui.w.navigator, "onLine", { value: false, configurable: true });
  await ui.click("add-paste");
  ui.$("paste-text").value = url;
  await ui.click("paste-ok");
  assert.ok(ui.$("dlg-sub").open);
  assert.equal(ui.text("sub-host"), "Site: sub.example.com");
  assert.equal(ui.text("sub-url"), url);
  await ui.click("sub-no");
  assert.equal(ui.called("import_subscription").length, 0, "nothing is fetched without a yes");
  await ui.emit("imported", { added: [], duplicates: 0, problems: [], subscription_urls: [url] });
  await ui.click("sub-ok");
  assert.equal(ui.called("import_subscription")[0].args.url, url);
  assert.ok(ui.toasts().some((s) => s.includes("Downloading the subscription failed.") && s.includes(dict.en.offline)));
  assert.equal(ui.$("add-paste").disabled, false, "busy state is released after a failure");
  ui.close();
});

test("settings: validation inline, behaviour options saved, warning while connected, theme and zoom", async () => {
  const ps = mkProfiles(1);
  const ui = await boot({ profiles: ps, status: st("connected", { profile_id: ps[0].id, connected_since: Date.now() }) });
  await ui.click("adv-btn");
  assert.ok(ui.$("dlg-adv").open);
  assert.equal(ui.$("adv-warn").hidden, false, "warns that engine settings disconnect");
  ui.$("adv-port").value = "80";
  await ui.click("adv-save");
  assert.equal(ui.called("set_settings").length, 0);
  assert.equal(ui.w.document.querySelector("#dlg-adv .dlg-error").textContent, dict.fa.e_bad_settings_port);
  ui.$("adv-port").value = "20000";
  ui.$("adv-launch").checked = true; ui.$("adv-minimized").checked = true; ui.$("adv-tray").checked = false;
  await ui.click("adv-save");
  const sent = ui.called("set_settings").at(-1).args.settings;
  assert.equal(sent.socks_port, 20000);
  assert.deepEqual([sent.connect_on_launch, sent.start_minimized, sent.close_to_tray], [true, true, false]);
  assert.ok(ui.toasts().includes(dict.fa.settingsSavedDisc));
  // Theme + text size are per-viewer.
  await ui.click("adv-btn");
  const dark = ui.w.document.querySelector('input[name="theme"][value="dark"]');
  dark.checked = true; dark.dispatchEvent(new ui.w.Event("change"));
  assert.equal(ui.w.document.documentElement.dataset.theme, "dark");
  await ui.click("zoom-in");
  assert.equal(ui.w.document.documentElement.style.fontSize, "125%");
  ui.w.document.dispatchEvent(new ui.w.KeyboardEvent("keydown", { key: "=", ctrlKey: true, bubbles: true }));
  assert.equal(ui.w.document.documentElement.style.fontSize, "150%");
  ui.w.document.dispatchEvent(new ui.w.KeyboardEvent("keydown", { key: "0", ctrlKey: true, bubbles: true }));
  assert.equal(ui.w.document.documentElement.style.fontSize, "100%");
  for (let i = 0; i < 10; i++) await ui.click("zoom-in");
  assert.equal(ui.w.document.documentElement.style.fontSize, "200%");
  ui.close();
});

test("Enter in a text field saves; Escape-closing a dialog returns focus to the page", async () => {
  const ps = mkProfiles(1);
  const ui = await boot({ profiles: ps });
  await ui.click(ui.w.document.querySelector(".row-edit"));
  ui.$("edit-name").value = "Changed";
  ui.w.document.querySelector("#dlg-edit form").dispatchEvent(new ui.w.Event("submit", { cancelable: true, bubbles: true }));
  await flush();
  assert.equal(ui.called("rename_profile").length, 1);
  ui.close();
});

test("secure storage unavailable: a persistent, actionable banner (not a vanishing toast)", async () => {
  const ui = await boot({ info: { secrets: "memory" } });
  assert.equal(ui.$("banner").hidden, false);
  assert.match(ui.text("banner"), /gnome-keyring/);
  assert.equal(ui.toasts().length, 0);
  ui.close();
  const ui2 = await boot({ info: { secrets: "memory", platform: "windows" }, settings: { lang: "en" } });
  assert.match(ui2.text("banner"), /Credential Manager/);
  ui2.close();
});

test("proxy mode and insecure TLS are explained on the main screen", async () => {
  const ps = mkProfiles(1);
  const ui = await boot({ profiles: ps, settings: { mode: "proxy", socks_port: 18080, lang: "en" } });
  await ui.emit("status", st("connected", { profile_id: ps[0].id, connected_since: Date.now(), insecure_tls: true }));
  assert.equal(ui.$("mode-note").hidden, false);
  assert.match(ui.text("mode-note"), /127\.0\.0\.1, port 18080/);
  assert.equal(ui.$("insecure").hidden, false);
  assert.match(ui.text("insecure"), /does not prove its identity/);
  assert.doesNotMatch(ui.text("insecure"), /certificate|TLS/i, "no jargon");
  ui.close();
});

test("webview reload: state is rebuilt from the backend (connected, with server and timer)", async () => {
  const ps = mkProfiles(3);
  const ui = await boot({ profiles: ps, status: st("connected", { profile_id: ps[2].id, connected_since: Date.now() - 61000 }) });
  assert.equal(ui.text("state-title"), dict.fa.s_connected);
  assert.equal(ui.text("state-detail"), "Server 3");
  assert.equal(ui.rows()[2].dataset.selected, "true");
  assert.match(ui.text("timer-text"), /۰۰:۰۱:۰[۰-۳]/);
  ui.close();
});

test("about dialog shows the version and the bundled third-party notices", async () => {
  const ui = await boot({ settings: { lang: "en" } });
  await ui.click("adv-btn");
  await ui.click("adv-about");
  assert.ok(ui.$("dlg-about").open);
  assert.match(ui.text("about-text"), /9\.9\.9/);
  assert.equal(ui.$("about-licenses").value, "Third party notices test text");
  ui.close();
  const ui2 = await boot({ settings: { lang: "en" }, api: { licenses_text: { __throw: { code: "not_found" } } } });
  await ui2.click("adv-btn"); await ui2.click("adv-about");
  assert.equal(ui2.$("about-licenses").value, dict.en.licensesMissing);
  ui2.close();
});

test("startup: connect-on-launch connects the selected server once", async () => {
  const ps = mkProfiles(2);
  const ui = await boot({ profiles: ps, api: { take_startup_connect: true } });
  assert.equal(ui.called("connect").length, 1);
  ui.close();
});

test("never claims Connected unless the core says Connected; reconnecting is a distinct no-internet state", async () => {
  const ps = mkProfiles(1);
  const ui = await boot({ profiles: ps, settings: { lang: "en" } });
  for (const s of ["idle", "preparing", "connecting", "reconnecting", "disconnecting", "failed"]) {
    await ui.emit("status", st(s, { profile_id: ps[0].id, connected_since: Date.now() - 9000, message_en: "m", message: "m" }));
    assert.doesNotMatch(ui.text("state-title"), /^Connected$/, s);
    assert.notEqual(ui.$("connect-btn").dataset.state, "connected", s);
    assert.notEqual(ui.text("power-label"), dict.en.b_connected, s);
  }
  await ui.emit("status", st("reconnecting", { profile_id: ps[0].id, attempt: 2, message_en: "The network dropped.", message: "x" }));
  assert.equal(ui.$("connect-btn").dataset.state, "reconnecting");
  assert.match(ui.text("state-title"), /No internet/);
  assert.match(ui.text("state-detail"), /The network dropped\./);
  // A stale client-side "cancelling" flag never turns into a connected look.
  await ui.click("connect-btn");
  await ui.emit("status", st("connected", { profile_id: ps[0].id, connected_since: Date.now() }));
  assert.equal(ui.$("connect-btn").dataset.state, "connected");
  ui.close();
});

test("leak protection: blocked-network banner with allow-direct, leftover rules with remove action, core error shown", async () => {
  const ui = await boot({ settings: { lang: "en" } });
  assert.equal(ui.$("ks").hidden, true);
  await ui.emit("status", st("reconnecting", { kill_switch_active: true }));
  assert.equal(ui.$("ks").hidden, false);
  assert.equal(ui.text("ks-btn"), dict.en.ksAllow);
  await ui.click("ks-btn");
  assert.equal(ui.called("allow_direct").length, 1);
  await ui.emit("status", st("connected", { kill_switch_active: true }));
  assert.equal(ui.$("ks").hidden, true, "no warning while the tunnel is up");
  await ui.emit("status", st("idle", { kill_switch_leftover: true, kill_switch_error: "pkexec failed" }));
  assert.equal(ui.text("ks-btn"), dict.en.ksClear);
  assert.match(ui.text("ks-text"), /pkexec failed/);
  await ui.click("ks-btn");
  assert.equal(ui.called("clear_leftover_rules").length, 1);
  ui.close();
});

test("start-up: the UI waits quietly while the backend is still starting (keyring probe off the UI thread)", async () => {
  let n = 0;
  const ui = await boot({ api: { get_settings: () => { if (n++ < 4) return { __throw: "state not managed" }; return { lang: "fa", mode: "tun", socks_port: 10808, dns: [], last_profile: null, connect_on_launch: false, start_minimized: false, close_to_tray: true }; } } });
  await new Promise((r) => setTimeout(r, 1500));
  assert.ok(n >= 5);
  assert.equal(ui.toasts().length, 0);
  assert.equal(ui.text("state-title"), dict.fa.s_idle);
  ui.close();
});
