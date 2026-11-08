/* Shared helpers of the Laocoon pages (inlined into each page by console.render).
   Access: operators sign in on NAV.login (a session cookie); NAV.user is who is signed in ("" = nobody, "token" =
   opened with the console token, absent = an open console: no token and no accounts configured). The console
   token in ?token= still works and is passed on between pages.
   Language: English by default, Greek as an option (header switch, remembered per browser, or ?lang=el).
   Static text: elements carry data-i18n="key" (textContent), data-i18n-ph (placeholder), data-i18n-aria
   (aria-label); the English text is also written in the HTML so the page reads right before the script runs. */
window.Lcn = (function () {
  const NAV = JSON.parse((document.getElementById("nav-data") || {}).textContent || "{}");
  const LANGS = {en: "EN", el: "ΕΛ"};
  const DICT = {
    en: {"nav.label": "Pages", "nav.home": "Home", "nav.console": "Console", "nav.policies": "Policies", "nav.settings": "Mitigations",
         "lang": "Language", "err.token": "Your session has ended. Sign in again.", "err.http": "Request failed (HTTP {status}).",
         "err.forbidden": "The server refused the request (HTTP 403).", "acct": "Account",
         "who.signin": "Sign in", "who.signout": "Sign out", "who.as": "Signed in as", "who.token": "the console token"},
    el: {"nav.label": "Σελίδες", "nav.home": "Αρχική", "nav.console": "Κονσόλα", "nav.policies": "Πολιτικές", "nav.settings": "Μέτρα προστασίας",
         "lang": "Γλώσσα", "err.token": "Η σύνδεσή σας έληξε. Συνδεθείτε ξανά.", "err.http": "Το αίτημα απέτυχε (HTTP {status}).",
         "err.forbidden": "Ο διακομιστής αρνήθηκε το αίτημα (HTTP 403).", "acct": "Λογαριασμός",
         "who.signin": "Σύνδεση", "who.signout": "Αποσύνδεση", "who.as": "Συνδεδεμένος ως", "who.token": "το token της κονσόλας"},
  };
  const hooks = [];
  const qs = new URLSearchParams(location.search);
  const store = (k, v) => { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { /* blocked */ } return null; };

  let lang = qs.get("lang");
  if (LANGS[lang]) store("lcn-lang", lang); else lang = store("lcn-lang");
  if (!LANGS[lang]) lang = "en";

  // The console token: from ?token=… (the existing links), remembered for this tab so the nav keeps it.
  let token = qs.get("token") || "";
  try {
    if (token) sessionStorage.setItem("lcn-token", token);
    else token = sessionStorage.getItem("lcn-token") || "";
  } catch (e) { /* storage blocked: the URL token still works */ }

  const brandEl = document.querySelector(".brand span");
  const brand = brandEl ? brandEl.textContent : "Laocoon";

  function t(key, vars) {
    let s = (DICT[lang] || {})[key];
    if (s == null) s = DICT.en[key];
    if (s == null) return key;
    vars = Object.assign({brand}, vars || {});
    return s.replace(/\{(\w+)\}/g, (m, k) => (vars[k] != null ? String(vars[k]) : m));
  }

  function apply(root) {
    root = root || document;
    root.querySelectorAll("[data-i18n]").forEach(e => { e.textContent = t(e.dataset.i18n); });
    root.querySelectorAll("[data-i18n-ph]").forEach(e => { e.placeholder = t(e.dataset.i18nPh); });
    root.querySelectorAll("[data-i18n-aria]").forEach(e => { e.setAttribute("aria-label", t(e.dataset.i18nAria)); });
    document.documentElement.lang = lang;
  }

  function withToken(url) {
    if (!token || !url) return url;
    const u = new URL(url, location.href);
    u.searchParams.set("token", token);
    return u.pathname + u.search + u.hash;
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }

  async function api(base, path, opts) {
    opts = Object.assign({}, opts || {});
    opts.headers = Object.assign({"Content-Type": "application/json"}, token ? {"X-Laocoon-Token": token} : {},
                                 opts.headers || {});
    const r = await fetch(base + path, opts);
    let data = null;
    try { data = await r.json(); } catch (e) { /* not JSON */ }
    if (r.status === 401 && NAV.login && !opts.noRedirect) { toLogin(); }
    if (!r.ok && !(opts.allow || []).includes(r.status)) {
      const err = new Error(r.status === 401 ? t("err.token") : r.status === 403 ? t("err.forbidden") : t("err.http", {status: r.status}));
      err.status = r.status; err.data = data;
      throw err;
    }
    return data;
  }

  // The sign-in page, coming back here afterwards (without a stale ?token= in the address).
  function toLogin() {
    const here = new URL(location.href);
    here.searchParams.delete("token");
    location.href = NAV.login + "?next=" + encodeURIComponent(here.pathname + here.search + here.hash);
  }
  async function signOut() {
    try { await fetch(NAV.logout, {method: "POST", headers: {"Content-Type": "application/json"}, body: "{}"}); } catch (e) { /* offline */ }
    try { sessionStorage.removeItem("lcn-token"); } catch (e) { /* blocked */ }
    location.href = NAV.login + "?next=" + encodeURIComponent(location.pathname);
  }

  function langSwitch() {
    const sw = el("div", "langswitch");
    sw.setAttribute("role", "group");
    sw.dataset.i18nAria = "lang";
    Object.entries(LANGS).forEach(([code, label]) => {
      const b = el("button", "", label);
      b.type = "button";
      b.lang = code;
      b.setAttribute("aria-pressed", String(code === lang));
      b.onclick = () => setLang(code);
      sw.appendChild(b);
    });
    return sw;
  }

  // One account menu instead of a row of buttons: who is signed in, the language, sign out. Signed out: a single
  // "Sign in" button and the language. An open console (no accounts) shows only the language.
  function account(slot) {
    if (NAV.user === undefined || !NAV.login) { slot.appendChild(langSwitch()); return; }
    if (!NAV.user) {
      const a = el("a", "band-link", t("who.signin")); a.dataset.i18n = "who.signin";
      a.href = NAV.login + "?next=" + encodeURIComponent(NAV.console || "/");
      slot.appendChild(langSwitch());
      slot.appendChild(a);
      return;
    }
    const name = NAV.user === "token" ? t("who.token") : NAV.user;
    const box = el("div", "acct");
    const btn = el("button", "acct-btn"); btn.type = "button";
    btn.setAttribute("aria-haspopup", "true"); btn.setAttribute("aria-expanded", "false");
    btn.setAttribute("aria-label", t("acct")); btn.dataset.i18nAria = "acct";
    const av = el("span", "avatar", NAV.user === "token" ? "#" : NAV.user.slice(0, 1).toUpperCase()); av.setAttribute("aria-hidden", "true");
    btn.append(av, el("span", "lbl", name), el("span", "caret", "▾"));
    const menu = el("div", "acct-menu"); menu.hidden = true;
    const who = el("div", "who"); const pre = el("span", "", t("who.as")); pre.dataset.i18n = "who.as";
    who.append(pre, el("b", "", name));
    const row = el("div", "row"); const ll = el("span", "", t("lang")); ll.dataset.i18n = "lang";
    row.append(ll, langSwitch());
    const out = el("button", "item", t("who.signout")); out.type = "button"; out.dataset.i18n = "who.signout"; out.onclick = signOut;
    menu.append(who, row, out);
    const close = () => { menu.hidden = true; btn.setAttribute("aria-expanded", "false"); };
    btn.onclick = e => { e.stopPropagation(); menu.hidden = !menu.hidden; btn.setAttribute("aria-expanded", String(!menu.hidden)); };
    menu.onclick = e => e.stopPropagation();
    document.addEventListener("click", close);
    document.addEventListener("keydown", e => { if (e.key === "Escape") { close(); btn.focus(); } });
    box.append(btn, menu);
    slot.appendChild(box);
  }

  // Header: the mark (home), the pages, the account. Pages without a link in NAV are simply
  // absent.
  function header(current) {
    const box = document.getElementById("nav");
    const brandLink = document.getElementById("brand-link");
    if (brandLink) brandLink.href = NAV.home ? NAV.home : "#";
    if (box) {
      [["console", "nav.console"], ["policies", "nav.policies"], ["settings", "nav.settings"]].forEach(([key, label]) => {
        if (!NAV[key]) return;
        const a = el("a", "", t(label));
        a.dataset.i18n = label;
        a.href = withToken(NAV[key]);
        if (key === current) a.setAttribute("aria-current", "page");
        box.appendChild(a);
      });
    }
    const slot = document.getElementById("topbar-slot");
    if (slot) account(slot);
  }

  function setLang(code) {
    if (!LANGS[code] || code === lang) return;
    lang = code;
    store("lcn-lang", code);
    document.querySelectorAll(".langswitch button").forEach(b => b.setAttribute("aria-pressed", String(b.lang === code)));
    apply();
    hooks.forEach(fn => fn());
  }

  // One call per page: its strings ({en: {...}, el: {...}}), the header, then the translated static text.
  // `onLang` re-renders the parts the page builds itself.
  function init(opts) {
    Object.keys(LANGS).forEach(code => Object.assign(DICT[code], (opts.dict || {})[code] || {}));
    header(opts.page);
    if (opts.onLang) hooks.push(opts.onLang);
    apply();
  }

  let toastTimer = null;
  function toast(msg, kind) {
    let box = document.querySelector(".toast");
    if (!box) { box = el("div", "toast"); box.setAttribute("role", "status"); document.body.appendChild(box); }
    box.className = "toast" + (kind ? " " + kind : "");
    box.textContent = msg;
    box.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { box.hidden = true; }, kind === "bad" ? 6000 : 3000);
  }

  return {NAV, brand, get lang() { return lang; }, get token() { return token; }, t, apply, init, withToken, el, api, toast,
          toLogin, signOut};
})();
