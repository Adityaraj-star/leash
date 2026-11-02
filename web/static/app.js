(function () {
  "use strict";

  // ---------------------------------------------------------------- helpers
  var $ = function (id) { return document.getElementById(id); };

  // Everything the agent or a merchant wrote reaches the page as text, never as
  // markup: this builder only ever sets textContent.
  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === false || v == null) return;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    });
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c == null || c === false) continue;
      el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return el;
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

  function money(a) {
    if (!a) return "";
    var f = new Intl.NumberFormat("en-US", { style: "currency", currency: a.currency || "USD" });
    var d = f.resolvedOptions().maximumFractionDigits;
    return f.format(a.minor / Math.pow(10, d));
  }
  function moneyStr(amount, currency) { // "60.00" + "USD"
    var n = Number(amount);
    return isFinite(n) ? new Intl.NumberFormat("en-US", { style: "currency", currency: currency || "USD" }).format(n) : amount;
  }
  function when(iso) {
    var d = new Date(iso);
    if (isNaN(d)) return "";
    return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
  }
  function clock(iso) {
    var d = new Date(iso);
    return isNaN(d) ? "" : d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit", second: "2-digit" });
  }
  function pretty(s) {
    return String(s || "").toLowerCase().replace(/_/g, " ").replace(/^./, function (c) { return c.toUpperCase(); });
  }
  function toast(msg, bad) {
    var t = $("toast");
    t.textContent = msg;
    t.dataset.bad = bad ? "true" : "false";
    t.classList.add("show");
    clearTimeout(toast.t);
    toast.t = setTimeout(function () { t.classList.remove("show"); }, 4200);
  }

  // state -> visual kind
  var KIND = {
    PAID_OUT: "allow", CAPTURED: "allow", DELIVERED: "allow", AUTHORIZED: "allow", APPROVED: "info", EVALUATED: "info", REQUESTED: "info",
    STEP_UP_PENDING: "hold", DENIED: "deny", EXPIRED: "hold", VOIDED: "hold", REFUNDED: "hold", DISPUTED: "deny",
    CAPTURE_PENDING: "hold", PAYOUT_PENDING: "hold"
  };
  var STATE_TEXT = {
    STEP_UP_PENDING: "Waiting for you", AUTHORIZED: "Held in escrow", PAID_OUT: "Paid out", DENIED: "Blocked",
    CAPTURED: "Captured", DELIVERED: "Delivered", VOIDED: "Released", APPROVED: "Approved",
    CAPTURE_PENDING: "Capture pending", PAYOUT_PENDING: "Payout pending"
  };

  // The buyer-approval link comes from PayPal. Only ever link to a paypal.com
  // address over https, whatever the server says.
  function safePayPalUrl(u) {
    try {
      var x = new URL(u);
      return x.protocol === "https:" && (x.hostname === "paypal.com" || /\.paypal\.com$/.test(x.hostname)) ? x.href : "";
    } catch (e) { return ""; }
  }
  function badge(state) {
    return h("span", { class: "badge " + (KIND[state] || "info"), text: STATE_TEXT[state] || pretty(state) });
  }

  // ---------------------------------------------------------------- api
  var TOKEN_KEY = "leash.token";
  var token = "";
  try { token = sessionStorage.getItem(TOKEN_KEY) || ""; } catch (e) { /* storage may be blocked */ }

  function api(path, opts) {
    opts = opts || {};
    var headers = { "Authorization": "Bearer " + token };
    if (opts.body) headers["Content-Type"] = "application/json";
    return fetch(path, { method: opts.method || "GET", headers: headers, body: opts.body, signal: opts.signal }).then(function (r) {
      if (r.status === 401) { askLogin(); throw new Error("Sign in to continue."); }
      return r.text().then(function (txt) {
        var data = null;
        try { data = txt ? JSON.parse(txt) : null; } catch (e) { /* not json */ }
        if (!r.ok) throw new Error((data && data.error) || ("Request failed (" + r.status + ")."));
        return data;
      });
    });
  }

  // ---------------------------------------------------------------- state
  var requests = [];
  var tape = []; // ledger entries, ascending by seq
  var seen = {};
  var gridApi = null;

  function askLogin() {
    var d = $("login");
    if (!d.open) { try { d.showModal(); } catch (e) { d.setAttribute("open", ""); } }
    $("token").focus();
  }

  $("login-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var v = $("token").value.trim();
    if (!v) return;
    token = v;
    fetch("/api/state", { headers: { Authorization: "Bearer " + token } }).then(function (r) {
      if (r.status === 401) { $("login-error").textContent = "That token was not accepted. Check it and try again."; return; }
      try { sessionStorage.setItem(TOKEN_KEY, token); } catch (e) { /* ignore */ }
      $("login-error").textContent = "";
      $("token").value = "";
      $("login").close();
      start();
    }).catch(function () { $("login-error").textContent = "Could not reach the Leash server."; });
  });

  $("signout").addEventListener("click", function () {
    try { sessionStorage.removeItem(TOKEN_KEY); } catch (e) { /* ignore */ }
    location.reload();
  });

  // ---------------------------------------------------------------- signing key
  var S = window.LeashSign;
  var server = { strict: false, key_id: "" }; // the last /api/state
  var signer = null; // { pair, publicB64, keyId } when THIS browser holds the key

  function loadSigner() {
    if (!S || !S.supported()) return Promise.resolve(null);
    return S.load().then(function (k) { signer = k; return k; }).catch(function () { signer = null; return null; });
  }
  function code(t) { return h("code", { text: t }); }
  function canSign() { return !!(signer && server.key_id && signer.keyId === server.key_id); }

  function enrollSigner() {
    return api("/api/enroll", { method: "POST", body: JSON.stringify({ public_key: signer.publicB64 }) }).then(function () {
      toast("Leash now trusts your signing key.");
      return refresh();
    });
  }
  function createKey() {
    S.create().then(function (k) { signer = k; return enrollSigner(); }).catch(function (e) { toast(e.message, true); renderKeyPanel(); });
  }
  function renderKeyPanel() {
    var box = $("key-panel");
    clear(box);
    var text, action = null;
    if (!S || !S.supported()) {
      text = [h("b", { text: "Signing is not available here. " }), "Your browser needs a secure page (https, or http://localhost) to hold a signing key."];
    } else if (!signer && !server.key_id) {
      text = [h("b", { text: "No signing key yet. " }), "Create one in this browser. Leash will trust only mandates and approvals signed with it. The key stays in the browser and cannot be exported."];
      action = h("button", { class: "btn primary", type: "button", text: "Create my signing key", onclick: createKey });
    } else if (!signer) {
      text = [h("b", { text: "This browser does not hold the key Leash trusts. " }), "Leash trusts key ", code(server.key_id), ". Open the dashboard in the browser that created it to sign mandates and approvals."];
    } else if (!server.key_id) {
      text = [h("b", { text: "This browser has a key Leash does not trust yet. " }), "Key ", code(signer.keyId), "."];
      action = h("button", { class: "btn primary", type: "button", text: "Trust this key", onclick: function () { enrollSigner().catch(function (e) { toast(e.message, true); }); } });
    } else if (signer.keyId !== server.key_id) {
      text = [h("b", { text: "Key mismatch. " }), "This browser holds ", code(signer.keyId), " but Leash trusts ", code(server.key_id), ". Use the browser that created the trusted key."];
    } else {
      text = [h("b", { text: "Ready. " }), "Mandates", server.strict ? " and approvals" : "", " are signed with key ", code(server.key_id), ", held in this browser."];
    }
    box.appendChild(h.apply(null, ["div", { class: "k-text" }].concat(text)));
    if (action) box.appendChild(action);
    $("new-mandate").disabled = !canSign();
    $("new-mandate").title = canSign() ? "" : "Create or use your signing key first";
  }

  // ---- new mandate
  function openMandate() {
    if (!canSign()) { toast("Set up your signing key first.", true); return; }
    var sel = $("m-cur");
    if (!sel.options.length) (S.CURRENCIES || ["USD"]).forEach(function (c) { sel.appendChild(h("option", { value: c, text: c })); });
    $("m-error").textContent = "";
    var d = $("mandate-dlg");
    try { d.showModal(); } catch (e) { d.setAttribute("open", ""); }
    $("m-intent").focus();
  }
  $("new-mandate").addEventListener("click", openMandate);
  $("m-cancel").addEventListener("click", function () { $("mandate-dlg").close(); });
  $("mandate-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    if (!canSign()) { $("m-error").textContent = "This browser does not hold the key Leash trusts."; return; }
    var built = S.buildMandate({
      intent: $("m-intent").value, maxTotal: $("m-max").value, currency: $("m-cur").value, perTx: $("m-per").value,
      stepUp: $("m-step").value, merchants: $("m-merchants").value, categories: $("m-cats").value,
      expiresInHours: $("m-exp").value, deliverBy: $("m-deliver").value, returnPolicy: $("m-return").checked, singleUse: $("m-single").checked
    }, Date.now());
    if (!built.ok) { $("m-error").textContent = built.error; return; }
    var btn = $("m-sign");
    btn.disabled = true;
    $("m-error").textContent = "";
    S.signText(signer.pair.privateKey, built.text).then(function (sig) {
      return api("/api/mandates", { method: "POST", body: JSON.stringify({ mandate: built.text, signature: sig }) });
    }).then(function () {
      $("mandate-dlg").close();
      $("mandate-form").reset();
      toast("Mandate " + built.id + " signed and registered.");
      return refresh();
    }).catch(function (e) { $("m-error").textContent = e.message; }).then(function () { btn.disabled = false; });
  });

  // ---------------------------------------------------------------- needs you
  function renderNeeds() {
    var box = $("needs-list");
    clear(box);
    var ask = requests.filter(function (r) { return r.state === "STEP_UP_PENDING"; });
    var buyer = requests.filter(function (r) { return r.buyer_approval_url && (r.state === "APPROVED"); });
    if (!ask.length && !buyer.length) {
      box.appendChild(h("div", { class: "needs-empty", text: "Nothing is waiting for you. When a payment needs your approval, it shows up here." }));
      return;
    }
    ask.forEach(function (r) {
      var approve = h("button", { class: "btn primary", type: "button", text: "Approve " + money(r.amount) });
      var decline = h("button", { class: "btn", type: "button", text: "Decline" });
      approve.addEventListener("click", function () { decide(r, "approve", [approve, decline]); });
      decline.addEventListener("click", function () { decide(r, "reject", [approve, decline]); });
      box.appendChild(h("div", { class: "ask" },
        h("div", { class: "amt", text: money(r.amount) }),
        h("div", { class: "what", text: (r.items || []).join(", ") + " from " + r.merchant_id }),
        h("div", { class: "acts" }, approve, decline),
        h("div", { class: "why", text: r.reason + " Approving places a hold; you are charged only when the merchant confirms delivery." })
      ));
    });
    buyer.forEach(function (r) {
      box.appendChild(h("div", { class: "ask" },
        h("div", { class: "amt", text: money(r.amount) }),
        h("div", { class: "what", text: (r.items || []).join(", ") + " from " + r.merchant_id }),
        h("div", { class: "acts" }, safePayPalUrl(r.buyer_approval_url)
          ? h("a", { class: "btn primary", href: safePayPalUrl(r.buyer_approval_url), target: "_blank", rel: "noopener noreferrer", text: "Approve in PayPal" })
          : h("span", { class: "muted", text: "The approval link was not a PayPal address, so it is hidden." })),
        h("div", { class: "why", text: "PayPal needs you to approve this payment once before the hold is placed." })
      ));
    });
  }

  // On a strict server an approval is only valid with your signature over the
  // exact text the server shows (request, merchant, amount). The browser checks
  // that text names this request and merchant before it signs anything.
  function approveSigned(r) {
    if (!canSign()) return Promise.reject(new Error("This browser does not hold your signing key, so it cannot approve."));
    return api("/api/requests/" + encodeURIComponent(r.id) + "/approval").then(function (am) {
      var lines = String(am.message || "").split("\n");
      if (lines.length < 4 || lines[0] !== "leash.approve.v1" || lines[1] !== r.id || lines[2] !== r.merchant_id) {
        throw new Error("The approval text does not match this request, so nothing was signed.");
      }
      return confirmDialog("Sign and approve " + money(r.amount) + "?",
        "You are signing: " + lines[3] + " to " + lines[2] + ". Approving places a hold; you are charged only when the merchant confirms delivery.",
        "Sign and approve").then(function (ok) {
        if (!ok) return null;
        return S.signText(signer.pair.privateKey, am.message).then(function (sig) {
          return api("/api/requests/" + encodeURIComponent(r.id) + "/approve", { method: "POST", body: JSON.stringify({ signature: sig }) });
        });
      });
    });
  }

  function decide(r, action, buttons) {
    buttons.forEach(function (b) { b.disabled = true; });
    var call = (action === "approve" && server.strict)
      ? approveSigned(r)
      : api("/api/requests/" + encodeURIComponent(r.id) + "/" + action, { method: "POST" });
    call.then(function (out) {
      if (!out) { buttons.forEach(function (b) { b.disabled = false; }); return null; } // you chose not to sign
      toast(action === "approve" ? (out.state === "AUTHORIZED" ? "Approved. Funds are held in escrow." : "Approved: " + (STATE_TEXT[out.state] || pretty(out.state)) + ".") : "Declined. Nothing was charged.");
      return refresh();
    }).catch(function (e) {
      toast(e.message, true);
      buttons.forEach(function (b) { b.disabled = false; });
    });
  }

  // ---------------------------------------------------------------- mandates
  function renderMandates(list) {
    var box = $("mandates");
    clear(box);
    if (!list.length) {
      box.appendChild(h("div", { class: "needs-empty", text: "No mandates yet. A mandate is the spending limit you sign for your agent; without one, Leash refuses every payment." }));
      return;
    }
    list.forEach(function (m) {
      var max = Number(m.max_total) || 0;
      var spent = Number(m.spent) || 0;
      var pct = max > 0 ? Math.min(100, (spent / max) * 100) : 0;
      var used = h("div", { class: "used" });
      used.style.width = pct + "%";
      var bar = h("div", { class: "leash", role: "img", "aria-label": moneyStr(m.spent, m.currency) + " of " + moneyStr(m.max_total, m.currency) + " used" }, used);
      if (m.step_up_over && max > 0) {
        var tick = h("div", { class: "tick", title: "You approve anything over " + moneyStr(m.step_up_over, m.currency) });
        tick.style.left = Math.min(100, (Number(m.step_up_over) / max) * 100) + "%";
        bar.appendChild(tick);
      }
      var revoke = h("button", { class: "btn small danger", type: "button", text: "Revoke" });
      revoke.addEventListener("click", function () {
        confirmDialog("Revoke " + m.id + "?", "Leash will refuse every payment under this mandate, cancel anything waiting for your approval and release unused holds. This cannot be undone.", "Revoke mandate").then(function (ok) {
          if (!ok) return;
          api("/api/mandates/" + encodeURIComponent(m.id) + "/revoke", { method: "POST" }).then(function (out) {
            var n = (out.holds_released || []).length;
            toast("Mandate revoked." + (n ? " " + n + (n === 1 ? " hold" : " holds") + " released." : ""));
            return refresh();
          }).catch(function (e) { toast(e.message, true); });
        });
      });
      box.appendChild(h("div", { class: "mandate", "data-revoked": m.revoked ? "true" : "false" },
        h("div", { class: "m-head" },
          h("div", null, h("span", { class: "m-id", text: m.id }), " ", m.revoked ? h("span", { class: "badge deny", text: "Revoked" }) : h("span", { class: "badge allow", text: "Active" })),
          m.revoked ? null : revoke),
        h("div", { class: "m-intent", text: m.intent }),
        bar,
        h("div", { class: "leash-legend" },
          h("span", null, h("b", { text: moneyStr(m.spent, m.currency) }), " used of ", h("b", { text: moneyStr(m.max_total, m.currency) })),
          m.step_up_over ? h("span", { text: "You approve over " + moneyStr(m.step_up_over, m.currency) }) : null),
        h("div", { class: "m-meta" },
          h("span", { text: "Merchants: " + (m.allowed_merchants || []).join(", ") }),
          h("span", { text: "Per purchase up to " + moneyStr(m.per_tx_cap, m.currency) }),
          m.deliver_by ? h("span", { text: "Delivery by " + new Date(m.deliver_by).toLocaleDateString() }) : null,
          h("span", { text: "Expires " + when(m.expires_at) }),
          m.single_use ? h("span", { text: "Single use" }) : null)
      ));
    });
  }

  function confirmDialog(title, text, okLabel) {
    return new Promise(function (resolve) {
      var d = $("confirm");
      $("confirm-title").textContent = title;
      $("confirm-text").textContent = text;
      $("confirm-ok").textContent = okLabel;
      d.addEventListener("close", function once() {
        d.removeEventListener("close", once);
        resolve(d.returnValue === "ok");
      });
      try { d.showModal(); } catch (e) { d.setAttribute("open", ""); }
    });
  }

  // ---------------------------------------------------------------- grid
  function gridTheme() {
    return agGrid.themeQuartz.withParams({
      backgroundColor: "var(--surface)", foregroundColor: "var(--ink)", borderColor: "var(--line)",
      headerBackgroundColor: "var(--sunk)", headerTextColor: "var(--ink)", headerFontWeight: 700,
      rowHoverColor: "var(--sunk)", accentColor: "var(--strap)", fontFamily: "Schibsted Grotesk, system-ui, sans-serif",
      fontSize: 14, wrapperBorderRadius: 6, borderRadius: 4
    });
  }

  function initGrid() {
    var cols = [
      { headerName: "When", field: "created_at", width: 175, valueFormatter: function (p) { return when(p.value); }, sort: "desc" },
      { headerName: "Merchant", field: "merchant_id", width: 130 },
      { headerName: "Items", field: "items", flex: 1, minWidth: 130, valueFormatter: function (p) { return (p.value || []).join(", "); } },
      { headerName: "Amount", field: "amount", width: 110, type: "rightAligned", comparator: function (a, b) { return a.minor - b.minor; }, valueFormatter: function (p) { return money(p.value); } },
      { headerName: "Status", field: "state", width: 160, cellRenderer: function (p) { return badge(p.value); } },
      { headerName: "Why", field: "reason", flex: 2, minWidth: 220, tooltipField: "reason" }
    ];
    gridApi = agGrid.createGrid($("grid"), {
      theme: gridTheme(),
      columnDefs: cols,
      rowData: [],
      getRowId: function (p) { return p.data.id; },
      defaultColDef: { sortable: true, resizable: true, filter: true },
      overlayNoRowsTemplate: "<span>No payment requests yet. When the agent asks to pay, it shows up here.</span>",
      onRowClicked: function (e) { openDrawer(e.data); },
      suppressCellFocus: false,
      animateRows: false
    });
  }

  // ---------------------------------------------------------------- drawer
  var lastFocus = null;
  function openDrawer(r) {
    lastFocus = document.activeElement;
    var b = $("drawer-body");
    clear(b);
    b.appendChild(badge(r.state));
    b.appendChild(h("div", { class: "d-amt", text: money(r.amount) }));
    b.appendChild(h("div", { class: "d-sub", text: (r.items || []).join(", ") + " from " + r.merchant_id + " on " + r.mandate_id }));
    b.appendChild(h("p", { text: r.reason }));

    var d = r.decision || {};
    var sec = h("div", { class: "d-sec" }, h("h3", { text: "What the rules said" }));
    (d.findings || []).forEach(function (f) {
      sec.appendChild(h("div", { class: "finding", "data-r": f.result }, h("span", { class: "rule", text: f.rule }), h("span", { text: f.reason })));
    });
    if (!(d.findings || []).length && d.result) sec.appendChild(h("p", { class: "passed", text: "Allowed. Every check passed." }));
    if ((d.passed || []).length) sec.appendChild(h("p", { class: "passed", text: "Passed: " + d.passed.join(", ") }));
    b.appendChild(sec);

    if (r.judge) b.appendChild(h("div", { class: "d-sec" }, h("h3", { text: "AI judge" }), h("p", { text: r.judge })));

    var readSec = h("div", { class: "d-sec" }, h("h3", { text: "What the agent read" }), h("p", { class: "passed", text: "Loading..." }));
    b.appendChild(readSec);
    loadRead(r).then(function (pages) {
      clear(readSec);
      readSec.appendChild(h("h3", { text: "What the agent read" }));
      if (!pages.length) { readSec.appendChild(h("p", { class: "passed", text: "No pages were cited for this request." })); return; }
      pages.forEach(function (pg) { readSec.appendChild(renderRead(pg)); });
    }).catch(function () {
      clear(readSec);
      readSec.appendChild(h("h3", { text: "What the agent read" }));
      readSec.appendChild(h("p", { class: "passed", text: "Could not load the pages for this request." }));
    });

    var hist = h("ol", { class: "hist" });
    (r.history || []).forEach(function (t) {
      hist.appendChild(h("li", null, h("time", { text: clock(t.at) }), h("span", null, h("b", { text: pretty(t.to) }), " " + (t.reason || ""))));
    });
    b.appendChild(h("div", { class: "d-sec" }, h("h3", { text: "What happened" }), hist));

    var kv = h("dl", { class: "kv" });
    [["Request", r.id], ["Order", r.order_id], ["Authorization", r.authorization_id], ["Capture", r.capture_id], ["Payout", r.payout_batch_id], ["Paid to", r.merchant_email]].forEach(function (p) {
      if (p[1]) { kv.appendChild(h("dt", { text: p[0] })); kv.appendChild(h("dd", { text: p[1] })); }
    });
    b.appendChild(h("div", { class: "d-sec" }, h("h3", { text: "References" }), kv));

    $("drawer").hidden = false;
    $("drawer").querySelector(".drawer-panel").focus();
  }
  // The pages a request cited are listed in its provenance entry in the ledger.
  function evidenceIds(r) {
    for (var i = tape.length - 1; i >= 0; i--) {
      if (tape[i].type !== "provenance.checked") continue;
      var p = {};
      try { p = JSON.parse(tape[i].payload); } catch (e) { continue; }
      if (p.request_id === r.id) return p.evidence_refs || [];
    }
    return [];
  }
  function loadRead(r) {
    return Promise.all(evidenceIds(r).map(function (id) {
      return api("/api/evidence/" + encodeURIComponent(id)).catch(function () { return { id: id, gone: true }; });
    }));
  }
  var SEVERITY = [["allow", "No instructions found"], ["hold", "Low risk"], ["hold", "Possible instructions"], ["deny", "Planted instructions"]];
  // Page text with the hidden snippets marked. Everything is set as text nodes.
  function markedText(text, snippets) {
    var pre = h("pre"), lower = text.toLowerCase(), ranges = [];
    snippets.forEach(function (sn) {
      sn = String(sn || "").trim();
      if (!sn || sn.length > 400) return;
      var at = lower.indexOf(sn.toLowerCase());
      if (at >= 0) ranges.push([at, at + sn.length]);
    });
    ranges.sort(function (a, b) { return a[0] - b[0]; });
    var pos = 0;
    ranges.forEach(function (rg) {
      if (rg[0] < pos) return;
      pre.appendChild(document.createTextNode(text.slice(pos, rg[0])));
      pre.appendChild(h("mark", { text: text.slice(rg[0], rg[1]) }));
      pos = rg[1];
    });
    pre.appendChild(document.createTextNode(text.slice(pos)));
    return pre;
  }
  function renderRead(ev) {
    if (ev.gone) return h("div", { class: "read" }, h("div", { class: "r-url", text: ev.id }), h("p", { class: "passed", text: "This page is no longer in memory (the server restarted or it was cleared)." }));
    var sev = SEVERITY[Math.max(0, Math.min(3, ev.severity || 0))];
    var box = h("div", { class: "read" },
      h("div", { class: "r-url", text: ev.url }),
      h("span", { class: "badge " + sev[0], text: sev[1] }));
    if ((ev.hidden || []).length) {
      var hid = h("div", { class: "r-hidden" }, h("b", { text: "Hidden text a person would not see, but the agent was shown:" }));
      ev.hidden.forEach(function (t) { hid.appendChild(h("div", { text: t })); });
      box.appendChild(hid);
    }
    (ev.notes || []).forEach(function (n) { box.appendChild(h("p", { class: "passed", text: n })); });
    var text = String(ev.text || ""), more = text.length > 1500;
    box.appendChild(markedText(more ? text.slice(0, 1500) : text, ev.hidden || []));
    if (more) box.appendChild(h("p", { class: "passed", text: "Shortened: the page has " + text.length + " characters." }));
    return box;
  }

  function closeDrawer() {
    $("drawer").hidden = true;
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }
  $("drawer-close").addEventListener("click", closeDrawer);
  $("drawer-scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape" && !$("drawer").hidden) closeDrawer(); });

  // ---------------------------------------------------------------- tape
  function describe(e) {
    var p = {};
    try { p = JSON.parse(e.payload); } catch (x) { /* keep empty */ }
    var kind = "info", text;
    switch (e.type) {
      case "user.enrolled": text = "Your signing key was pinned. Only mandates signed with it count."; break;
      case "mandate.registered": text = "Mandate " + p.mandate_id + " signed and registered."; break;
      case "mandate.revoked": text = "Mandate " + p.mandate_id + " revoked."; kind = "deny"; break;
      case "browse":
        text = "Agent read " + String(p.url || "").replace(/^https?:\/\//, "") + (p.hidden_text ? ". Hidden text was found on the page." : ".");
        kind = p.severity >= 2 ? "deny" : "info"; break;
      case "settlement.requested": text = "Agent asked to pay " + moneyStr(p.amount, p.currency) + " to " + p.merchant_id + "."; break;
      case "provenance.checked":
        text = p.injection >= 2 ? "Provenance: the agent had read instructions planted in a page." :
          (p.quote_verified ? "Provenance: price and merchant match the merchant's own quote." : "Provenance: " + ((p.notes || [])[0] || "facts could not be traced to a trusted source") + ".");
        kind = p.injection >= 2 ? "deny" : (p.quote_verified ? "allow" : "hold"); break;
      case "taint.raised":
        text = "Planted instructions were read at " + String(p.url || "").replace(/^https?:\/\//, "") + ". Every payment needs your approval until " + clock(p.until) + ".";
        kind = "deny"; break;
      case "settlement.unknown":
        text = "PayPal did not answer in time. Leash is checking and will finish or release the payment on its own."; kind = "hold"; break;
      case "user.message": text = "You told the agent what to do."; break;
      case "judge.reviewed": text = "AI judge reviewed the request: " + (p.verdict || "done") + "."; break;
      case "request.rejected": text = "Request refused before it started: " + (p.reason || "invalid") ; kind = "deny"; break;
      case "request.replayed": text = "Same request sent again. Returned the first answer; nothing new was charged."; break;
      case "settlement.intent":
        text = ({ order: "PayPal call logged: create the order.", authorize: "PayPal call logged: place the hold.", capture: "PayPal call logged: capture the funds.", payout: "PayPal call logged: pay the merchant.", void: "PayPal call logged: release the hold.", refund: "PayPal call logged: refund." })[p.op] || ("PayPal call logged: " + p.op + ".");
        break;
      case "settlement.transition":
        text = (p.reason || (pretty(p.from) + " to " + pretty(p.to)));
        kind = KIND[p.to] || "info";
        if (p.decision && p.decision.result) {
          text = "Rules checked: " + ({ ALLOW: "all passed.", STEP_UP: "this one needs your approval.", DENY: "blocked.", REPLAY: "already answered." })[p.decision.result] || text;
          kind = ({ ALLOW: "allow", STEP_UP: "hold", DENY: "deny" })[p.decision.result] || kind;
        }
        break;
      default: text = e.type;
    }
    return { text: text, kind: kind };
  }

  function tapeItem(e, fresh) {
    var d = describe(e);
    var li = h("li", { class: "tape-item" + (fresh ? " fresh" : ""), "data-kind": d.kind, "data-seq": String(e.seq) },
      h("div", { class: "t-text", text: d.text }),
      h("div", { class: "t-meta" }, h("span", { text: "#" + e.seq }), h("span", { text: clock(e.ts) }), h("span", { class: "t-hash", title: e.hash, text: String(e.hash || "").slice(0, 10) })));
    return li;
  }

  function addTape(entries, fresh) {
    var list = $("tape-list");
    entries.forEach(function (e) {
      if (seen[e.seq]) return;
      seen[e.seq] = true;
      tape.push(e);
      list.insertBefore(tapeItem(e, fresh), list.firstChild); // newest on top
    });
  }

  $("verify").addEventListener("click", function () {
    var btn = $("verify");
    btn.disabled = true;
    var note = $("verify-note");
    api("/api/ledger/verify").then(function (out) {
      var res = out.result, items = Array.prototype.slice.call($("tape-list").children).reverse(); // oldest first
      items.forEach(function (li) { li.classList.remove("checked", "broken"); });
      var delay = Math.min(26, 900 / Math.max(items.length, 1));
      var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      var i = 0;
      (function step() {
        var batch = reduce ? items.length : 1;
        for (var k = 0; k < batch && i < items.length; k++, i++) {
          var li = items[i], seq = Number(li.dataset.seq);
          if (!res.ok && res.broken_at && seq >= res.broken_at) { li.classList.add("broken"); } else { li.classList.add("checked"); }
        }
        if (i < items.length) { setTimeout(step, delay); return; }
        btn.disabled = false;
        if (res.ok) {
          note.textContent = "All " + res.entries + " entries link up and carry the server's signature. Latest checkpoint: #" + out.checkpoint.seq + ".";
          setChain(res);
        } else {
          note.textContent = "Entry #" + res.broken_at + " does not match the one before it. " + (res.reason || "The record was changed after it was written.");
          setChain(res);
        }
      })();
    }).catch(function (e) { btn.disabled = false; toast(e.message, true); });
  });

  function setChain(res) {
    var p = $("chain");
    p.dataset.ok = res.ok ? "true" : "false";
    p.dataset.bad = res.ok ? "false" : "true";
    p.textContent = res.ok ? "Chain intact, " + res.entries + " entries" : "Chain broken at #" + res.broken_at;
  }

  // ---------------------------------------------------------------- refresh + live
  var pending = null;
  function refresh() {
    return Promise.all([api("/api/state"), api("/api/requests")]).then(function (r) {
      var st = r[0];
      server = st;
      requests = r[1] || [];
      $("keyid").textContent = st.key_id ? "key " + st.key_id : "no key enrolled";
      var tb = $("taint");
      if (st.tainted_until) { tb.hidden = false; tb.textContent = "A page with planted instructions was read recently. Every payment needs your approval until " + clock(st.tainted_until) + "."; } else { tb.hidden = true; }
      renderKeyPanel();
      setChain(st.chain);
      renderMandates(st.mandates || []);
      renderNeeds();
      if (gridApi) {
        gridApi.setGridOption("rowData", requests);
        $("grid").style.height = Math.min(560, 56 + 42 * Math.max(requests.length, 3)) + "px";
      }
      document.title = (st.step_ups ? "(" + st.step_ups + ") " : "") + "Leash";
    });
  }
  function scheduleRefresh() {
    if (pending) return;
    pending = setTimeout(function () { pending = null; refresh().catch(function () { /* shown by api() */ }); }, 250);
  }

  var abort = null;
  function live() {
    if (abort) abort.abort();
    abort = new AbortController();
    var liveEl = $("live");
    fetch("/api/events", { headers: { Authorization: "Bearer " + token }, signal: abort.signal }).then(function (r) {
      if (r.status === 401) { askLogin(); return; }
      if (!r.ok || !r.body) throw new Error("stream");
      liveEl.dataset.on = "true"; liveEl.textContent = "Live";
      var reader = r.body.getReader(), dec = new TextDecoder(), buf = "";
      return (function pump() {
        return reader.read().then(function (x) {
          if (x.done) throw new Error("closed");
          buf += dec.decode(x.value, { stream: true });
          var parts = buf.split("\n\n");
          buf = parts.pop();
          parts.forEach(function (blk) {
            var m = /^data: (.*)$/m.exec(blk);
            if (!m) return;
            try { addTape([JSON.parse(m[1])], true); scheduleRefresh(); } catch (e) { /* ignore a bad frame */ }
          });
          return pump();
        });
      })();
    }).catch(function (e) {
      if (e && e.name === "AbortError") return;
      liveEl.dataset.on = "false"; liveEl.textContent = "Reconnecting";
      setTimeout(live_retry, 2000);
    });
  }
  function live_retry() { api("/api/ledger?after=" + (tape.length ? tape[tape.length - 1].seq : 0)).then(function (es) { addTape(es, false); return refresh(); }).then(live).catch(function () { setTimeout(live_retry, 3000); }); }

  function start() {
    if (!gridApi) initGrid();
    loadSigner().then(refresh).then(function () { return api("/api/ledger?limit=1000"); }).then(function (es) { addTape(es, false); live(); }).catch(function () { /* login prompt or error toast already shown */ });
  }

  if (token) start(); else askLogin();
})();
