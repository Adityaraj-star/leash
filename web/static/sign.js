/* Leash signing.
 *
 * The user's signing key is a P-256 key pair made by this browser and kept in
 * IndexedDB as a NON-EXTRACTABLE CryptoKey: the page can ask the browser to sign
 * with it, but nothing (not this script, not an injected one) can read the
 * private key out. Leash pins the public key once; after that only mandates and
 * step-up approvals signed by this key count.
 *
 * WebCrypto returns ECDSA signatures as a raw 64-byte r||s value and public keys
 * as a 65-byte uncompressed point. Those are exactly what the Go side verifies
 * (internal/mandate), so nothing is converted.
 *
 * Needs a secure context (https, or http://localhost).
 */
(function (root) {
  "use strict";

  var subtle = root.crypto && root.crypto.subtle;
  var enc = new TextEncoder();
  var DB = "leash-signing", STORE = "keys", ID = "user";
  var ALG = { name: "ECDSA", namedCurve: "P-256" };
  var SIGN = { name: "ECDSA", hash: "SHA-256" };
  var CURRENCIES = ["USD", "EUR", "GBP", "CAD", "AUD"]; // all have two decimals

  function b64(buf) {
    var bytes = new Uint8Array(buf), s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return root.btoa(s);
  }
  function hex(bytes) {
    return Array.prototype.map.call(bytes, function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  }
  function randomHex(n) {
    var a = new Uint8Array(n);
    root.crypto.getRandomValues(a);
    return hex(a);
  }

  // ------------------------------------------------------------ key pair
  function supported() { return !!(subtle && root.indexedDB); }

  function generate() {
    // extractable=false: the private key can sign but can never be exported.
    return subtle.generateKey(ALG, false, ["sign", "verify"]);
  }
  // Base64 of the 65-byte uncompressed public point (what /api/enroll takes).
  function publicRaw(pair) {
    return subtle.exportKey("raw", pair.publicKey).then(b64);
  }
  // The same short id the server shows: first 8 bytes of SHA-256 of the point, hex.
  function keyId(rawB64) {
    var bin = root.atob(rawB64), bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return subtle.digest("SHA-256", bytes).then(function (d) { return hex(new Uint8Array(d).slice(0, 8)); });
  }
  // Base64 of the raw r||s signature over the UTF-8 bytes of text.
  function signText(privateKey, text) {
    return subtle.sign(SIGN, privateKey, enc.encode(text)).then(b64);
  }

  // ------------------------------------------------------------ storage
  function open() {
    return new Promise(function (resolve, reject) {
      var req = root.indexedDB.open(DB, 1);
      req.onupgradeneeded = function () { req.result.createObjectStore(STORE); };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }
  function tx(mode, fn) {
    return open().then(function (db) {
      return new Promise(function (resolve, reject) {
        var t = db.transaction(STORE, mode), req = fn(t.objectStore(STORE));
        t.oncomplete = function () { db.close(); resolve(req.result); };
        t.onerror = t.onabort = function () { db.close(); reject(t.error); };
      });
    });
  }
  // Resolves to { pair, publicB64, keyId } or null when this browser has no key.
  function load() {
    if (!supported()) return Promise.resolve(null);
    return tx("readonly", function (s) { return s.get(ID); }).then(function (pair) {
      if (!pair || !pair.privateKey) return null;
      return publicRaw(pair).then(function (pub) {
        return keyId(pub).then(function (id) { return { pair: pair, publicB64: pub, keyId: id }; });
      });
    });
  }
  function create() {
    return generate().then(function (pair) {
      return tx("readwrite", function (s) { return s.put(pair, ID); }).then(function () { return load(); });
    });
  }
  function forget() { return tx("readwrite", function (s) { return s.delete(ID); }); }

  // ------------------------------------------------------------ mandates
  var AMOUNT = /^\d{1,9}(\.\d{1,2})?$/;
  var ID_RE = /^[A-Za-z0-9._:-]{1,64}$/;

  function cents(s) { // "40", "40.5" -> 4000, 4050
    var p = String(s).split(".");
    return Number(p[0]) * 100 + Number(((p[1] || "") + "00").slice(0, 2));
  }
  function money(s) { var c = cents(s); return Math.floor(c / 100) + "." + ("0" + (c % 100)).slice(-2); }
  function list(v) {
    return (Array.isArray(v) ? v : String(v || "").split(","))
      .map(function (x) { return String(x).trim(); }).filter(Boolean);
  }

  // buildMandate turns the form fields into the exact text that gets signed, or
  // says what is wrong. The text is signed and sent byte for byte; the server
  // checks the signature over exactly these bytes and then parses them strictly.
  //   f: { intent, maxTotal, perTx, stepUp, currency, merchants, categories,
  //        returnPolicy, deliverBy ("YYYY-MM-DD" or ""), expiresInHours, singleUse }
  function buildMandate(f, nowMs) {
    var err = function (m) { return { ok: false, error: m }; };
    var intent = String(f.intent || "").trim();
    if (!intent) return err("Say what the agent may buy (this is shown with the mandate).");
    if (intent.length > 300) return err("Keep the description under 300 characters.");
    var currency = f.currency || "USD";
    if (CURRENCIES.indexOf(currency) < 0) return err("Pick a currency from the list.");
    if (!AMOUNT.test(String(f.maxTotal || ""))) return err("The total limit must be an amount like 40 or 40.00.");
    var max = money(f.maxTotal);
    if (cents(max) <= 0) return err("The total limit must be more than zero.");
    var perTx = String(f.perTx || "").trim() ? String(f.perTx).trim() : max;
    if (!AMOUNT.test(perTx)) return err("The per-purchase limit must be an amount like 25 or 25.00.");
    perTx = money(perTx);
    if (cents(perTx) <= 0 || cents(perTx) > cents(max)) return err("The per-purchase limit must be more than zero and not above the total limit.");
    var stepUp = String(f.stepUp || "").trim();
    if (stepUp) {
      if (!AMOUNT.test(stepUp)) return err("The approval line must be an amount like 20 or 20.00.");
      stepUp = money(stepUp);
      if (cents(stepUp) > cents(perTx)) return err("You can only ask to approve purchases up to the per-purchase limit.");
    }
    var merchants = list(f.merchants), categories = list(f.categories);
    if (!merchants.length) return err("Name at least one merchant the agent may pay.");
    if (merchants.concat(categories).some(function (x) { return x.length > 64; })) return err("Merchant and category names are limited to 64 characters.");
    var hours = Number(f.expiresInHours);
    if (!isFinite(hours) || hours < 1 || hours > 24 * 90) return err("Choose how long the mandate lasts (1 hour to 90 days).");
    var now = nowMs == null ? Date.now() : nowMs;
    var deliverBy = String(f.deliverBy || "").trim();
    if (deliverBy) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(deliverBy) || isNaN(Date.parse(deliverBy + "T00:00:00Z"))) return err("Use a delivery date like 2026-11-02.");
      if (Date.parse(deliverBy + "T23:59:59Z") < now) return err("The delivery date is in the past.");
    }
    var id = "m_" + randomHex(4);
    var m = {
      mandate_id: id,
      intent: intent,
      max_total: { amount: max, currency: currency },
      per_tx_cap: perTx,
      allowed_merchants: merchants,
      categories: categories,
      requires_return_policy: !!f.returnPolicy
    };
    if (deliverBy) m.deliver_by = deliverBy;
    m.single_use = !!f.singleUse;
    if (stepUp) m.step_up_over = stepUp;
    m.expires_at = new Date(now + hours * 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
    m.nonce = randomHex(8);
    if (!ID_RE.test(id)) return err("Could not make a mandate id.");
    return { ok: true, id: id, text: JSON.stringify(m), mandate: m };
  }

  var api = {
    supported: supported, generate: generate, publicRaw: publicRaw, keyId: keyId, signText: signText,
    load: load, create: create, forget: forget, buildMandate: buildMandate, CURRENCIES: CURRENCIES
  };
  root.LeashSign = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof self !== "undefined" ? self : globalThis);
