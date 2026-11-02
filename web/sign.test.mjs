// Unit tests for the signing script. Run with: node --test web/
import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const S = createRequire(import.meta.url)("./static/sign.js");

const now = Date.UTC(2026, 9, 26, 12, 0, 0);
const good = {
  intent: "Birthday gift for my sister, under $40", maxTotal: "40", perTx: "", stepUp: "25", currency: "USD",
  merchants: "legitgifts, otherpal", categories: "gifts", returnPolicy: true, deliverBy: "", expiresInHours: 72, singleUse: true,
};
const bad = (patch, re) => {
  const r = S.buildMandate({ ...good, ...patch }, now);
  assert.equal(r.ok, false, "expected an error for " + JSON.stringify(patch));
  assert.match(r.error, re);
};

test("a valid form builds the exact text Leash parses", () => {
  const r = S.buildMandate(good, now);
  assert.equal(r.ok, true, r.error);
  const m = JSON.parse(r.text);
  assert.deepEqual(Object.keys(m), ["mandate_id", "intent", "max_total", "per_tx_cap", "allowed_merchants", "categories",
    "requires_return_policy", "single_use", "step_up_over", "expires_at", "nonce"]);
  assert.match(m.mandate_id, /^m_[0-9a-f]{8}$/);
  assert.deepEqual(m.max_total, { amount: "40.00", currency: "USD" });
  assert.equal(m.per_tx_cap, "40.00"); // blank means the total
  assert.deepEqual(m.allowed_merchants, ["legitgifts", "otherpal"]);
  assert.equal(m.step_up_over, "25.00");
  assert.equal(m.expires_at, "2026-10-29T12:00:00Z"); // 72 hours, no milliseconds
  assert.match(m.nonce, /^[0-9a-f]{16}$/);
  assert.equal(m.single_use, true);
  assert.equal("deliver_by" in m, false);
});

test("optional fields are left out when blank", () => {
  const r = S.buildMandate({ ...good, stepUp: "", categories: "", deliverBy: "2026-11-02" }, now);
  const m = JSON.parse(r.text);
  assert.equal("step_up_over" in m, false);
  assert.deepEqual(m.categories, []);
  assert.equal(m.deliver_by, "2026-11-02");
});

test("amounts are normalised to two decimals", () => {
  const m = JSON.parse(S.buildMandate({ ...good, maxTotal: "40.5", perTx: "12", stepUp: "5.1" }, now).text);
  assert.equal(m.max_total.amount, "40.50");
  assert.equal(m.per_tx_cap, "12.00");
  assert.equal(m.step_up_over, "5.10");
});

test("every ordinary mistake is explained and nothing is built", () => {
  bad({ intent: "  " }, /what the agent may buy/i);
  bad({ intent: "x".repeat(301) }, /300/);
  bad({ maxTotal: "" }, /total limit/i);
  bad({ maxTotal: "40.999" }, /total limit/i);
  bad({ maxTotal: "-5" }, /total limit/i);
  bad({ maxTotal: "0" }, /more than zero/i);
  bad({ perTx: "90" }, /not above the total/i);
  bad({ stepUp: "50" }, /up to the per-purchase limit/i);
  bad({ stepUp: "abc" }, /approval line/i);
  bad({ merchants: " , " }, /at least one merchant/i);
  bad({ merchants: "x".repeat(65) }, /64 characters/);
  bad({ expiresInHours: 0 }, /how long/i);
  bad({ expiresInHours: 24 * 91 }, /how long/i);
  bad({ expiresInHours: "soon" }, /how long/i);
  bad({ deliverBy: "next week" }, /delivery date/i);
  bad({ deliverBy: "2026-10-01" }, /in the past/i);
  bad({ currency: "XXX" }, /currency/i);
});

test("each mandate gets a fresh id and nonce", () => {
  const a = JSON.parse(S.buildMandate(good, now).text), b = JSON.parse(S.buildMandate(good, now).text);
  assert.notEqual(a.mandate_id, b.mandate_id);
  assert.notEqual(a.nonce, b.nonce);
});

test("keys are 65-byte points, signatures 64 raw bytes, and the private key cannot be exported", async () => {
  const pair = await S.generate();
  const pub = await S.publicRaw(pair);
  assert.equal(Buffer.from(pub, "base64").length, 65);
  assert.match(await S.keyId(pub), /^[0-9a-f]{16}$/);
  const sig = await S.signText(pair.privateKey, "leash.approve.v1\nreq_1\nlegitgifts\n32.00 USD");
  assert.equal(Buffer.from(sig, "base64").length, 64);
  await assert.rejects(() => crypto.subtle.exportKey("pkcs8", pair.privateKey), "the private key must not be extractable");
  await assert.rejects(() => crypto.subtle.exportKey("jwk", pair.privateKey));
});

test("a signature verifies for the signed text only", async () => {
  const pair = await S.generate();
  const text = "some mandate text";
  const sig = Buffer.from(await S.signText(pair.privateKey, text), "base64");
  const verify = (t) => crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pair.publicKey, sig, new TextEncoder().encode(t));
  assert.equal(await verify(text), true);
  assert.equal(await verify(text + " "), false);
});
