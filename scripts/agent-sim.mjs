#!/usr/bin/env node
// A stand-in for an AI agent (and for a merchant), for testing a running Leash
// server without a model. It speaks to Leash exactly like a real agent: MCP over
// HTTP with the agent token. Node 18+, no dependencies.
//
//   LEASH_URL           default http://127.0.0.1:8787
//   LEASH_AGENT_TOKEN   the agent token (for the agent commands)
//   SHOP_URL            the shop's base address (the fake demo prints it at start-up)
//   MERCHANT_ID         default legitgifts      MERCHANT_SECRET   (for `deliver`)
//
//   node scripts/agent-sim.mjs mandates
//   node scripts/agent-sim.mjs browse /legit/card
//   node scripts/agent-sim.mjs buy --mandate m_birthday --page /legit/card --quote q-card --items "Greeting card" --amount 12.00
//   node scripts/agent-sim.mjs attack --mandate m_birthday        # a poisoned page tries to steer the agent
//   node scripts/agent-sim.mjs status req_...
//   node scripts/agent-sim.mjs deliver req_... [--fail]           # the MERCHANT confirms delivery
const BASE = (process.env.LEASH_URL || "http://127.0.0.1:8787").replace(/\/$/, "");
const TOKEN = process.env.LEASH_AGENT_TOKEN || "";
const SHOP = (process.env.SHOP_URL || "").replace(/\/$/, "");
const MERCHANT = process.env.MERCHANT_ID || "legitgifts";

const [cmd, ...rest] = process.argv.slice(2);
const flags = {}, pos = [];
for (let i = 0; i < rest.length; i++) {
  if (rest[i].startsWith("--")) { const k = rest[i].slice(2); flags[k] = rest[i + 1] && !rest[i + 1].startsWith("--") ? rest[++i] : true; } else pos.push(rest[i]);
}
const die = (m) => { console.error("error: " + m); process.exit(1); };
const show = (label, v) => console.log(label.padEnd(8), typeof v === "string" ? v : JSON.stringify(v, null, 2));

let sid = null, rpcId = 0;
async function rpc(method, params) {
  if (!TOKEN) die("set LEASH_AGENT_TOKEN to the agent token");
  const res = await fetch(BASE + "/mcp", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + TOKEN, ...(sid ? { "Mcp-Session-Id": sid } : {}) },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params }),
  });
  if (res.status === 401) die("the server refused the agent token");
  sid = res.headers.get("mcp-session-id") || sid;
  return res.json();
}
async function tool(name, args) {
  if (!sid) await rpc("initialize", { protocolVersion: "2025-06-18" });
  const out = (await rpc("tools/call", { name, arguments: args })).result;
  if (!out) die("no result from " + name);
  const text = out.content[0].text;
  let parsed = text; try { parsed = JSON.parse(text); } catch {}
  return { isError: !!out.isError, value: parsed };
}
const page = (p) => (p.startsWith("http") ? p : (SHOP || die("set SHOP_URL (the demo prints it at start-up)")) + p);

async function summary(label, r) {
  const v = r.value;
  if (typeof v === "string") return show(r.isError ? "ERROR" : label, v);
  show(label, `${v.state || ""}  ${v.reason || ""}`.trim());
  (v.findings || []).forEach((f) => show("  " + f.rule, `${f.result}: ${f.reason}`));
  if (v.request_id) show("request", v.request_id);
  if (v.next_step) show("next", v.next_step);
}

async function buy(opts) {
  if (!opts.mandate) die("--mandate is required");
  const ev = await tool("leash_browse", { url: page(opts.page) });
  if (ev.isError) return summary("browse", ev);
  show("read", `${opts.page} (labeled ${ev.value.trust}, evidence ${ev.value.evidence_id})`);
  const args = {
    mandate_id: opts.mandate, merchant_id: opts.merchant || MERCHANT, items: [opts.items || "Item"], amount: opts.amount,
    evidence_refs: [ev.value.evidence_id],
  };
  if (opts.quote) args.quote_id = opts.quote;
  if (opts.key) args.idempotency_key = opts.key;
  const r = await tool("leash_request_payment", args);
  await summary("Leash", r);
  return r;
}

switch (cmd) {
  case "mandates": show("mandates", (await tool("leash_list_mandates", {})).value); break;
  case "browse": { const r = await tool("leash_browse", { url: page(pos[0] || die("give a page, e.g. /legit/card")) }); show("page", r.value); break; }
  case "buy": await buy({ ...flags }); break;
  case "attack": {
    if (!flags.mandate) die("--mandate is required");
    const ev = await tool("leash_browse", { url: page("/shady/deal") });
    show("read", "/shady/deal (a page with a hidden instruction)");
    await summary("Leash", await tool("leash_request_payment", {
      mandate_id: flags.mandate, merchant_id: "shadyshop", items: ["Premium bundle"], amount: "39.99", evidence_refs: [ev.value.evidence_id], idempotency_key: flags.key || "attack-" + Date.now(),
    }));
    break;
  }
  case "status": await summary("status", await tool("leash_status", { request_id: pos[0] || die("give a request id") })); break;
  case "deliver": {
    const secret = process.env.MERCHANT_SECRET || die("set MERCHANT_SECRET to the merchant's delivery secret");
    const res = await fetch(BASE + "/merchant/delivery", {
      method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + secret },
      body: JSON.stringify({ merchant_id: MERCHANT, request_id: pos[0] || die("give a request id"), delivered: !flags.fail, reference: "SIM-1" }),
    });
    show("HTTP", String(res.status));
    show("merchant", await res.json());
    break;
  }
  default:
    console.log("commands: mandates | browse <page> | buy --mandate ID --page P --quote Q --items I --amount A | attack --mandate ID | status <id> | deliver <id> [--fail]");
}
