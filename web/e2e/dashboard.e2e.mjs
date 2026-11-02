// End-to-end check of the dashboard.
// Builds the Leash binary, starts it in fake mode, and tests the real
// dashboard in jsdom.
//
// Tests:
// 1. Create and enroll a signing key.
// 2. Sign a mandate through the dashboard.
// 3. Reject an invalid mandate.
// 4. Request payment through MCP.
// 5. Approve a payment using a browser signature.
// 6. Reject unsigned approval.
// 7. Detect a poisoned page and verify the evidence viewer.
//
// Run:
// cd web/e2e && npm install && node dashboard.e2e.mjs

import { JSDOM, ResourceLoader, VirtualConsole } from "jsdom";
import { webcrypto } from "node:crypto";
import { IDBFactory } from "fake-indexeddb";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";


// Build the Leash binary
const here = path.dirname(fileURLToPath(import.meta.url));
const tmp = mkdtempSync(path.join(tmpdir(), "leash-e2e-"));

const bin = path.join(
  tmp,
  process.platform === "win32" ? "leash.exe" : "leash",
);

execFileSync(
  "go",
  ["build", "-o", bin, "./cmd/leash"],
  {
    cwd: path.join(here, "..", ".."),
    stdio: "inherit",
  },
);


// Start the test server
const PORT = 18000 + Math.floor(Math.random() * 1000);
const BASE = `http://127.0.0.1:${PORT}`;

const OP = "e2e-operator-token-0123456789abcdef";
const AG = "e2e-agent-token-0123456789abcdefghij";

let serverLog = "";

const server = spawn(
  bin,
  [
    "serve",
    "-fake",
    "-seed=false",
    "-addr",
    `127.0.0.1:${PORT}`,
  ],
  {
    env: {
      ...process.env,
      LEASH_ADMIN_TOKEN: OP,
      LEASH_AGENT_TOKEN: AG,
      PORT: "",
    },
  },
);

server.stderr.on("data", (data) => {
  serverLog += data;
});

const stop = () => {
  server.kill();

  try {
    rmSync(tmp, {
      recursive: true,
      force: true,
    });
  } catch {
    // The temporary directory may already have been removed.
  }
};

process.on("exit", stop);

// Wait for the server to become healthy.
for (let i = 0; i < 100; i++) {
  try {
    const response = await fetch(`${BASE}/healthz`);

    if (response.ok) {
      break;
    }
  } catch {
    // The server may not be ready yet.
  }

  await new Promise((resolve) => setTimeout(resolve, 100));
}

// Test utilities

const sleep = (ms) =>
  new Promise((resolve) => setTimeout(resolve, ms));

const log = (...args) => console.log(...args);

let failures = 0;

const check = (name, ok, extra) => {
  log(
    (ok ? "PASS " : "FAIL ") +
      name +
      (extra ? `  ${extra}` : ""),
  );

  if (!ok) {
    failures++;
  }
};

// Configure jsdom

// The real AG Grid bundle needs a layout engine.
// The dashboard only needs createGrid for these tests.
class Loader extends ResourceLoader {
  fetch(url, opts) {
    if (url.includes("ag-grid-community")) {
      return Promise.resolve(Buffer.from(""));
    }

    return super.fetch(url, opts);
  }
}

const vc = new VirtualConsole();

vc.on("jsdomError", (error) => {
  log("jsdomError:", error.message.slice(0, 200));
});

vc.on("error", (error) => {
  log("page error:", String(error).slice(0, 200));
});

const dom = await JSDOM.fromURL(`${BASE}/`, {
  runScripts: "dangerously",
  resources: new Loader(),
  pretendToBeVisual: true,
  virtualConsole: vc,

  beforeParse(window) {
    Object.defineProperty(window, "crypto", {
      value: webcrypto,
      configurable: true,
    });

    window.indexedDB = new IDBFactory();

    window.TextEncoder = TextEncoder;
    window.TextDecoder = TextDecoder;
    window.AbortController = AbortController;

    window.matchMedia = () => ({
      matches: false,
      addEventListener() {},
      removeEventListener() {},
    });

    window.fetch = (url, options) =>
      fetch(new URL(url, BASE), options);

    window.sessionStorage.setItem("leash.token", OP);

    window.agGrid = {
      themeQuartz: {
        withParams: () => ({}),
      },

      createGrid(element, options) {
        window.__grid = options;

        return {
          setGridOption() {},
        };
      },
    };

    window.HTMLDialogElement.prototype.showModal =
      function () {
        this.setAttribute("open", "");
      };

    window.HTMLDialogElement.prototype.close =
      function (value) {
        if (value !== undefined) {
          this.returnValue = value;
        }

        this.removeAttribute("open");

        this.dispatchEvent(new window.Event("close"));
      };
  },
});

const w = dom.window;
const d = w.document;

// Get normalized text from an element.
const text = (id) =>
  (d.getElementById(id)?.textContent || "")
    .replace(/\s+/g, " ")
    .trim();

// Wait until a condition becomes true.
const until = async (what, fn, ms = 6000) => {
  const startTime = Date.now();

  while (Date.now() - startTime < ms) {
    try {
      if (fn()) {
        return true;
      }
    } catch {
      // The condition may not be available yet.
    }

    await sleep(50);
  }

  log("  timed out waiting for", what);

  return false;
};

// Verify the dashboard without a signing key

check(
  "key panel offers to create a key",
  await until(
    "create button",
    () => /No signing key yet/.test(text("key-panel")),
  ),
  text("key-panel").slice(0, 90),
);

check(
  "new-mandate is disabled until a key exists",
  d.getElementById("new-mandate").disabled === true,
);

// Create and enroll the signing key

const createKeyButton = [
  ...d.querySelectorAll("#key-panel button"),
].find((button) =>
  /Create my signing key/.test(button.textContent),
);

createKeyButton.click();

check(
  "key created and trusted by the server",
  await until(
    "ready",
    () => /Ready\./.test(text("key-panel")),
  ),
  text("key-panel").slice(0, 120),
);

const stateResponse = await fetch(`${BASE}/api/state`, {
  headers: {
    Authorization: `Bearer ${OP}`,
  },
});

const st = await stateResponse.json();

check(
  "server reports strict mode and the enrolled key",
  st.strict === true && /^[0-9a-f]{16}$/.test(st.key_id),
  `key ${st.key_id}`,
);

check(
  "header shows the key id",
  text("keyid").includes(st.key_id),
);

check(
  "new-mandate is enabled",
  d.getElementById("new-mandate").disabled === false,
);

// Create and sign a mandate
d.getElementById("new-mandate").click();

const set = (id, value) => {
  const element = d.getElementById(id);
  element.value = value;
};

// Fill in a valid mandate.
set(
  "m-intent",
  "Birthday gift for my sister, under $60",
);
set("m-max", "60");
set("m-per", "40");
set("m-step", "20");
set("m-merchants", "legitgifts");
set("m-cats", "gifts");
set("m-exp", "72");

// Submit the mandate form.
d.getElementById("mandate-form").dispatchEvent(
  new w.Event("submit", {
    cancelable: true,
    bubbles: true,
  }),
);

check(
  "mandate signed in the browser and accepted by the server",
  await until(
    "mandate card",
    () =>
      /Birthday gift for my sister/.test(
        text("mandates"),
      ),
  ),
  text("m-error"),
);

check(
  "mandate form closed",
  !d
    .getElementById("mandate-dlg")
    .hasAttribute("open"),
);

// Verify invalid mandate validation
d.getElementById("new-mandate").click();

set("m-intent", "x");
set("m-max", "40");
set("m-per", "90");
set("m-merchants", "legitgifts");

d.getElementById("mandate-form").dispatchEvent(
  new w.Event("submit", {
    cancelable: true,
    bubbles: true,
  }),
);

await sleep(100);

check(
  "an inconsistent mandate is rejected in the form",
  /per-purchase limit/.test(text("m-error")),
  text("m-error"),
);

d.getElementById("m-cancel").click();

// Set up MCP communication
const rpc = async (sid, method, params, id = 1) => {
  const response = await fetch(`${BASE}/mcp`, {
    method: "POST",

    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${AG}`,

      ...(sid
        ? { "Mcp-Session-Id": sid }
        : {}),
    },

    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method,
      params,
    }),
  });

  return {
    sid: response.headers.get("mcp-session-id"),
    body: await response.json(),
  };
};

// Initialize the MCP session.
const init = await rpc(
  null,
  "initialize",
  {
    protocolVersion: "2025-06-18",
  },
);

const sid = init.sid;

// Extract the demo shop URL from the server logs.
const shopMatch =
  /Demo shop: (http:\/\/[\d.:]+)/.exec(serverLog);

const shop = shopMatch[1];

// Call an MCP tool and parse its JSON result.
const call = async (name, args) => {
  const response = await rpc(
    sid,
    "tools/call",
    {
      name,
      arguments: args,
    },
    2,
  );

  return JSON.parse(
    response.body.result.content[0].text,
  );
};

// Request payment for a $32 desk lamp
const browseResult = await call("leash_browse", {
  url: `${shop}/legit/lamp`,
});

const ev = browseResult.evidence_id;

const mandateResult = await call(
  "leash_list_mandates",
  {},
);

const mand = mandateResult.mandates[0].mandate_id;

const pay = await call("leash_request_payment", {
  mandate_id: mand,
  merchant_id: "legitgifts",
  items: ["Desk lamp"],
  amount: "32.00",
  quote_id: "q-lamp",
  evidence_refs: [ev],
});

check(
  "the agent's $32 request waits for the user",
  pay.state === "STEP_UP_PENDING",
  pay.state,
);

check(
  "the dashboard shows it under 'Needs you'",
  await until(
    "approve button",
    () => /Approve \\$32\.00/.test(text("needs-list")),
  ),
  text("needs-list").slice(0, 100),
);

// Approve the payment using a browser signature
const approveButton = [
  ...d.querySelectorAll("#needs-list button"),
].find((button) => /Approve/.test(button.textContent));

approveButton.click();

check(
  "a confirmation shows what will be signed",
  await until(
    "confirm dialog",
    () =>
      d.getElementById("confirm").hasAttribute("open") &&
      /32\.00 USD to legitgifts/.test(
        text("confirm-text"),
      ),
  ),
  text("confirm-text").slice(0, 140),
);

// Confirm the approval.
d.getElementById("confirm").returnValue = "ok";
d.getElementById("confirm").close("ok");

check(
  "the signed approval was accepted and the hold placed",
  await until(
    "held",
    () => /held in escrow/i.test(d.body.textContent),
  ),
  "",
);

// Verify the request status through MCP.
const status = await call("leash_status", {
  request_id: pay.request_id,
});

check(
  "the server shows the request AUTHORIZED",
  status.state === "AUTHORIZED",
  status.state,
);

// 12. Verify that unsigned approval is rejected

// A stolen operator token alone must not authorize payment.
const pay2 = await call("leash_request_payment", {
  mandate_id: mand,
  merchant_id: "legitgifts",
  items: ["Desk lamp"],
  amount: "32.00",
  quote_id: "q-lamp",
  evidence_refs: [ev],
  idempotency_key: "second",
});

const raw = await fetch(
  `${BASE}/api/requests/${pay2.request_id}/approve`,
  {
    method: "POST",
    headers: {
      Authorization: `Bearer ${OP}`,
    },
  },
);

check(
  "an unsigned approval with the operator token alone is refused",
  raw.status === 403,
  `HTTP ${raw.status}`,
);

// Test a poisoned page and the evidence viewer

// Browse a page containing planted instructions.
const evilResult = await call("leash_browse", {
  url: `${shop}/shady/deal`,
});

const evil = evilResult.evidence_id;

// Request payment using evidence from the suspicious page.
await call("leash_request_payment", {
  mandate_id: mand,
  merchant_id: "shadyshop",
  items: ["Premium bundle"],
  amount: "39.99",
  evidence_refs: [evil],
  idempotency_key: "attack",
});

// Verify the taint warning appears.
check(
  "the taint banner appears",
  await until(
    "banner",
    () =>
      !d.getElementById("taint").hidden &&
      /planted instructions/.test(text("taint")),
  ),
  text("taint").slice(0, 100),
);

// Fetch the payment requests.
const listResponse = await fetch(`${BASE}/api/requests`, {
  headers: {
    Authorization: `Bearer ${OP}`,
  },
});

const list = await listResponse.json();

const attack = list.find(
  (request) => request.merchant_id === "shadyshop",
);

check(
  "the attack request exists and is blocked",
  attack && attack.state === "DENIED",
  attack && attack.state,
);

// Inspect the evidence viewer
// Open the suspicious request in the dashboard.
w.__grid.onRowClicked({
  data: attack,
});

check(
  "the drawer shows what the agent read, hidden text included",
  await until(
    "evidence",
    () =>
      /Hidden text a person would not see/.test(
        text("drawer-body") || d.body.textContent,
      ),
  ),
  "",
);

// Check whether the hidden instruction is highlighted.
const marks = [
  ...d.querySelectorAll(
    "#drawer mark, .drawer mark, mark",
  ),
].map((element) => element.textContent);

check(
  "the hidden instruction is highlighted in the page text",
  marks.some((value) =>
    /ignore previous instructions/i.test(value),
  ),
  JSON.stringify(marks).slice(0, 100),
);

check(
  "the page badge says planted instructions",
  /Planted instructions/.test(d.body.textContent),
);

// Check for script injection
check(
  "no script injection: nothing from a page became markup",
  d.querySelectorAll("script").length === 3 &&
    !d.body.innerHTML.includes("<img"),
  `scripts=${d.querySelectorAll("script").length}`,
);

// Print the final test result
log(
  failures
    ? `\n${failures} FAILED`
    : "\nALL UI CHECKS PASSED",
);

process.exit(failures ? 1 : 0);