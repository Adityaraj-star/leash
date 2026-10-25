# Architecture

```
agent (untrusted)            Leash control plane                      PayPal
 request_payment  ───────►  validate → mandate lookup → replay check
 browse(url)      ───────►  quote fetch (server-to-server) → provenance.Check
                            judge (may only tighten) → policy.Evaluate
                            settlement.Engine ───────────────────────► Orders / Payouts
 merchant attests ───────►  AttestDelivery (merchant secret)  ───────► capture, payout
                            ledger: signed hash chain of every event
```

## Packages

| Package | Role |
|---|---|
| `internal/money` | integer minor-unit amounts, no floats |
| `internal/mandate` | user-signed spending authority (ECDSA P-256, raw r‖s) |
| `internal/policy` | deterministic rules R1-R9, `Decision` ALLOW / STEP_UP / DENY / REPLAY |
| `internal/provenance` | HTML to text, injection detection, trusted-value check |
| `internal/judge` | `Judge` interface and `Tighten`: never loosens a decision |
| `internal/ledger` | hash-chained, verifiable event log |
| `internal/settlement` | state machine and engine with write-ahead intents, deterministic PayPal-Request-Ids |
| `internal/paypal` | sandbox-only REST client; `paypaltest` is the in-process fake |
| `internal/control` | orchestration and the agent-facing API |

## Rules

R1 mandate validity, R2 amount/budget, R3 merchant allowlist and category,
R4 single-use, R5 velocity, R6 step-up threshold, R7 provenance, R8 idempotency,
R9 delivery deadline.

## Settlement states

REQUESTED → EVALUATED → (STEP_UP_PENDING) → APPROVED → AUTHORIZED → DELIVERED →
(CAPTURE_PENDING) → CAPTURED → (PAYOUT_PENDING) → PAID_OUT. Exits: DENIED, EXPIRED,
VOIDED, REFUNDED, DISPUTED.

The two PENDING states exist because PayPal's answer is not always final: a request
becomes CAPTURED or PAID_OUT only when PayPal says so. A payout that fails returns the
request to CAPTURED (funds stay in escrow) and is retried with a new batch id.

## Callers

`internal/control/surfaces.go` splits the control plane into `AgentAPI`, `UserAPI`,
`MerchantAPI`, `WebhookAPI` and `OperatorAPI`. The MCP handlers receive only an
`AgentConn`, which is bound to a server-issued session. See the threat model.

## Reliability

Every call that moves money writes an intent first and reuses a deterministic
`PayPal-Request-Id`. A client error (4xx) proves PayPal did nothing and denies the
request. A timeout, dropped connection or 5xx proves nothing: the request keeps its
state and `Reconcile` (run by `Plane.Sweep` at startup and on a timer) reads PayPal's
state and finishes it. After delivery an optional inspection window keeps the hold in
place so the buyer can still back out; a hold about to lapse is captured early.

## Concurrency and restart

A global decision lock serializes usage → evaluate → tighten → decide, so the
budget invariant holds under concurrent requests (tested: 12 concurrent requests
approve exactly 3). Mandates, the pinned user key and revocations are rebuilt from
the verified ledger on startup.

## Deviation from the plan

`request_payment` accepts `quote_id`. See README.
