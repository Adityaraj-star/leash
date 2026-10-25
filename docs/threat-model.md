# Threat model

**Trusted:** the user's signing key, Leash's code and ledger, PayPal.
**Untrusted:** the agent, every web page it reads, merchants' claims about themselves.

| Threat | Mitigation | Test |
|---|---|---|
| Prompt injection redirects payment | provenance (R7), merchant allowlist (R3), severity is max over the whole session | `control_test` attack tests |
| Injection on an allowed merchant | judge and provenance still tighten to STEP_UP / DENY | yes |
| Agent inflates amount | amount trusted only via mandate, user message, or Leash-fetched quote | quote mismatch test |
| Agent forges delivery | only the merchant secret can attest; one `ErrUnauthorized` for every failure | yes |
| Replay / double spend | idempotency (R8), single-use (R4), deterministic PayPal-Request-Ids | replay test |
| Concurrent budget overrun | global decision lock | 12-way concurrency test |
| Judge manipulated into approving | judge can only tighten; errors fail closed | exhaustive matrix and fuzz |
| Ledger tampering | hash chain; startup refuses a ledger that does not verify | tamper test |
| Compromised agent keeps spending | kill switch: revoke mandate, cancel step-ups, void holds | yes |
| SSRF via browse | host allowlist, size cap, redirect check | browse tests |
| Agent hides a poisoned page by switching sessions | sessions are issued by the server and bound to the connection (`AgentConn`); in `Strict` mode made-up sessions are refused | `hardening_test` |
| Agent fakes "the user said so" | the user's words come only from `SetUserMessage` (user side); the agent has no such field | `hardening_test` |
| Agent approves its own step-up, or refunds a delivered purchase | `Strict` requires a user-key signature over the request, merchant and amount; `ReportProblem` can only release holds, never move captured money | `hardening_test` |
| First visitor pins their own user key | enrollment needs `EnrollSecret` in `Strict` mode | `hardening_test` |
| PayPal timeout leaves an orphan hold or a stuck capture | unknown outcomes are not denied; PayPal state is read first; `Reconcile` retries with the same request ids | `reliability_test` |
| Mandate revoked or expired while a request waits | a guard is checked before any new hold, in every path | `hardening_test` |
| Crash mid-write bricks restart | a torn final line is repaired on open; a failed write is rolled back; the ledger key is persisted | `durability_test` |
| Evidence flood pushes a poisoned page out of memory | benign pages are evicted first, and a session's worst severity is remembered | provenance tests |

## Not covered

- Compromise of the user's key or the Leash host.
- A malicious merchant that delivers badly: handled by escrow, an optional inspection window before capture (`InspectionPeriod`), `report_problem` (holds only) and PayPal disputes.
- Signatures are ECDSA and malleable; Leash never uses signature bytes as an identity.
- Look-alike folding covers common Cyrillic, Greek, full-width and mathematical letters, not all of Unicode.
- Real PayPal behavior (see `docs/spikes.md`); injection detection is heuristic, not complete.
