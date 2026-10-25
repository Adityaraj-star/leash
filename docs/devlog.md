# Devlog

## 2026-10-19
- Provenance HTML parsing fixed (tag regexp, whitespace squash).
- Added `judge` (tighten-only), `control` (orchestration, ~25 tests under -race),
  `Engine.Cancel`, `cmd/leash demo`, `cmd/spike` (sandbox spike runner with `-fake`).
- Dry-run of the spike runner found the fake refuses void-after-partial-capture.
  Kept as a pessimistic assumption until S1 runs against the real sandbox.
- Next: run spikes S1-S4 with real credentials; HTTP API + SSE, MCP server, LLM
  judge with an eval set, demo shops, dashboard, deploy.
