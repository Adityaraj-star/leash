# ADR 0001: stdlib-first, interfaces at the edges

**Status:** accepted (temporary for storage and SDKs)

Third-party modules could not be fetched in the build environment. The core is
stdlib-only behind interfaces (`Store`, `Judge`, `QuoteSource`, PayPal client), so
SQLite, the MCP SDK and the Anthropic SDK can be added on a networked machine
without touching the rules, settlement or ledger code.

**Consequence:** the file store is JSON lines; tests use a fake PayPal. Real
behavior is validated by `cmd/spike` (see `docs/spikes.md`).
