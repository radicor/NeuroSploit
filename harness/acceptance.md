# P0 acceptance checklist (v4.5.0 gate)

Twelve assertions, one per P0 finding. Run from the repo root. Every row is owned by a closed spec; a
row whose owner loses `approved` breaks the harness (`SEC-016` criterion 13).

| # | Finding | Command | Expected | Owner |
|---|---------|---------|----------|-------|
| A1 | C1 | `cd web && npm run accept` | `A1` ok — the console binds `127.0.0.1` only | SEC-001 |
| A2 | C2 | `cd web && npm run accept` | `A2` ok — `text/plain` → 415, bad `Origin` → 403, bad `Host` → 403 | SEC-007 |
| A3 | C3 | `cd web && npm run accept` | `A3` ok — integration and vault GETs carry `__masked__`, never the value | SEC-007b |
| A4 | H1 | `cd web && npm run accept` | `A4` ok — the asset is `octet-stream` + `attachment` + `nosniff` | SEC-006 |
| A5 | H2 | `cd web && npm run accept` | `A5` ok — a client `id` becomes a UUID; no data rides `onclick=` | SEC-006 |
| A6 | H3 | `cd web && npm run accept` | `A6` ok — a CRLF target is 400 `field:target` | SEC-002 |
| A7 | H4 | `cd web && npm run accept` | `A7` ok — `mode:"mcp"` 400, leading `-` 400, outside-root `creds` 400 | SEC-002 |
| A8 | H5 | `cd web && npm run accept` | `A8` ok — `/proxy …` refused, `/pause` allowed | SEC-003 |
| A9 | H6 | `cd web && npm run accept` | `A9` ok — a metadata URL fails URL policy | SEC-013a |
| A10 | H8 | `cd neurosploit-rs && cargo test -p neurosploit-harness recon_rejects_shell_metacharacter_urls` | `1 passed` and no marker file | SEC-004 |
| A11 | H13 | `cargo test -p neurosploit-harness state::` and `cd web && npm run accept` | Rust `6 passed`; `A11` ok — a torn config recovers from `.bak` | SEC-014 |
| A12 | H14 | `cd neurosploit-rs && cargo test -p neurosploit-harness recon_child_is_killed_on_cancel` | `1 passed` | SEC-004 |

`cargo` needs `export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"`.

## Notes for anyone extending this

Four loopback facts cost a round each to discover; a new wire test must honour all four (`SEC-016` TN-4):

1. A `ScopePolicy` `hard:` entry is **host-only** — `127.0.0.1:<port>` is refused as out of scope.
2. Raw request header names arrive **lowercased** (reqwest writes `authorization:`), so match a
   lowercased copy.
3. A mock accepts in a **bounded loop** (deadline + attempt cap), counts non-matching connections, and
   panics with that count — never a single `accept()`, never a silent timeout.
4. A loopback client must be `.no_proxy()`: `NEUROSPLOIT_PROXY` is the real proxy seam.

**A12 is load-sensitive.** `recon_child_is_killed_on_cancel` spawns a child and polls `/proc` for a
unique token; under a loaded machine it can miss its ~1 s budget and fail intermittently (observed once
in a full run, passing alone and in two subsequent full runs). If A12 fails, re-run it alone before
believing it: `cargo test -p neurosploit-harness recon_child_is_killed_on_cancel`. Widening its poll
budget belongs to `SEC-004`'s test, not to this harness.

A8 is asserted through the production `gateStdin` because the `/input` route needs a live child; its
HTTP-level half is SEC-003's own suite. A10/A12 are cited Rust tests, run by CI rather than shelled out
from the web suite.
