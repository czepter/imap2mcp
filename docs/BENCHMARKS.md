# Benchmarks (Version 1 performance gate)

Source of truth for the v1 performance criteria (`docs/VERSION_PLAN.md` Version 1, criteria 4 and 5; `docs/DESIGN_V1.md` "Performance gate & harness"). Every run of `npm run bench` appends a dated section at the end of this file. Failed gates are recorded as **FAIL**; the gates are never changed to fit a result.

## Gates

| # | Gate | Limit |
|---|---|---|
| G1 | Cold UID/header sync of 10,000 messages | <= 30 s |
| G2 | Warm header list/search, <= 100 results, 100 calls at concurrency 5 | p95 <= 300 ms |
| G3 | 100 new messages searchable after a sync starts | <= 5 s |
| G3b | Unchanged messages are not fully re-FETCHed during that incremental sync | none (one tolerated, see below) |
| G4 | Flag changes and expunges done by another client, measured separately (G4a flags, G4b expunges) | <= 60 s each |
| G5 | UIDVALIDITY reset rebuild, no stale UID mapping served | within the cold budget (30 s) |
| G6 | Sidecar RSS with the 10k fixture | < 256 MB |
| B1-B3 | Body transfer (`fetchBody`) and remote body search (`searchText`) | measured separately, no gate |

## Method

- **Fixture**: `test/helpers/fakeImap.ts` (in-process IMAP-over-TLS) holds 10,000 messages in `INBOX`, generated lazily, with about 2 KB of envelope data each (long To/Cc lists), plus a second folder of 200 messages with ~50 KB bodies for the body measurements. Every response batch is delayed by 20 ms, i.e. a 20 ms round trip per IMAP command exchange. The fake server runs on the host and is *not* CPU-limited; it shares the machine with the driver, so a heavily loaded host inflates every number.
- **Sidecar**: the Go binary (`sidecar/bin/sidecar`) runs in Docker with `--cpus=2 --memory=2g --memory-swap=2g --network host`, started with the same stdin-secret handshake the Node supervisor uses. If Docker is unavailable, `npm run bench -- --no-docker` runs it as a plain host process; the report then states that **no CPU/memory limit was enforced** and G6 only reflects process RSS.
- **Driver**: `bench/run.ts` talks to the sidecar directly over its authenticated Unix socket (JSON-RPC), one connection, 5 workers for the concurrency-5 gates. Memory comes from the sidecar's own `ping.rssBytes`, plus `docker stats` sampled every 2 s.
- **Cold sync** is `sync mode=full` on a fresh cache. **Warm** calls are `list` (100 newest) and header `search` (subject; sender + unseen) against the filled cache; the sidecar's implicit status sync (every 5 s) is part of what is measured. **Incremental** delivers 100 messages through the fake, starts `sync mode=auto` and polls `search` until all 100 are found; the fake counts per-UID envelope FETCHes so "not refetched" is measured on the wire. **Reconciliation**: first 500 flag changes alone, then 200 expunges alone, applied through the fake as another client would, with the default `SYNC_RECONCILE_SECS=30`; each is polled until visible (so the flag number is the worst case that only the periodic reconcile can detect). **UIDVALIDITY** recreates the folder with 10,000 new messages that reuse UID 1..N and checks that a `fetchHeaders` with the old UIDVALIDITY is refused (`-32010`) and that no old row remains.
- **Tolerance for G3b**: `UID FETCH <lastUid+1>:*` returns the highest existing message even when nothing is new (RFC 3501 sequence-set semantics), so at most one old UID may show one envelope FETCH. The report prints the exact count.

## What these numbers do not cover

- The Node MCP/OAuth/policy layer and HTTP in front of the sidecar (end-to-end behavior is covered functionally by `test/integration/v1-*.test.ts`, not by timing).
- Real mail servers. The fixture is a purpose-built fake; its per-FETCH cost, response size and TLS behavior differ from Dovecot, Gmail or Exchange. Body search time is dominated by the fake scanning every message, so B3 says little about a real provider.
- Network jitter, packet loss, IMAP servers that throttle.

## Reproduce

```bash
npm run build:sidecar   # builds sidecar/bin/sidecar through Docker (scripts/go.sh)
npm run bench                 # full gate run, appends to this file
npm run bench -- --messages 2000 --no-write   # smoke run, nothing is written here
```

Run it on an otherwise idle machine and check `uptime` first; the fake server and the driver share the host with the container, and a loaded host inflates every number.

## Results

## Run 2026-11-07T22:12:15.000Z

**Result: ALL GATES PASSED**

| Item | Value |
|---|---|
| Host CPU | 12th Gen Intel(R) Core(TM) i5-12500T, 10 logical CPUs |
| Host load average (1/5/15 min) | at start 0.59 / 1.51 / 9.52; at end 0.42 / 1.25 / 8.76 (10 CPUs; high load invalidates timings) |
| Host RAM | 8.7 GiB |
| Kernel / OS | Linux 7.0.0-42-generic |
| Node | v26.13.0 |
| Docker | client 29.9.3 / server 29.9.3 |
| Sidecar runtime | `docker run -i --rm --init --cpus=2 --memory=2g --memory-swap=2g --network host` image `alpine:latest` (sha256:3f4d6b32e267) |
| Sidecar binary | `sidecar/bin/sidecar`, dcb6496+uncommitted; `9364cfbe40f9` |
| Fixture | 10000 messages in INBOX, ~2 KB envelope each, 200 x ~50 KB-body messages in a second folder; fake IMAP-over-TLS server (Node, **on the host, not CPU-limited**, shares the machine with the driver); injected 20 ms delay on every response batch |
| Not measured | The Node MCP/OAuth/policy layer and HTTP in front of the sidecar; real providers (Gmail/Dovecot/...); network jitter. Numbers are sidecar RPC latency over the Unix socket + IMAP link to a fake. |

| Gate | Result | Limit | Measured |
|---|---|---|---|
| G1 Cold UID/header sync | PASS | <= 30 s | 1893 ms wall (sidecar reports 1891 ms), 10000 messages, 10000 fetched, 10000 envelope FETCHes at the server |
| G2 Warm list (100 newest), 100 calls, concurrency 5, <=100 results | PASS | p95 <= 300 ms | p50 4.2 / p95 7.0 / p99 1026.7 / max 1026.8 ms (1111 ms wall) |
| G2 Warm search subject, 100 calls, concurrency 5, <=100 results | PASS | p95 <= 300 ms | p50 5.2 / p95 10.1 / p99 11.5 / max 11.6 ms (115 ms wall) |
| G2 Warm search from + unseen, 100 calls, concurrency 5, <=100 results | PASS | p95 <= 300 ms | p50 4.3 / p95 7.4 / p99 9.1 / max 10.4 ms (100 ms wall) |
| G3 100 new messages searchable after sync start | PASS | <= 5 s | 71 ms (found 100/100; sync reported fetched=100) |
| G3b Unchanged messages not refetched during incremental sync | PASS | 0 refetched (1 tolerated: `UID FETCH n:*` always returns the highest UID, RFC 3501) | 0 of 10000 old UIDs got an envelope FETCH (max 0); new UIDs fetched 100x |
| G4a Flag reconciliation: 500 flag changes by another client, no other change (SYNC_RECONCILE_SECS=30) | PASS | <= 60 s | visible after 30305 ms |
| G4b Expunge reconciliation: 200 messages expunged by another client, no other change | PASS | <= 60 s | count correct after 31714 ms; expunged UIDs still returned by search: 0 |
| G4c Explicit full reconcile (`sync mode=full`, UID SEARCH ALL + FLAGS) on 10k folder | info | informational | 1642 ms (flagChanges=46, expunged=0) |
| G5 UIDVALIDITY reset rebuild | PASS | <= 30 s (cold budget), no stale mappings | 2799 ms, reset=true, count=10000, stale-uidValidity fetchHeaders -> error -32010, new-only list=true, old rows left=0 |
| G6 Sidecar RSS (ping.rssBytes, max of after-warm and after-reset with 2 x 10k headers built) | PASS | < 256 MB | 91.3 MiB (after warm queries 91.3, final 70.8) |
| G6b Container memory peak (docker stats, 2 s sampling) | info | informational (< 2 GiB cgroup limit) | 92.6 MiB |
| B1 Body transfer fetchBody (~50 KB bodies), sequential x50 | info | measured separately, no gate | p50 41.6 / p95 43.3 ms |
| B2 Body transfer fetchBody, 100 calls concurrency 5 | info | no gate | p50 41.8 / p95 109.1 ms |
| B3 Remote body search searchText over 10000 messages (IMAP UID SEARCH TEXT; time is dominated by the fake server scanning), sequential x5 | info | no gate | p50 354 / max 1350 ms |

- Average header as returned by `list` (JSON): 2612 bytes (target fixture: about 2 KB).

### Notes on the runs above and on earlier runs (written by hand)

- **One call per warm batch takes about 1.0 s** (p99 and max of 1026-1058 ms in four of five full runs; it hit a different one of the three warm batches each time). p95 is unaffected (7-10 ms) so no gate fails, but the stall is real: it looks like the sidecar's implicit status sync (every 5 s, the first read after the interval) occasionally taking about a second on the 10k folder. Not investigated further by the benchmark owner; see the sidecar owner.
- **Flag reconciliation costs one full reconcile interval by design.** A flag change alone moves neither UIDNEXT nor MESSAGES, so only the periodic reconcile (30 s) can see it: 30.3 s measured, well inside the 60 s gate but not fast. Expunges are seen after about the same time (31.7 s) when nothing else triggers a sync. The earlier run where flags became visible after 6 s coincided with an expunge, which forces a reconcile; that is why the harness now measures the two separately.
- **Unreliable run on a loaded host (not written by the harness; 10,000 messages, same configuration, host load average 11-25 caused by unrelated processes): G4a FAILED at 73.2 s** (gate 60 s) for 500 flag changes while expunges took 31.4 s; the run then stalled in the UIDVALIDITY phase (`sync` after the folder was recreated never returned; sidecar idle at 0.02 % CPU, one idle TLS connection between sidecar and fixture, no error logged; killed after more than ten minutes). The same configuration on an idle host (load below 1) passed every gate in three consecutive runs. The cause of the 73 s and of the stall was not established; treat both as a robustness risk for the sidecar under CPU pressure (the harness now fails a hung RPC after 120 s and prints the last IMAP commands the fixture saw). Gates are not tuned: the section above is the idle-host result, this paragraph is the failed one.
- `SYNC_RECONCILE_SECS` is not forwarded from the Node server to the sidecar child (the supervisor passes only `PATH`, `SIDECAR_SOCKET` and `SIDECAR_EXTRA_CA_FILE`), so setting it on the server has no effect; these benchmarks start the sidecar directly with `SYNC_RECONCILE_SECS=30`, which is also its default.
