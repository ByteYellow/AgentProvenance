# AgentProvenance Infra v1 -- Definition of Done

> Status: release-scope doc. Turns the `north-star-three-pillars.md` vision into a
> checkable v1 acceptance list. Decisions below were taken 2026-06-27 after a
> file-grounded audit of the whole repo. Each item is DONE / PARTIAL / DEFERRED
> with the evidence symbol. "DEFERRED" means explicitly out of v1, into v2.

## 0. The one decision that frames v1

The differentiated asset is the **correlation primitive** turned into a
**verifiable, queryable evidence graph**. v1 ships that core for the two deploy
shapes that have users today (Library/CLI and sidecar daemon). v1 is **hardening
+ honesty**, not new features -- the evidence-graph core (storage, ingest,
correlation, observability, provenance, risk, forensics) is already implemented
and verified by a live binary run.

### Honesty scoping (load-bearing)

v1 makes an **integrity** claim, NOT a **tamper-evidence** claim. `graph verify`
recomputes hashes from the local SQLite store, which a host-root attacker can
edit; it detects accidental corruption and object-hash/parent breaks, not an
attacker who rewrites the store and re-derives the chain. Off-host
capture-time anchoring (KMS/TPM/transparency log) is the thing that would make
"tamper-evident" true, and it is **v2** (see Sec 3). Do not market v1 as
tamper-evident against a malicious host root.

## 1. What v1 includes (status from the 2026-06-27 audit)

| # | Area | Status | Evidence (file:symbol) |
|---|---|---|---|
| 1 | Data-plane: spool / backpressure / drop | DONE | `telemetry/spool.go` Enqueue/applyBackpressure/dropPolicy (reject\|drop_oldest, HTTP 429); `accept_telemetry_100k_pressure.sh` |
| 1 | Data-plane: collector as a *separate process* | PARTIAL -> v1 accepts in-daemon ingest | only `cmd/agentprov-sensor` is a separate producer; ingest is in-daemon (shared SQLite + writeMu). Full process-level data-plane split is coupled to Deploy 3 -> **v2** |
| 2 | Control: daemon holds correlation/policy/risk/response/verify | DONE | `daemon/server.go` /v1 routes |
| 2 | Control: CLI as client | PARTIAL | reads route via daemon; **writes (`record`,`telemetry ingest*`,`bind`) run in-process, no daemon client method** -> two-writer hazard, see Sec 2 must-fix |
| 2 | Control: stable JSON schema | PARTIAL | `schema_version` is per-response-type, not a universal envelope; several handlers (health, security/*, graph/verify, observe, timeline) lack it. Tighten as the Tier-A contract item |
| 2 | Control: authn | DONE | `withAuth` bearer token, constant-time, open-by-default |
| 2 | Control: authz / scopes | DEFERRED | no roles/scopes; single all-or-nothing token -> **v2** (rides with Deploy 3) |
| 3 | Storage: WAL + busy_timeout (all conns) | DONE | `store/store.go` DSN `_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)` |
| 3 | Storage: raw retention | DONE | `telemetry/retention.go` PruneRawEvents (manual CLI; no scheduler) |
| 3 | Storage: 10s/60s windows | DONE | `telemetry/windows.go` (10s built but unasserted -- see Sec 2 tests) |
| 3 | Storage: content-addressed objects | DONE | `provenance/objects.go` MaterializeRun; forensics/replay manifests |
| 3 | Storage: graph verify object hash/parent/chain | DONE | `provenance/verify.go` verifyObjects + verifyRiskAndResponses |
| 4 | Ingest: Falco | DONE | `IngestFalco`; `accept_falco_risk_realistic.sh` |
| 4 | Ingest: Tetragon | DONE | `mapTetragon`; unit + demo (no accept script -- see Sec 2 tests) |
| 4 | Ingest: own eBPF sensor -- receiver | DONE | `mapNative` native format; `accept_native_sensor_risk.sh`; live VM E2E 2026-06-27 |
| 4 | Ingest: own eBPF sensor -- capture binary build | PARTIAL | bpf2go bindings not committed; needs Linux `go generate` -> reproducible build is a Sec 2 must-fix |
| 4 | Ingest: raw events need no tool_call_id | DONE | `telemetry/service.go` IngestFiltered -> correlation.Resolve fallback |
| 4 | Correlation by container/cgroup/pid/time | DONE | `correlation/binding.go`: process 1.0 / cgroup 0.98 / container 0.92 / pid 0.85 |
| 4 | Child/async/delayed -> original scope | DONE | time-window open bindings + root_pid + container/cgroup co-membership (not ppid lineage); add child-pid test (Sec 2) |
| 5 | Observability: timeline app+runtime | DONE | `provenance/timeline.go` BuildTimeline, lanes + correlation_status |
| 5 | observe summary/coverage/scopes/event/process/flow | DONE | `cli/observe_cmd.go` (6/6) |
| 5 | graph explain event/process/tool_call/file/risk/artifact | DONE | `provenance/explain.go` (+attempt,+run) |
| 5 | core queries JSON + schema_version | DONE | all commands `--json` |
| 6 | record base snapshot / changed files / process obs | DONE | `record/service.go` (self-recursion bug fixed 2026-06-27) |
| 6 | diff / blame(4-state) / artifact(hash,source,parent) / replay | DONE | `provenance/diff.go`, `objects.go`, `replay.go` |
| 7 | metadata_ip / private_cidr / secret_path -> risk -> response | DONE | `security/policy.go` DefaultRules, EvaluateRuntimeEvent |
| 7 | verify policy->risk->response->unified security signal | DONE | `verify.go` verifyRiskAndResponses (requires unified signal) |
| 7 | quarantine/kill/deny disposition (record-level) | DONE | state mutation, not real enforcement (acceptable for v1) |
| 7 | Feishu/DingTalk/webhook notifier | DEFERRED | zero implementation -> **v2** |
| 8 | forensics export bundle + sha256 | DONE | `forensics/export.go` ExportBundle |
| 8 | bundle contents (events/policy/risk/response/edges/manifest/cost) | DONE | export.go bundle map; `accept_forensics_bundle.sh` |
| 8 | sign + offline verify (hash + schema) | DONE | `attest/` in-toto + DSSE + ed25519; VerifyBundleAttestation |
| 8 | graph verify proves run chain unbroken | DONE | integrity only -- see Sec 0 honesty scoping |
| 9 | 100k ingest keeps query responsive | PARTIAL | bounded paging asserted; no latency SLA (Sec 2) |
| 9 | concurrent record/ingest preserves consistency | PARTIAL | `record batch --concurrency` exists (worker pool, WAL-serialized writes); **file-safe via WAL, logical consistency under concurrent writers untested** (Sec 2) |
| 9 | raw retention effective | DONE | `accept_daemon_evidence_api.sh` prune |
| 9 | pagination / cursor | DONE | ListEventsPage opaque cursor |
| 9 | scenarios normal/risk/high-pressure/corrupted-chain | PARTIAL | corrupted-chain only tests the **signed bundle**, not an in-DB hash-chain tamper -> `graph verify` detection (Sec 2 test) |
| 10 | Deploy 1 Library/CLI | DONE | single binary + python helper; `accept_deploy1_batch_pipeline.sh` |
| 10 | Deploy 2 Sidecar/local daemon | DONE | `daemon serve` + REST + bearer auth |
| 10 | Deploy 3 Central evidence service | DEFERRED | no object storage / multi-tenant / mTLS -> **v2** |

## 2. v1 must-close before calling it done (hardening + honesty, no new features)

1. **[DONE 2026-06-27] record self-recursion crash** -- `CopyDirFiltered` excludes
   the dst subtree + .agentprov.
2. **Confidence semantics split** -- distinguish `self_observed` (Mode 1 recorder
   joins data it collected itself, synthetic container_id -> 1.0) from
   `kernel_correlated` (real telemetry joined via binding). Today both land as a
   bare confidence number; a security consumer must be able to tell them apart.
3. **Two-writer guard** -- WAL makes concurrent writers file-safe, but a running
   daemon + a direct CLI write to the same data dir diverge logically. Either
   route CLI writes through the daemon, or refuse/warn when a daemon owns the
   data dir. At minimum document it as unsupported.
4. **eBPF sensor reproducible build** -- commit the generated bpf2go bindings (or a
   `make sensor` + Linux CI job) so the capture binary builds from the repo, not
   only after a manual `go generate` on the VM.
5. **Adversarial / coverage tests** (the "prove the crown jewel" gates):
   - in-DB hash-chain tamper -> `graph verify` detects it (real corrupted-chain
     scenario, not just signed-bundle tamper)
   - concurrent writers -> graph logical consistency invariant holds
   - child event whose pid != binding pid still attributes to the scope
   - Tetragon `accept_*.sh` script (parity with falco/native)
   - 10s window assertion; a latency/responsiveness assertion under 100k pressure
6. **Contract tightening** -- give the control API a consistent `schema_version`
   on every response type (Tier-A versioned-contract item).

## 3. Explicitly DEFERRED to v2 (decided 2026-06-27)

- **Off-host capture-time tamper-evidence anchoring** (KMS/TPM/transparency log).
  Until then the v1 security claim is integrity, not tamper-evidence (Sec 0). This
  is north-star Tier B "existential for the security customer" -- v2 headline.
- **Deploy 3 central evidence service** + the strong process-level data-plane
  isolation and authz/scopes it requires (object storage, multi-tenant, mTLS).
  Deploy 2 (sidecar daemon) already serves single-node security harnesses, so
  deferring Deploy 3 does **not** drop the security track -- it defers scale-out.
  north-star Sec 7: earn it through Mode 1/2 adoption.
- **Notifications** (Feishu/DingTalk/webhook response adapters).
- Cross-host identity / clock-skew correlation (A2); auditd/extra substrates;
  sensor capturing openat *reads* (for true `secret_path`, vs today's writes).

## 4. v1 done gate

v1 is done when: every Sec 1 PARTIAL above is either DONE or consciously moved to Sec 3,
all Sec 2 items are closed, and the full gate is green --
`go vet/test ./...`, every `scripts/accept_*.sh`, gofmt + non-ASCII + `git diff --check`.
