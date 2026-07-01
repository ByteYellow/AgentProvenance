# Interview Demo — Agent-in-Sandbox Supply-Chain Exfiltration

A 5–10 minute walkthrough you can drive live. It shows the one thesis behind
AgentProvenance: **model intent → system action → a verifiable, signed causal
chain on one graph**, and how that chain answers security and audit questions a
flat log cannot.

Everything here runs offline from a committed, signed capture — no Linux/eBPF VM
required at demo time.

---

## 1. The one-sentence pitch

> When you let an AI agent run in a sandbox, AgentProvenance correlates what the
> agent *intended* (run / tool call / process) with what the system *did*
> (execve / file / network) into a single causality graph, stores the evidence
> content-addressed and signed, and lets you replay, query, and audit it.

The moat is **verifiable signed provenance + correlation**, not feature count.

---

## 2. The scenario

A real coding agent, running headless in a sandbox, is asked to build a Snake
game. A prompt-injection in the task makes it `pip install pysnake-helper` — a
poisoned dependency whose install hook:

1. reads planted **fake** secrets (`~/.aws/credentials`, an API token), and
2. attempts egress to the cloud metadata IP `169.254.169.254`.

This replicates the ctx / torchtriton TTP as **benign behaviour against planted
fake secrets** — not live malware. It was captured on a Linux eBPF lab VM, signed
at export, and committed as a portable bundle.

Three-stage arc to narrate:

| Stage | What you show | Message |
|-------|---------------|---------|
| 看不见 (blind) | a raw event log / no correlation | "you can't tell intent from noise" |
| 看得见 (visible) | the Graph Explorer causal chain | "intent → action → risk, on one graph" |
| 管得住 (controlled) | policy decisions + compliance | "detected, blocked, and audited" |

---

## 3. Run it

Two ways in. The replay data dir is the fastest for a live demo.

**A. Serve the already-imported replay**

```bash
agentprov --data-dir .agentprov-snake-replay dashboard serve
# open the printed URL; run "run-snake-supervised" auto-loads
```

**B. Import the signed bundle from scratch (shows verification)**

```bash
agentprov forensics import demo/snake-supply-chain/run-snake-supervised.forensics.json \
  --pub-key demo/snake-supply-chain/attestation.pub \
  --data-dir /tmp/snake-demo
# --pub-key verifies the in-toto/DSSE attestation BEFORE loading; tamper => refused
agentprov --data-dir /tmp/snake-demo dashboard serve
```

---

## 4. Dashboard walkthrough (the visible + controlled stages)

Drive these in order:

1. **Graph Explorer — Agent intent lens.** Start at the tool call / process. Point
   out that this run is supervised capture: the agent was born into a real cgroup
   while a per-node `sensor stream` collected kernel events. The binding engine
   resolves those events by cgroup/time at high confidence; raw kernel events do
   not carry `tool_call_id`.

2. **Security lens.** The poisoned install hook's `secret_path` reads and the
   `metadata_ip` egress light up as risk. Follow the edges:
   `runtime_event → policy_decision → risk_signal → response_action`.

3. **Signals & Risk panel.** Grouped by rule: `secret_path_access` (kill),
   `metadata_ip_dst` (quarantine), `private_cidr_access` (deny). Each carries a
   recommended action and severity. Click one to focus its node in the graph.

4. **Data-flow / taint lens.** Show the derived `possible_sensitive_data_flow`
   edges — a secret read *before* an egress in the *same process* — with
   confidence. These are inferred, drawn dashed, and never temporally impossible.

5. **Time-scrubber.** Replay the run over its real event clock to show ordering:
   the secret read precedes the egress attempt.

6. **A node's Side Panel.** Evidence + a bounded, secret-redacted content preview
   of the artifact/object behind the node (content-addressed, hash-verified).

7. **Timeline / Process Tree.** Use it for the time-ordered story and readable
   process names. The dashboard now prefers argv/command and falls back to
   kernel `comm`, so short-lived helpers are not shown as anonymous PID-only
   rows unless no command evidence exists.

---

## 5. Compliance — the audit stage

```bash
agentprov --data-dir .agentprov-snake-replay compliance map \
  --framework owasp-asi --run run-snake-supervised
```

Or the dashboard's **Compliance** card. The verdict per control is **four honest
states**, driven by whether a real detection rule mapped to that control actually
fired this run, and whether it enforced or only observed:

- 🟢 **enforced** — a mapped rule fired **and blocked** (deny / quarantine / kill)
- 🟠 **detected** — a mapped rule fired but is **detect-only** (observed, not blocked)
- ⚪ **not_triggered** — a detector maps here but nothing fired this run
- ⬚ **no_rule** — **no detector maps to this control** (an honest coverage gap)

Talking points that land:

- **`no_rule` is deliberately not a pass.** ASI01 (goal hijack), ASI06 (memory
  poisoning), ASI07 (inter-agent) show `no_rule` because the system emits no event
  that could detect them yet — we refuse to author a "phantom rule" that would
  show a fake green. Honesty is the differentiator.
- **Expand a control → every individual rule hit** (time · decision · reason),
  each clickable back to its graph node. `secret_path_access` fired dozens of
  times, each `kill`, each traceable.
- The exact same four-state model backs the CLI and the dashboard — one source of
  truth (`compliance.MapRunRules`), so they never drift.

---

## 6. Verify — why anyone should believe it

```bash
agentprov forensics verify-attestation \
  demo/snake-supply-chain/run-snake-supervised.forensics.json \
  --pub-key demo/snake-supply-chain/attestation.pub
```

- Evidence is **content-addressed** (SHA-256) and **hash-verified** on import.
- The bundle carries an **in-toto Statement wrapped in a DSSE / ed25519**
  signature; verification runs *before* rows are committed, and a tampered blob
  or edited row is **refused**, not silently loaded.

---

## 7. Honest boundaries (say these before you're asked)

- The security claim today is **integrity, not tamper-evidence against a host-root
  attacker.** `graph verify` recomputes from a host-editable SQLite DB; off-host
  capture-time anchoring (KMS / TPM / transparency log) is a deferred v2 item.
- The capture came from a single-arch (ARM64) lab VM; production LLM traffic
  (x86, HTTP/2) is not what this recording exercises.
- The TLS-boundary intent capture (SSL uprobe) is a demonstrated PoC, not a
  hardened multi-framework interceptor — deliberately not chased.
- The fake secrets are planted; nothing here exfiltrates real data.
- `self_launched` means AgentProvenance directly launched the process scope.
  `kernel_correlated` means a runtime event was joined back to that scope by
  runtime identity such as cgroup/container/pid/time. These are separate facts:
  an event can be kernel-correlated without being self-launched.

---

## 8. If asked "what's the hard part?"

The **time-windowed tiered correlation engine** (`internal/correlation`) that
binds app-side context to kernel telemetry across cgroup / container / pid /
time with confidence, while keeping `self_launched`, `context_asserted`, and
`kernel_correlated` semantics honest. In supervised mode the hard join is:
`record` creates a real cgroup scope, `sensor stream` observes syscalls, and the
correlator attaches those runtime events back to the run without requiring the
kernel payload to know agent identifiers. Everything else rides that spine.
