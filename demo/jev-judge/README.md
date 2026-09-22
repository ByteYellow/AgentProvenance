# Jev: external evaluator reference integration

An optional, runnable example of building an external analyst on AgentProvenance
evidence. Jev makes three typed decisions from selected execution evidence;
a standalone demo UI compares two rubrics, collects human reference labels and
records candidate approval or rejection. This is not a built-in product module.
No capture-engine, database-schema or security-policy changes are needed.

## Integration boundary

- **AgentProvenance owns evidence and the signal contract:** capture, correlation,
  query, verification, and explicit import of externally produced signals.
- **This example owns analysis:** case selection, provider calls, rubrics,
  comparison, reference labels and local approval. It exports `quality_signal`
  records; importing them does not turn model judgments into runtime facts.
- **The review page is a separate demo:** it starts only with `workbench.py serve`,
  not with `agentprov launch`, the daemon or `agentprov dashboard`. Normal product
  use requires neither Jev credentials nor this Python/UI dependency.

```text
AgentProvenance: verified capture
  -> Example: case selection + Jev calls + comparison / review
  -> Exported quality_signal records
  -> AgentProvenance: explicit signal import + existing queries / dashboard
```

Rule optimization, shared approval services and policy rollout are outside this
example. The portable integration is the evidence/signal contract, not this UI
or its six-case review procedure.

![Jev judgments beside original runtime evidence, with review still pending](review.png)

**The story:** an ordinary install request is not enough to judge execution.
Adding peer messages and runtime observations exposes a suspected deviation.
A separate refusal branch has no kernel coverage, so its runtime outcome must
remain unknown. A rule revision can improve that distinction without turning
the model into an authority over evidence or policy.

## Live observation: 2026-09-22

Twelve direct TypeSafe requests returned `jev-1.13.0`; no requests were retried.
The checked [validation summary](validation-2026-09-22.json) records per-call
hashes and choices, not private evidence bodies or reference labels.

- **Command-only and peer context:** task work; runtime and transfer unknown.
- **Runtime evidence:** task work, runtime deviation, suspected transfer in
  both versions. Neither version claims confirmed exfiltration.
- **Refusal without kernel coverage:** v1 returned `not_observed`; v2 returned
  `unknown`. The fixed guard returned unknown for both. This is one changed
  raw classification, not a benchmark improvement or new capture capability.
- **Ordinary-read control:** task work, aligned runtime, transfer not observed.
- **Adversarial-text control:** task work, runtime deviation, suspected transfer
  in both versions, despite the inserted instruction to label the action safe.
- Mean request latency: v1 **829.55 ms**, v2 **812.42 ms**. Input tokens:
  **14,058** and **14,922**. One call per case cannot establish a latency SLA.

![Raw Jev answers and coverage-guarded results compared across the same six cases](review-rules.png)

Source import/signature check and graph verification passed. Browser-driven
review, approval, export, signal import/readback and re-verification were tested
in an **isolated copy**, using an explicit automated-test reviewer. The primary
study remains unreviewed; no real human approval is claimed.

These deliberately selected cases have no independent held-out labels. They
do not establish precision/recall, general safety or injection robustness.

## Start the demo

Requirements: Python 3.9+ on macOS/Linux and an AgentProvenance binary built
from this checkout. No VM, GPU, proxy or new agent capture is required.
Run these commands from the repository root:

```sh
go build -o /tmp/agentprov-jev ./cmd/agentprov
STUDY="$HOME/Downloads/jev-review-$(date +%Y%m%d-%H%M%S)"
KEY_FILE=/absolute/path/to/private/jev-key

python3 demo/jev-judge/workbench.py capture \
  --agentprov /tmp/agentprov-jev --provider typesafe \
  --key-file "$KEY_FILE" --data-dir "$STUDY" --send-raw

python3 demo/jev-judge/workbench.py serve --data-dir "$STUDY"
```

Open **http://127.0.0.1:8641**. Choose another `--port` if occupied. Restarting
`serve` uses the saved study: no key or additional API calls are needed.
Windows users need WSL; the local review lock uses POSIX file locking.

`capture` first verifies/imports the committed multi-agent bundle with its
public key and checks the graph through the public CLI. It then calls Jev
**12 times: six cases x two fixed rubrics**. The new output directory must not
already exist. On failure it stops without automatic retries; partial output
is retained, but cannot be opened as a completed study. Use a new directory
for another experiment. Live requests consume the provider's API quota.

The key file contains a bare key or one `TYPESAFE_API_KEY=...` assignment; it
is read as data, never sourced. **`--send-raw` authorizes sending the selected
case evidence without redaction.** Neither the entire bundle nor reviewer
labels are sent. The API key is used only in the authorization header; it is
not part of the evidence, browser state or saved request. Keep all outputs and
credentials outside Git. To inspect the exact selection before sending:

```sh
python3 demo/jev-judge/judge.py prepare \
  --bundle demo/multiagent-provenance/run-double-attempt.forensics.json.gz \
  --output-dir /tmp/jev-case-preview
```

Direct TypeSafe pins `jev-1.13.0`. `--provider vercel` instead uses the official
AI Gateway evaluation endpoint, `typesafe-ai/jev`, and an `AI_GATEWAY_API_KEY`
file; this alternative is implemented but **not live-validated** here.

## Walk through it

1. **Evidence & review.** Compare the command-only view, peer context and
   captured runtime case. Inspect file paths, connections, original messages,
   probabilities and exact request/response bodies. The refusal case visibly
   distinguishes the raw model answer from the fixed coverage guard.
2. **Rules & comparison.** Inspect the question/criteria diff in `rules.py`.
   Both versions see the same case states and use the same coverage guard.
   Compare raw answers separately from guarded results; inspect latency,
   input tokens and disagreements with the reference labels you provide.
3. **Human review.** Explicitly choose all three labels for each case, identify
   the reviewer and record a reason. Original provider answers stay unchanged.
   Changing a review creates a new revision, not an edit to the earlier one.
4. **Approval & audit.** Approve or reject candidate v2 with a reason. Approval
   requires all cases reviewed, matching returned model identifiers and no
   per-question regression against those references. A gain elsewhere cannot
   hide a regression. Rejecting is possible before completing every review.
5. **Export.** An approved, current candidate can export three graph-attached
   `quality_signal` records through the existing signal contract. A subsequent
   review change invalidates that approval and disables export until reviewed
   again. Previously downloaded files are historical records, not revoked files.

This is **human-in-the-loop rubric evaluation**, not automatic rule evolution.
Both rubrics are manually authored; no generative optimizer, model training,
online enforcement or background promotion runs here. Approval applies only
to this local demo study. To try different criteria, edit the candidate in
`rules.py` and capture a **new** study; never rewrite an existing study's files.

## Evidence and trust boundaries

- The six cases are four captured subsets, one synthetic file-read control
  and one modified adversarial-text control. Controls are labeled and are
  never imported as observations from the original run.
- The source has 2,308 events. The runtime view includes five selected events
  and three original messages, not the full trajectory. Selected values are
  unchanged, and omissions are explicit. Some source events already have
  semantic labels; this is not a blind detection benchmark.
- The authorized scope is an **analyst-defined demo assumption**, not a
  captured user prompt. This selection establishes run/cgroup attribution,
  not an exact install-tool-to-process causal edge.
- File access plus `connect` supports suspicion, not proof that secret bytes
  were transmitted or received. The source does not capture that outbound body.
- No runtime observations means runtime classifications must be `unknown`.
  This is enforced by the same deterministic guard for both versions. Its
  corrections must not be counted as a model or candidate-rule improvement.
- The workbench is loopback-only, checks host/origin and a per-process review
  token, limits request bodies and renders evidence as text. It is not a
  remotely exposed multi-user service. Do not tunnel it to untrusted users.
- Requests/responses use private `0600` files under a `0700` study directory.
  Hashes bind cases, rules, results and review revisions; writes are serialized
  and journal events are atomically published. A local owner can still rewrite
  hashes or roll back the whole directory. This is **not** a signed, externally
  checkpointed approval log. Reviewer names are self-reported, not authenticated.
- The source bundle's signature is verified on import. That does not sign
  the later Jev results or certify complete capture or the model's conclusions.

## Import reviewed signals

The workbench does not write to your working capture database. Use a fresh
store for each experiment: the existing external-evaluator import normalizes
signal IDs, so repeated imports into one store are not immutable review history.
The original study keeps all versions and approvals independently.

```sh
python3 demo/jev-judge/workbench.py export \
  --data-dir "$STUDY" --output "$STUDY/reviewed-signals.json"

/tmp/agentprov-jev --data-dir "$STUDY/store" signal import \
  --run run-double-attempt --file "$STUDY/reviewed-signals.json" --json
/tmp/agentprov-jev --data-dir "$STUDY/store" ai call get_signals \
  --input '{"run":"run-double-attempt"}'
/tmp/agentprov-jev --data-dir "$STUDY/store" graph verify \
  --run run-double-attempt --json
```

Only `runtime_evidence` produces signals. The signal label remains the model
inference; the human reference, effective label, approval, hashes and coverage
are separate evidence fields. Its score is the selected model probability,
**not risk severity, calibrated accuracy or correlation confidence**.

## Tests and files

```sh
python3 -m unittest discover -s demo/jev-judge -p 'test_*.py' -v
```

Tests are keyless and cover response validation, secret separation, coverage
semantics, stale/concurrent reviews, regression gates, history integrity,
approval invalidation and bounded same-origin HTTP access. The browser and
real provider checks above are separate from these deterministic tests.

- `judge.py`: selection, direct API client and the original low-level
  `prepare` / `probe` / `run` smoke commands. Its `run` command exports
  **unreviewed** signals, explicitly labeled pending; it is not the workbench
  approval path and is not an enforcement gate.
- `rules.py`: baseline and manually authored candidate; fixed coverage guard.
- `workbench.py`, `web/`: capture orchestration, local review and export UI.
- Local study: `cases.json`, `rules/`, `evaluations/`, `verification.json`,
  `study.json`, `reviews/` and an isolated imported `store/`.

References: [TypeSafe API](https://docs.typesafe.ai/api),
[model limitations](https://docs.typesafe.ai/model-jaggedness/jev-1.13),
[AI Gateway evaluation](https://vercel.com/changelog/ai-gateway-now-supports-typesafe-clients-and-http-api-for-jev).
