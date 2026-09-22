"use strict";

const $ = (query, scope = document) => scope.querySelector(query);
const names = {
  install_command_only: ["01", "Command only", "Captured declaration"],
  install_peer_context: ["02", "Peer context", "Original messages"],
  runtime_evidence: ["03", "Runtime evidence", "5 events + 3 messages"],
  refusal_coverage_gap: [
    "04",
    "Refusal, missing coverage",
    "No kernel observations",
  ],
  normal_read_control: ["05", "Ordinary file read", "Synthetic control"],
  adversarial_context: ["06", "Adversarial tool output", "Modified control"],
};
const questions = {
  declared_action: "Declared action",
  runtime_conformance: "Runtime conformance",
  secret_transfer: "Secret transmission",
};
const labels = {
  task_work: "Task work",
  refusal: "Refusal",
  credential_transfer: "Credential transfer",
  unknown: "Unknown",
  aligned: "Aligned",
  deviation: "Deviation",
  confirmed: "Confirmed",
  suspected: "Suspected",
  not_observed: "Not observed",
};
let state,
  selected = "runtime_evidence",
  view = "evidence",
  busy = false;
let compareQuestion = "secret_transfer",
  compareMode = "raw",
  toastTimer;
const drafts = {};
let decisionDraft;

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined && text !== null) element.textContent = text;
  if (className) element.className = className;
  return element;
}
function badge(text, color = "neutral") {
  return node("span", text, "badge " + color);
}
function tone(choice) {
  return (
    {
      deviation: "red",
      confirmed: "red",
      suspected: "amber",
      credential_transfer: "amber",
      unknown: "neutral",
    }[choice] || "green"
  );
}
function titleLine(title, trailing) {
  const line = node("div", null, "title-line");
  line.append(node("h3", title));
  if (trailing) line.append(trailing);
  return line;
}
function details(title, content, raw = false) {
  const element = node("details");
  element.append(
    node("summary", title),
    node(
      raw ? "pre" : "p",
      typeof content === "string" ? content : JSON.stringify(content, null, 2),
    ),
  );
  return element;
}
function button(text, action, style = "") {
  const element = node("button", text, "button " + style);
  element.type = "button";
  element.addEventListener("click", action);
  return element;
}
function field(title, input) {
  const element = node("label", null, "field");
  element.append(node("span", title), input);
  return element;
}
function input(name, placeholder, required = true, area = false) {
  const element = node(area ? "textarea" : "input");
  element.name = name;
  element.placeholder = placeholder;
  element.required = required;
  element.maxLength = area ? 3000 : 80;
  if (name === "reviewer")
    element.value = localStorage.getItem("jev-reviewer") || "";
  return element;
}
function toast(message) {
  clearTimeout(toastTimer);
  $("#toast").textContent = message;
  $("#toast").hidden = false;
  toastTimer = setTimeout(() => ($("#toast").hidden = true), 3500);
}
function error(message) {
  $("#error").textContent = message;
  $("#error").hidden = !message;
}
function isApproved() {
  return (
    state.decision_current &&
    state.decision?.status === "approved" &&
    state.approval_blockers.length === 0
  );
}

async function post(path, body) {
  if (busy) return;
  busy = true;
  error("");
  const submitters = [...document.querySelectorAll("button[type=submit]")];
  submitters.forEach((b) => (b.disabled = true));
  try {
    const response = await fetch(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Review-Token": state.csrf_token,
      },
      body: JSON.stringify({ ...body, revision: state.revision }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not save review");
    state = data;
    delete drafts[body.case_id];
    if (path.includes("decision")) decisionDraft = null;
    localStorage.setItem("jev-reviewer", body.reviewer);
    render();
    toast(
      path.includes("decision")
        ? "Decision recorded. No policy was deployed."
        : "Review saved. Original model answers are unchanged.",
    );
  } catch (e) {
    error(e.message);
  } finally {
    busy = false;
    submitters.forEach((b) => (b.disabled = false));
  }
}

function render() {
  $("#loading").hidden = true;
  $("#content").hidden = false;
  const models = [
    ...new Set([...state.metrics.v1.models, ...state.metrics.v2.models]),
  ].join(", ");
  $("#run-meta").textContent = state.study.run_id;
  $("#run-meta").hidden = false;
  $("#model-meta").textContent =
    models +
    (state.study.evaluation_kind === "live_provider" ? "" : " / test fixture");
  $("#model-meta").hidden = false;
  $("#model-meta").title =
    state.study.evaluation_kind === "live_provider"
      ? `${state.cases.length * 2} saved API responses; no calls are made while reviewing`
      : "Test fixture, not live API results";
  const verified =
    state.verification.status === "ok" && state.verification.error_count === 0;
  const source = $("#source-status");
  source.hidden = false;
  source.className = "source-status " + (verified ? "green" : "red");
  source.title =
    "Verification applies to the source capture, not the model judgments or local review.";
  source.replaceChildren(
    node("span", null, "status-dot"),
    node("strong", verified ? "Source verified" : "Source verification failed"),
    node(
      "span",
      `${state.verification.error_count} errors / ${state.verification.warning_count} warnings`,
      "source-counts",
    ),
  );
  const status = !state.decision
    ? "Candidate pending"
    : !state.decision_current
      ? "Review changed"
      : state.decision.status === "approved"
        ? "Candidate approved"
        : "Candidate rejected";
  $("#approval-status").replaceChildren(
    node(
      "span",
      `${state.reviewed_cases}/${state.cases.length} reviewed`,
      "muted",
    ),
    badge(status, isApproved() ? "green" : "amber"),
  );
  document
    .querySelectorAll(".tabs button")
    .forEach((b) =>
      b.setAttribute(
        "aria-current",
        b.dataset.view === view ? "page" : "false",
      ),
    );
  for (const item of ["evidence", "rules", "approval"])
    $("#" + item + "-view").hidden = item !== view;
  renderCases();
  renderCase();
  renderRules();
  renderApproval();
}

function renderCases() {
  $("#case-count").textContent = `${state.cases.length} cases`;
  $("#case-list").replaceChildren(
    ...state.cases.map((c) => {
      const [number, title, subtitle] = names[c.id] || ["", c.id, c.origin];
      const item = node("button", null, "case-button");
      item.type = "button";
      item.setAttribute("aria-pressed", c.id === selected);
      const words = node("span", null, "case-words");
      words.append(
        node("strong", title),
        node("small", c.review ? "Reviewed" : subtitle),
      );
      if (c.review) item.title = "Reviewed by " + c.review.reviewer;
      item.append(node("span", number, "case-number"), words);
      item.addEventListener("click", () => {
        selected = c.id;
        error("");
        renderCases();
        renderCase();
      });
      return item;
    }),
  );
}

function renderCase() {
  const c = state.cases.find((c) => c.id === selected),
    container = $("#case-content");
  container.replaceChildren();
  const heading = node("div", null, "case-title");
  heading.append(
    node("h2", names[c.id]?.[1] || c.id),
    badge(
      c.origin.replaceAll("_", " "),
      c.origin === "captured_subset" ? "blue" : "amber",
    ),
  );
  container.append(heading);
  const declaration = node("section", null, "section scope");
  declaration.append(
    titleLine("Authorized scope", badge("Analyst-defined demo assumption")),
    node("p", c.state.authorized_scope.text),
  );
  const command = node("div", null, "command-block");
  command.append(node("span", "Declared action", "command-label"));
  command.append(
    node(
      "pre",
      c.state.declared_action.command ||
        JSON.stringify(c.state.declared_action),
      "command",
    ),
  );
  declaration.append(
    command,
    details("Scope provenance", c.state.authorized_scope, true),
  );
  container.append(declaration);
  const judgments = $("#judgment-content");
  judgments.replaceChildren();
  judgments.append(
    titleLine("Jev judgments", badge("Inference", "blue")),
    node("p", "Raw answers / selected model probability", "judgment-caption"),
  );
  const grid = node("div", null, "judgment-list");
  for (const [q, label] of Object.entries(questions)) {
    const row = node("section", null, "judgment-row");
    row.append(node("h4", label));
    const pair = node("div", null, "judgment-pair");
    for (const version of ["v1", "v2"]) {
      const r = c.evaluations[version],
        a = r.answers[q],
        cell = node("div", null, "judgment-answer");
      cell.append(
        node(
          "small",
          version === "v1" ? "Baseline v1" : "Candidate v2",
          "answer-version",
        ),
      );
      const result = node("div", null, "answer-result");
      result.append(badge(labels[a.choice], tone(a.choice)));
      result.append(
        node(
          "span",
          `${(a.probabilities[a.choice] * 100).toFixed(0)}%`,
          "probability",
        ),
      );
      cell.append(result);
      if (r.effective.overrides[q])
        cell.append(node("span", "Coverage guard: Unknown", "guard"));
      pair.append(cell);
    }
    row.append(pair);
    grid.append(row);
  }
  judgments.append(grid);
  const links = node("div", null, "detail-links");
  for (const version of ["v1", "v2"])
    for (const file of ["request", "response"]) {
      const link = node("a", `${version} raw ${file}`);
      link.href = `/api/artifact/${version}/${c.id}/${file}.json`;
      link.target = "_blank";
      link.rel = "noopener";
      links.append(link);
    }
  const modelDetails = node("div", null, "model-details");
  modelDetails.append(
    links,
    details("Model details & fingerprints", c.evaluations, true),
  );
  judgments.append(modelDetails);
  const evidence = node("section", null, "section");
  evidence.append(
    titleLine(
      "Execution evidence",
      badge(`${c.state.runtime_events.length} observations`, "blue"),
    ),
  );
  if (c.state.runtime_events.length) {
    const list = node("ol", null, "event-list");
    for (const event of c.state.runtime_events) {
      let payload = event.payload || {};
      if (typeof payload === "string") {
        try {
          payload = JSON.parse(payload);
        } catch {
          payload = {};
        }
      }
      const raw = payload.payload?.raw || {},
        target =
          raw.path ||
          raw.dst_ip ||
          event.path ||
          raw.filename ||
          raw.command ||
          event.command ||
          raw.comm ||
          event.id ||
          "process event";
      const item = node("li"),
        body = node("div"),
        kind = event.event_type || event.operation;
      const eventTitle = node("div", null, "event-title");
      eventTitle.append(node("span", kind, "event-kind"));
      if (event.pid)
        eventTitle.append(node("span", `PID ${event.pid}`, "event-pid"));
      body.append(eventTitle);
      body.append(
        node(
          "code",
          String(target) +
            (raw.dst_port || raw.port ? ":" + (raw.dst_port || raw.port) : "") +
            (raw.exit_code !== undefined ? " / exit " + raw.exit_code : ""),
        ),
        node(
          "small",
          event.pid ? `cgroup ${event.cgroup_id} / ${event.id}` : event.source,
        ),
      );
      item.append(
        node(
          "span",
          null,
          "dot" +
            (["secret_path", "metadata_ip"].includes(kind) ? " risk" : ""),
        ),
        body,
      );
      list.append(item);
    }
    evidence.append(list);
  } else
    evidence.append(
      node(
        "p",
        "No runtime observations in this case. A declaration is not execution evidence.",
        "muted small",
      ),
    );
  container.append(evidence);
  const context = node("section", null, "section context");
  context.append(
    titleLine(
      "Application context",
      badge(`${c.state.peer_messages?.length || 0} peer messages`),
    ),
  );
  if (c.state.peer_messages)
    for (const [index, msg] of c.state.peer_messages.entries())
      context.append(
        details(
          `Peer message ${index + 1}`,
          msg.object?.payload?.body || msg,
          typeof msg.object?.payload?.body !== "string",
        ),
      );
  if (c.state.untrusted_tool_output)
    context.append(
      details(
        "Injected tool-output control (untrusted)",
        c.state.untrusted_tool_output,
      ),
    );
  context.append(
    details(
      "Selected evidence / original values",
      { state: c.state, evidence_ids: c.evidence_ids },
      true,
    ),
  );
  container.append(context);
  const coverage = node("section", null, "coverage-note");
  coverage.append(
    titleLine("Attribution & coverage", badge("Limited", "amber")),
    node(
      "p",
      typeof c.state.coverage === "string"
        ? c.state.coverage
        : c.state.coverage.attribution.replaceAll("_", " ") +
            ". Outbound payload not captured.",
    ),
  );
  container.insertBefore(coverage, evidence);
  const form = $("#review-form");
  form.replaceChildren(
    titleLine(
      "Human review",
      c.review ? badge("Reviewed", "green") : badge("Pending"),
    ),
  );
  const fields = node("div", null, "fields");
  for (const [q, title] of Object.entries(questions)) {
    const select = node("select");
    select.name = q;
    select.required = true;
    const placeholder = node("option", "Choose a reference label");
    placeholder.value = "";
    select.append(placeholder);
    for (const label of Object.keys(state.profiles.v1.questions[q].criteria)) {
      const option = node("option", labels[label]);
      option.value = label;
      select.append(option);
    }
    select.value = drafts[c.id]?.[q] ?? c.review?.labels[q] ?? "";
    fields.append(field(title, select));
  }
  const lower = node("div", null, "review-lower"),
    reviewer = input("reviewer", "Reviewer name"),
    reason = input(
      "reason",
      "Evidence and rationale for your labels",
      true,
      true,
    );
  if (c.review) {
    reviewer.value = c.review.reviewer;
    reason.value = c.review.reason;
  }
  if (drafts[c.id]) {
    reviewer.value = drafts[c.id].reviewer;
    reason.value = drafts[c.id].reason;
  }
  lower.append(
    field("Reviewer (self-reported)", reviewer),
    field("Review rationale", reason),
  );
  const actions = node("div", null, "form-actions"),
    submit = node(
      "button",
      c.review ? "Save a new review revision" : "Save review",
      "button primary",
    );
  submit.type = "submit";
  actions.append(
    node("span", "Reference labels stay separate from model output.", "muted"),
    submit,
  );
  form.append(fields, lower, actions);
  form.oninput = () => {
    drafts[c.id] = Object.fromEntries(new FormData(form));
  };
  form.onsubmit = (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(form));
    post("/api/review", {
      case_id: c.id,
      labels: Object.fromEntries(
        Object.keys(questions).map((q) => [q, data[q]]),
      ),
      reviewer: data.reviewer,
      reason: data.reason,
    });
  };
}

function renderRules() {
  const container = $("#rules-view");
  container.replaceChildren();
  const layout = node("div", null, "rules-layout"),
    main = node("div", null, "rules-main"),
    sidebar = node("aside", null, "rules-sidebar"),
    description = node("section", null, "panel candidate-panel"),
    metrics = node("section", null, "panel");
  description.append(
    titleLine("Candidate v2", badge("Manual revision", "blue")),
    node("p", state.profiles.v2.description, "small"),
  );
  description.append(
    node(
      "div",
      "The runtime-coverage guard is fixed for BOTH versions. Its corrections are not evidence that Jev or the candidate rule improved.",
      "notice",
    ),
    node(
      "p",
      "Same six cases, one call per version. Selected examples, not a held-out benchmark.",
      "muted small",
    ),
  );
  metrics.append(
    titleLine(
      "Observed comparison",
      badge(`${state.cases.length * 2} saved calls`),
    ),
  );
  const rows = [
    ["", "Baseline v1", "Candidate v2"],
    [
      "Mean API latency",
      ...["v1", "v2"].map((v) => state.metrics[v].mean_latency_ms + " ms"),
    ],
    [
      "Input tokens",
      ...["v1", "v2"].map((v) =>
        state.metrics[v].input_tokens.toLocaleString(),
      ),
    ],
    [
      "Raw disagreements",
      ...["v1", "v2"].map((v) =>
        state.reviewed_cases
          ? `${state.metrics[v].raw_disagreements} / ${state.metrics[v].reviewed_decisions}`
          : "Not reviewed",
      ),
    ],
    [
      "After coverage guard",
      ...["v1", "v2"].map((v) =>
        state.reviewed_cases
          ? `${state.metrics[v].effective_disagreements} / ${state.metrics[v].reviewed_decisions}`
          : "Not reviewed",
      ),
    ],
    [
      "Guard overrides",
      state.metrics.v1.guard_overrides,
      state.metrics.v2.guard_overrides,
    ],
  ];
  rows.forEach((cells, i) => {
    const row = node("div", null, "metric-row" + (i === 0 ? " head" : ""));
    cells.forEach((text) => row.append(node("span", text)));
    metrics.append(row);
  });
  sidebar.append(description, metrics);
  const diff = node("section", null, "panel diff-panel");
  diff.append(titleLine("Question & criteria diff", badge("v1 → v2")));
  const pre = node("pre", null, "rule-diff");
  for (const line of state.rule_diff.split("\n"))
    pre.append(
      node(
        "span",
        line || " ",
        "diff-line" +
          (line.startsWith("+")
            ? " diff-add"
            : line.startsWith("-")
              ? " diff-remove"
              : line.startsWith("@@")
                ? " diff-hunk"
                : ""),
      ),
    );
  diff.append(pre, details("Rule fingerprints", state.study.profiles, true));
  main.append(diff);
  const comparison = node("section", null, "panel comparison-panel");
  comparison.append(
    titleLine("Case-by-case comparison", badge("Same evidence")),
  );
  const controls = node("div", null, "compare-controls"),
    select = node("select"),
    mode = node("select");
  select.setAttribute("aria-label", "Comparison question");
  for (const [q, label] of Object.entries(questions)) {
    const option = node("option", label);
    option.value = q;
    select.append(option);
  }
  select.value = compareQuestion;
  mode.setAttribute("aria-label", "Comparison layer");
  for (const [key, label] of [
    ["raw", "Raw model answer"],
    ["effective", "After fixed coverage guard"],
  ]) {
    const option = node("option", label);
    option.value = key;
    mode.append(option);
  }
  mode.value = compareMode;
  select.onchange = () => {
    compareQuestion = select.value;
    renderRules();
  };
  mode.onchange = () => {
    compareMode = mode.value;
    renderRules();
  };
  controls.append(select, mode);
  comparison.append(controls);
  const scroll = node("div", null, "table-scroll"),
    table = node("table"),
    head = node("thead"),
    tr = node("tr");
  for (const text of ["Case", "Baseline v1", "Candidate v2", "Human reference"])
    tr.append(node("th", text));
  head.append(tr);
  table.append(head);
  const body = node("tbody");
  for (const c of state.cases) {
    const choices = ["v1", "v2"].map((v) =>
      compareMode === "raw"
        ? c.evaluations[v].answers[compareQuestion].choice
        : c.evaluations[v].effective.choices[compareQuestion],
    );
    const row = node("tr", null, choices[0] !== choices[1] ? "changed" : ""),
      name = node("td", names[c.id]?.[1] || c.id);
    name.append(node("small", c.origin));
    row.append(name);
    choices.forEach((choice) => {
      const cell = node("td");
      cell.append(badge(labels[choice], tone(choice)));
      row.append(cell);
    });
    row.append(
      node(
        "td",
        c.review ? labels[c.review.labels[compareQuestion]] : "Pending",
      ),
    );
    body.append(row);
  }
  table.append(body);
  scroll.append(table);
  comparison.append(scroll);
  main.append(comparison);
  layout.append(main, sidebar);
  container.append(layout);
}

function renderApproval() {
  const container = $("#approval-view");
  container.replaceChildren();
  const layout = node("div", null, "two-col"),
    panel = node("section", null, "panel approval-panel"),
    audit = node("section", null, "panel audit-panel");
  panel.append(
    titleLine(
      "Candidate v2",
      badge(
        isApproved() ? "Approved" : "Not promoted",
        isApproved() ? "green" : "amber",
      ),
    ),
    node(
      "p",
      "Approval binds this rule, these API results and the current reference labels. It does not deploy a policy or modify source evidence.",
      "muted small",
    ),
  );
  const checks = node("ul", null, "checklist");
  checks.append(
    node(
      "li",
      `${state.reviewed_cases} / ${state.cases.length} cases reviewed`,
      state.reviewed_cases === state.cases.length ? "pass" : "",
    ),
  );
  for (const text of state.approval_blockers) checks.append(node("li", text));
  if (!state.approval_blockers.length)
    checks.append(
      node(
        "li",
        "Review gate passed. Approval is still a human decision.",
        "pass",
      ),
    );
  panel.append(checks);
  if (state.decision && !state.decision_current)
    panel.append(
      node(
        "div",
        "Reviews changed after the last decision. A new decision is required before export.",
        "notice",
      ),
    );
  const form = node("form", null, "decision-form"),
    reviewer = input("reviewer", "Reviewer name"),
    reason = input(
      "reason",
      "Why approve or reject this candidate?",
      true,
      true,
    );
  if (decisionDraft) {
    reviewer.value = decisionDraft.reviewer;
    reason.value = decisionDraft.reason;
  }
  form.append(
    field("Reviewer (self-reported)", reviewer),
    field("Decision rationale", reason),
  );
  form.oninput = () => {
    decisionDraft = Object.fromEntries(new FormData(form));
  };
  const actions = node("div", null, "form-actions"),
    reject = node("button", "Reject candidate", "button danger"),
    approve = node("button", "Approve candidate", "button primary");
  reject.type = approve.type = "submit";
  reject.value = "rejected";
  approve.value = "approved";
  approve.disabled = state.approval_blockers.length > 0;
  approve.title = state.approval_blockers.join("; ");
  actions.append(reject, approve);
  form.append(actions);
  form.onsubmit = (e) => {
    e.preventDefault();
    post("/api/decision", {
      reviewer: reviewer.value,
      reason: reason.value,
      status: e.submitter?.value,
    });
  };
  panel.append(form);
  const exportButton = button("Download approved signals", async () => {
    try {
      const response = await fetch("/api/signals");
      if (!response.ok) throw new Error("Current approval required");
      const blob = await response.blob(),
        url = URL.createObjectURL(blob),
        link = node("a");
      link.href = url;
      link.download = "jev-reviewed-signals.json";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      error(e.message);
    }
  });
  exportButton.disabled = !isApproved();
  exportButton.style.marginTop = "20px";
  panel.append(exportButton);
  audit.append(
    titleLine(
      "Append-only review journal",
      badge(state.audit.length + " events"),
    ),
    node(
      "p",
      "Local file history with hashes; reviewer names are self-reported. This is not an authenticated or signed approval service.",
      "muted small",
    ),
  );
  const list = node("ol", null, "journal");
  if (!state.audit.length)
    list.append(node("li", "No human reviews or decisions yet.", "muted"));
  for (const event of [...state.audit].reverse()) {
    const li = node("li"),
      meta = node("div", null, "meta");
    meta.append(
      node(
        "strong",
        `#${event.revision} ${event.kind === "review" ? names[event.case_id]?.[1] || event.case_id : "Candidate " + event.status}`,
      ),
      node("span", event.reviewer, "muted"),
    );
    li.append(
      meta,
      node("small", new Date(event.at).toLocaleString(), "muted"),
      node("p", event.reason),
      details("Recorded event", event, true),
    );
    list.append(li);
  }
  audit.append(list);
  layout.append(panel, audit);
  container.append(
    layout,
    details("Immutable study fingerprints", state.study, true),
  );
}

document.querySelectorAll(".tabs button").forEach((b) =>
  b.addEventListener("click", () => {
    view = b.dataset.view;
    error("");
    render();
  }),
);
fetch("/api/state")
  .then(async (response) => {
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Study unavailable");
    state = data;
    render();
  })
  .catch((e) => {
    $("#loading").hidden = true;
    error(e.message);
  });
