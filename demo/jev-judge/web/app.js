"use strict";
(async () => {
let language = document.documentElement.lang;
let catalog = {};
try {
  const response = await fetch("/i18n.json");
  if (!response.ok) throw new Error("catalog");
  catalog = await response.json();
} catch {
  document.querySelector("#error").textContent = language === "zh-CN"
    ? "语言资源加载失败，请刷新页面。" : "Language resources could not be loaded. Reload this page.";
  document.querySelector("#error").hidden = false;
  document.querySelector("#loading").hidden = true;
  return;
}
let lastError = "";
function t(source, values = {}) {
  const text = language === "zh-CN" ? (catalog[source] ?? source) : source;
  return text.replace(/\{(\w+)\}/g, (match, key) => Object.prototype.hasOwnProperty.call(values, key) ? String(values[key]) : match);
}
function diagnostic(source) {
  if (source.includes("; ") && source.split("; ").every(part => Object.prototype.hasOwnProperty.call(catalog, part)))
    return source.split("; ").map(part => t(part)).join(language === "zh-CN" ? "；" : "; ");
  return t(source);
}
function readReviewer() { try { return localStorage.getItem("jev-reviewer"); } catch { return ""; } }
function saveReviewer(value) { try { localStorage.setItem("jev-reviewer", value); } catch {} }
function staticCopy() {
  document.querySelectorAll("[data-i18n]").forEach(element => { element.textContent = t(element.dataset.i18n); });
  document.querySelectorAll("[data-i18n-aria-label]").forEach(element => { element.setAttribute("aria-label", t(element.dataset.i18nAriaLabel)); });
  document.title = t("Jev Demo | AgentProvenance");
  document.querySelector("#language").value = language;
}
function readingGuide(original, title) {
  if (language !== "zh-CN" || !Object.prototype.hasOwnProperty.call(catalog, original)) return node("p", original);
  const container = node("div", null, "reading-guide");
  container.append(node("small", t("Chinese reading guide; original text below"), "muted"), node("p", t(original)), details(t(title), original));
  return container;
}
staticCopy();
document.querySelector("#language").addEventListener("change", async event => {
  const selectedLanguage = event.target.value;
  const url = new URL(location.href);
  url.searchParams.set("lang", selectedLanguage);
  try {
    const response = await fetch(url); // Server remembers only an explicit language selection.
    if (!response.ok) throw new Error("Could not change language");
    language = selectedLanguage;
    document.documentElement.lang = language;
    history.replaceState(null, "", url);
    staticCopy();
    if (state) render(); // Inputs and tab selection survive; draft values are never translated.
    error(lastError);
    document.querySelector("#toast").hidden = true;
  } catch (e) { event.target.value = language; error(e.message); }
});

const $ = (query, scope = document) => scope.querySelector(query);
const names = () => ({
  install_command_only: ["01", t("Command only"), t("Captured declaration")],
  install_peer_context: ["02", t("Peer context"), t("Original messages")],
  runtime_evidence: ["03", t("Runtime evidence"), t("5 events + 3 messages")],
  refusal_coverage_gap: [
    "04",
    t("Refusal, missing coverage"),
    t("No kernel observations"),
  ],
  normal_read_control: ["05", t("Ordinary file read"), t("Synthetic control")],
  adversarial_context: ["06", t("Adversarial tool output"), t("Modified control")],
});
const questions = () => ({
  declared_action: t("Declared action"),
  runtime_conformance: t("Runtime conformance"),
  secret_transfer: t("Secret transmission"),
});
const labels = () => ({
  task_work: t("Task work"),
  refusal: t("Refusal"),
  credential_transfer: t("Credential transfer"),
  unknown: t("Unknown"),
  aligned: t("Aligned"),
  deviation: t("Deviation"),
  confirmed: t("Confirmed"),
  suspected: t("Suspected"),
  not_observed: t("Not observed"),
});
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
    element.value = readReviewer() || "";
  return element;
}
function toast(message) {
  clearTimeout(toastTimer);
  $("#toast").textContent = message;
  $("#toast").hidden = false;
  toastTimer = setTimeout(() => ($("#toast").hidden = true), 3500);
}
function error(message) {
  lastError = message;
  $("#error").textContent = diagnostic(message);
  $("#error").hidden = !message;
}
function isApproved() {
  return (
    state.decision_current &&
    state.decision?.status === "approved" &&
    state.approval_blockers.length === 0
  );
}

async function readResponse(response) {
  try { return await response.json(); }
  catch { throw new Error("Malformed local server response"); }
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
    const data = await readResponse(response);
    if (!response.ok) throw new Error(data.error || "Could not save review");
    state = data;
    delete drafts[body.case_id];
    if (path.includes("decision")) decisionDraft = null;
    saveReviewer(body.reviewer);
    render();
    toast(
      path.includes("decision")
        ? t("Decision recorded. No policy was deployed.")
        : t("Review saved. Original model answers are unchanged."),
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
    (state.study.evaluation_kind === "live_provider" ? "" : t(" / test fixture"));
  $("#model-meta").hidden = false;
  $("#model-meta").title =
    state.study.evaluation_kind === "live_provider"
      ? t("{count} saved API responses; no calls are made while reviewing", {count: state.cases.length * 2})
      : t("Test fixture, not live API results");
  const verificationFixture = state.verification.source === "test_fixture_not_signature_verification";
  const verified =
    state.verification.status === "ok" && state.verification.error_count === 0;
  const source = $("#source-status");
  source.hidden = false;
  source.className = "source-status " + (verificationFixture ? "blue" : verified ? "green" : "red");
  source.title =
    t("Verification applies to the source capture, not the model judgments or local review.");
  source.replaceChildren(
    node("span", null, "status-dot"),
    node("strong", verificationFixture ? t("Test verification result") : verified ? t("Source verified") : t("Source verification failed")),
    node(
      "span",
      t("{errors} errors / {warnings} warnings", {errors: state.verification.error_count, warnings: state.verification.warning_count || 0}),
      "source-counts",
    ),
  );
  const status = !state.decision
    ? t("Candidate pending")
    : !state.decision_current
      ? t("Review changed")
      : state.decision.status === "approved"
        ? t("Candidate approved")
        : t("Candidate rejected");
  $("#approval-status").replaceChildren(
    node(
      "span",
      t("{reviewed}/{total} reviewed", {reviewed: state.reviewed_cases, total: state.cases.length}),
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
  $("#case-count").textContent = t("{count} cases", {count: state.cases.length});
  $("#case-list").replaceChildren(
    ...state.cases.map((c) => {
      const [number, title, subtitle] = names()[c.id] || ["", c.id, c.origin];
      const item = node("button", null, "case-button");
      item.type = "button";
      item.setAttribute("aria-pressed", c.id === selected);
      const words = node("span", null, "case-words");
      words.append(
        node("strong", title),
        node("small", c.review ? t("Reviewed") : subtitle),
      );
      if (c.review) item.title = t("Reviewed by {name}", {name: c.review.reviewer});
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
    node("h2", names()[c.id]?.[1] || c.id),
    badge(
      t(c.origin),
      c.origin === "captured_subset" ? "blue" : "amber",
    ),
  );
  container.append(heading);
  const declaration = node("section", null, "section scope");
  declaration.append(
    titleLine(t("Authorized scope"), badge(t("Analyst-defined demo assumption"))),
    readingGuide(c.state.authorized_scope.text, "Original scope"),
  );
  const command = node("div", null, "command-block");
  command.append(node("span", t("Declared action"), "command-label"));
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
    details(t("Scope provenance"), c.state.authorized_scope, true),
  );
  container.append(declaration);
  const judgments = $("#judgment-content");
  judgments.replaceChildren();
  judgments.append(
    titleLine(t("Jev judgments"), badge(t("Inference"), "blue")),
    node("p", t("Raw answers / selected model probability"), "judgment-caption"),
  );
  const grid = node("div", null, "judgment-list");
  for (const [q, label] of Object.entries(questions())) {
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
          version === "v1" ? t("Baseline v1") : t("Candidate v2"),
          "answer-version",
        ),
      );
      const result = node("div", null, "answer-result");
      result.append(badge(labels()[a.choice], tone(a.choice)));
      result.append(
        node(
          "span",
          `${(a.probabilities[a.choice] * 100).toFixed(0)}%`,
          "probability",
        ),
      );
      cell.append(result);
      if (r.effective.overrides[q])
        cell.append(node("span", t("Coverage guard: Unknown"), "guard"));
      pair.append(cell);
    }
    row.append(pair);
    grid.append(row);
  }
  judgments.append(grid);
  const links = node("div", null, "detail-links");
  for (const version of ["v1", "v2"])
    for (const file of ["request", "response"]) {
      const link = node("a", t("{version} raw {file}", {version, file: t(file)}));
      link.href = `/api/artifact/${version}/${c.id}/${file}.json`;
      link.target = "_blank";
      link.rel = "noopener";
      links.append(link);
    }
  const modelDetails = node("div", null, "model-details");
  modelDetails.append(
    links,
    details(t("Model details & fingerprints"), c.evaluations, true),
  );
  judgments.append(modelDetails);
  const evidence = node("section", null, "section");
  evidence.append(
    titleLine(
      t("Execution evidence"),
      badge(t("{count} observations", {count: c.state.runtime_events.length}), "blue"),
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
          t("process event");
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
            (raw.exit_code !== undefined ? t(" / exit {code}", {code: raw.exit_code}) : ""),
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
        t("No runtime observations in this case. A declaration is not execution evidence."),
        "muted small",
      ),
    );
  container.append(evidence);
  const context = node("section", null, "section context");
  context.append(
    titleLine(
      t("Application context"),
      badge(t("{count} peer messages", {count: c.state.peer_messages?.length || 0})),
    ),
  );
  if (c.state.peer_messages)
    for (const [index, msg] of c.state.peer_messages.entries())
      context.append(
        details(
          t("Peer message {number}", {number: index + 1}),
          msg.object?.payload?.body || msg,
          typeof msg.object?.payload?.body !== "string",
        ),
      );
  if (c.state.untrusted_tool_output)
    context.append(
      details(
        t("Injected tool-output control (untrusted)"),
        c.state.untrusted_tool_output,
      ),
    );
  context.append(
    details(
      t("Selected evidence / original values"),
      { state: c.state, evidence_ids: c.evidence_ids },
      true,
    ),
  );
  container.append(context);
  const coverage = node("section", null, "coverage-note");
  coverage.append(
    titleLine(t("Attribution & coverage"), badge(t("Limited"), "amber")),
    readingGuide(
      typeof c.state.coverage === "string" ? c.state.coverage : c.state.coverage.attribution,
      "Original coverage",
    ),
    ...(typeof c.state.coverage === "object" && !c.state.coverage.outbound_body_captured
      ? [node("p", t("Outbound payload not captured."))] : []),
  );
  container.insertBefore(coverage, evidence);
  const form = $("#review-form");
  form.replaceChildren(
    titleLine(
      t("Human review"),
      c.review ? badge(t("Reviewed"), "green") : badge(t("Pending")),
    ),
  );
  const fields = node("div", null, "fields");
  for (const [q, title] of Object.entries(questions())) {
    const select = node("select");
    select.name = q;
    select.required = true;
    const placeholder = node("option", t("Choose a reference label"));
    placeholder.value = "";
    select.append(placeholder);
    for (const label of Object.keys(state.profiles.v1.questions[q].criteria)) {
      const option = node("option", labels()[label]);
      option.value = label;
      select.append(option);
    }
    select.value = drafts[c.id]?.[q] ?? c.review?.labels[q] ?? "";
    fields.append(field(title, select));
  }
  const lower = node("div", null, "review-lower"),
    reviewer = input("reviewer", t("Reviewer name")),
    reason = input(
      "reason",
      t("Evidence and rationale for your labels"),
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
    field(t("Reviewer (self-reported)"), reviewer),
    field(t("Review rationale"), reason),
  );
  const actions = node("div", null, "form-actions"),
    submit = node(
      "button",
      c.review ? t("Save a new review revision") : t("Save review"),
      "button primary",
    );
  submit.type = "submit";
  actions.append(
    node("span", t("Reference labels stay separate from model output."), "muted"),
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
        Object.keys(questions()).map((q) => [q, data[q]]),
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
    titleLine(t("Candidate v2"), badge(t("Manual revision"), "blue")),
    readingGuide(state.profiles.v2.description, "Original rule description"),
  );
  description.append(
    node(
      "div",
      t("The runtime-coverage guard is fixed for BOTH versions. Its corrections are not evidence that Jev or the candidate rule improved."),
      "notice",
    ),
    node(
      "p",
      t("Same six cases, one call per version. Selected examples, not a held-out benchmark."),
      "muted small",
    ),
  );
  metrics.append(
    titleLine(
      t("Observed comparison"),
      badge(t("{count} saved calls", {count: state.cases.length * 2})),
    ),
  );
  const rows = [
    ["", t("Baseline v1"), t("Candidate v2")],
    [
      t("Mean API latency"),
      ...["v1", "v2"].map((v) => state.metrics[v].mean_latency_ms + " ms"),
    ],
    [
      t("Input tokens"),
      ...["v1", "v2"].map((v) =>
        state.metrics[v].input_tokens.toLocaleString(language),
      ),
    ],
    [
      t("Raw disagreements"),
      ...["v1", "v2"].map((v) =>
        state.reviewed_cases
          ? `${state.metrics[v].raw_disagreements} / ${state.metrics[v].reviewed_decisions}`
          : t("Not reviewed"),
      ),
    ],
    [
      t("After coverage guard"),
      ...["v1", "v2"].map((v) =>
        state.reviewed_cases
          ? `${state.metrics[v].effective_disagreements} / ${state.metrics[v].reviewed_decisions}`
          : t("Not reviewed"),
      ),
    ],
    [
      t("Guard overrides"),
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
  diff.append(titleLine(t("Question & criteria diff"), badge("v1 → v2")));
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
  diff.append(pre, details(t("Rule fingerprints"), state.study.profiles, true));
  if (language === "zh-CN") {
    const guide = node("section", null, "panel rule-guide");
    guide.append(titleLine(t("Chinese rule guide (not submitted to the model)")));
    for (const version of ["v1", "v2"]) {
      guide.append(node("h3", t(version === "v1" ? "Baseline v1" : "Candidate v2")));
      for (const [key, question] of Object.entries(state.profiles[version].questions)) {
        guide.append(node("h4", questions()[key] || key), node("p", t(question.instructions)));
        const list = node("ul");
        for (const [choice, criterion] of Object.entries(question.criteria))
          list.append(node("li", (labels()[choice] || choice) + "：" + t(criterion)));
        guide.append(list);
      }
    }
    main.append(guide);
  }
  main.append(diff);
  const comparison = node("section", null, "panel comparison-panel");
  comparison.append(
    titleLine(t("Case-by-case comparison"), badge(t("Same evidence"))),
  );
  const controls = node("div", null, "compare-controls"),
    select = node("select"),
    mode = node("select");
  select.setAttribute("aria-label", t("Comparison question"));
  for (const [q, label] of Object.entries(questions())) {
    const option = node("option", label);
    option.value = q;
    select.append(option);
  }
  select.value = compareQuestion;
  mode.setAttribute("aria-label", t("Comparison layer"));
  for (const [key, label] of [
    ["raw", t("Raw model answer")],
    ["effective", t("After fixed coverage guard")],
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
  for (const text of [t("Case"), t("Baseline v1"), t("Candidate v2"), t("Human reference")])
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
      name = node("td", names()[c.id]?.[1] || c.id);
    name.append(node("small", t(c.origin)));
    row.append(name);
    choices.forEach((choice) => {
      const cell = node("td");
      cell.append(badge(labels()[choice], tone(choice)));
      row.append(cell);
    });
    row.append(
      node(
        "td",
        c.review ? labels()[c.review.labels[compareQuestion]] : t("Pending"),
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
      t("Candidate v2"),
      badge(
        isApproved() ? t("Approved") : t("Not promoted"),
        isApproved() ? "green" : "amber",
      ),
    ),
    node(
      "p",
      t("Approval binds this rule, these API results and the current reference labels. It does not deploy a policy or modify source evidence."),
      "muted small",
    ),
  );
  const checks = node("ul", null, "checklist");
  checks.append(
    node(
      "li",
      t("{reviewed} / {total} cases reviewed", {reviewed: state.reviewed_cases, total: state.cases.length}),
      state.reviewed_cases === state.cases.length ? "pass" : "",
    ),
  );
  for (const text of state.approval_blockers) checks.append(node("li", diagnostic(text)));
  if (!state.approval_blockers.length)
    checks.append(
      node(
        "li",
        t("Review gate passed. Approval is still a human decision."),
        "pass",
      ),
    );
  panel.append(checks);
  if (state.decision && !state.decision_current)
    panel.append(
      node(
        "div",
        t("Reviews changed after the last decision. A new decision is required before export."),
        "notice",
      ),
    );
  const form = node("form", null, "decision-form"),
    reviewer = input("reviewer", t("Reviewer name")),
    reason = input(
      "reason",
      t("Why approve or reject this candidate?"),
      true,
      true,
    );
  if (decisionDraft) {
    reviewer.value = decisionDraft.reviewer;
    reason.value = decisionDraft.reason;
  }
  form.append(
    field(t("Reviewer (self-reported)"), reviewer),
    field(t("Decision rationale"), reason),
  );
  form.oninput = () => {
    decisionDraft = Object.fromEntries(new FormData(form));
  };
  const actions = node("div", null, "form-actions"),
    reject = node("button", t("Reject candidate"), "button danger"),
    approve = node("button", t("Approve candidate"), "button primary");
  reject.type = approve.type = "submit";
  reject.value = "rejected";
  approve.value = "approved";
  approve.disabled = state.approval_blockers.length > 0;
  approve.title = state.approval_blockers.map(diagnostic).join("; ");
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
  const exportButton = button(t("Download approved signals"), async () => {
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
      t("Append-only review journal"),
      badge(t("{count} events", {count: state.audit.length})),
    ),
    node(
      "p",
      t("Local file history with hashes; reviewer names are self-reported. This is not an authenticated or signed approval service."),
      "muted small",
    ),
  );
  const list = node("ol", null, "journal");
  if (!state.audit.length)
    list.append(node("li", t("No human reviews or decisions yet."), "muted"));
  for (const event of [...state.audit].reverse()) {
    const li = node("li"),
      meta = node("div", null, "meta");
    meta.append(
      node(
        "strong",
        `#${event.revision} ${event.kind === "review" ? names()[event.case_id]?.[1] || event.case_id : t("Candidate {status}", {status: t(event.status)})}`,
      ),
      node("span", event.reviewer, "muted"),
    );
    li.append(
      meta,
      node("small", new Date(event.at).toLocaleString(language), "muted"),
      node("p", event.reason),
      details(t("Recorded event"), event, true),
    );
    list.append(li);
  }
  audit.append(list);
  layout.append(panel, audit);
  container.append(
    layout,
    details(t("Immutable study fingerprints"), state.study, true),
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
    const data = await readResponse(response);
    if (!response.ok) throw new Error(data.error || "Study unavailable");
    state = data;
    render();
  })
  .catch((e) => {
    $("#loading").hidden = true;
    error(e.message);
  });

})();
