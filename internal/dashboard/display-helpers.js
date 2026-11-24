// Pure, DOM-free display helpers for context coverage, retention settings,
// readable JSON projection, and harness-scoped session directories.
// Never mutates recorded evidence or infers run loss from node-wide counters.
window.AgentDisplayHelpers = (() => {
  'use strict';

  const statusNames = {
    disabled: 'Not enabled',
    no_input: 'No source found',
    empty: 'Valid empty source',
    ok: 'Captured',
    partial: 'Partially captured',
    failed: 'Capture failed',
    ambiguous: 'Ambiguous binding',
    legacy_not_recorded: 'Not recorded in this historical run',
  };

  function retentionPresentation(policy) {
    if (!policy) return { label: 'Retention settings not recorded', settings: [] };
    const labels = {
      tool_results: 'Tool-result bodies',
      source_records: 'Raw source records',
      history: 'Resumed history',
      configuration: 'Configuration bodies',
    };
    return {
      label: ({ basic: 'Basic context', detailed: 'Detailed context' })[policy.preset] || 'Retention settings unavailable',
      settings: Object.entries(labels).map(([key, label]) => ({
        key,
        label,
        enabled: typeof policy[key] === 'boolean' ? policy[key] : null,
        override: Object.hasOwn(policy.overrides || {}, key),
      })),
    };
  }

  function contentReason(ref) {
    if (ref?.reason === 'capture_policy') return 'Not saved by this run’s retention settings.';
    return ref?.reason || 'Content was not recorded';
  }

  function runtimePresentation(capture = {}) {
    if (capture.run_dropped_events > 0) {
      return { state: 'failed', label: 'Run event loss confirmed', message: 'Some events from this run were lost. The runtime record is incomplete.' };
    }
    const state = capture.status || 'legacy_not_recorded';
    if (state === 'partial' && capture.issues?.length === 0 && capture.limitations?.length > 0) {
      return { state: 'limited', label: 'Limited capture capabilities', message: 'Some capture capabilities were unavailable. This is separate from event loss and tool association.' };
    }
    if (state === 'partial') {
      return {
        state,
        label: 'Capture completeness unconfirmed',
        message: capture.issues?.includes('node_backlog_at_seal')
          ? 'This record was sealed with node events still pending. Their impact on this run is unknown; this is not an ongoing confirmation task.'
          : 'Saved events remain available. These diagnostics do not establish how much of this run is missing.',
      };
    }
    if (state === 'ok') {
      return { state, label: 'No reported capture issues', message: 'No node loss reported; completeness is not established.' };
    }
    return {
      state,
      label: statusNames[state] || state,
      message: state === 'legacy_not_recorded'
        ? 'Runtime capture history was not recorded.'
        : state === 'disabled'
          ? 'Kernel capture was not enabled for this run.'
          : state === 'no_input'
            ? 'Kernel sensor unavailable'
            : 'Capture diagnostics require attention.',
    };
  }

  function recordedNativeLimits(capture) {
    const snapshots = [capture?.capabilities_start, capture?.capabilities_end];
    const limits = snapshots
      .flatMap(s => Array.isArray(s?.observation_limits) ? s.observation_limits : [])
      .filter(l => l && typeof l.mechanism === 'string' && typeof l.detail === 'string');
    return [...new Map(limits.map(l => [JSON.stringify([l.mechanism, l.scope, l.mode, l.detail]), l])).values()];
  }

  function coverageSections(value) {
    const reports = value?.coverage || [];
    return {
      sessions: reports.filter(c => !['runtime_correlation', 'discovery', 'processing'].includes(c.source?.channel)),
      processing: reports.filter(c => c.source?.channel === 'processing'),
      discoveries: reports.filter(c => c.source?.channel === 'discovery'),
      associations: reports.filter(c => c.source?.channel === 'runtime_correlation'),
      runtime: runtimePresentation(value?.runtime_coverage?.capture),
      nativeLimits: recordedNativeLimits(value?.runtime_coverage?.capture),
    };
  }

  // Display projection only: never rewrites the saved body, digest, or byte offsets.
  function readableContent(text, entry, metadataLabel = 'Other recorded fields') {
    if (typeof text !== 'string' || text.length > 65536) return null;
    let value;
    try { value = JSON.parse(text); } catch (_) { return null; }
    const pending = [[value, 0]];
    while (pending.length) {
      const [node, depth] = pending.pop();
      if (typeof node === 'number' && (!Number.isFinite(node) || Number.isInteger(node) && !Number.isSafeInteger(node))) return null;
      if (!node || typeof node !== 'object') continue;
      if (depth > 12) return null;
      for (const child of Object.values(node)) pending.push([child, depth + 1]);
    }
    const blocks = content => typeof content === 'string' ? content : Array.isArray(content)
      ? content.map(block => ['text', 'input_text', 'output_text'].includes(block?.type) && typeof block.text === 'string' && Object.keys(block).every(k => k === 'type' || k === 'text')
        ? block.text : JSON.stringify(block, null, 2)).join('\n\n') : null;
    let result;
    if (entry?.source?.harness === 'deepseek' && entry.kind === 'tool_result' && value?.message?.role === 'tool') {
      const output = blocks(value.message.content);
      if (output != null) {
        const { content, ...message } = value.message;
        result = output + '\n\n' + metadataLabel + '\n' + JSON.stringify({ ...value, message }, null, 2);
      }
    } else if (['message', 'tool_result'].includes(entry?.kind)) result = blocks(value);
    result ??= JSON.stringify(value, null, 2);
    return result.length <= 262144 ? result : null;
  }

  // Session identity comes from source metadata; processing diagnostics and
  // entries without a native session ID stay unassigned.
  function sessionDirectory(value) {
    const groups = new Map(), unassigned = [], seen = new Set();
    for (const report of value?.coverage || []) {
      const source = report.source || {};
      if (!source.id || seen.has(source.id) || ['runtime_correlation', 'discovery', 'processing'].includes(source.channel) || source.harness === 'launch') continue;
      seen.add(source.id);
      if (!source.session_id || !source.harness || source.harness === 'unknown') { unassigned.push(report); continue; }
      const key = JSON.stringify([source.harness, source.session_id]);
      if (!groups.has(key)) groups.set(key, { key, harness: source.harness, id: source.session_id, reports: [], parents: new Set() });
      const group = groups.get(key);
      group.reports.push(report);
      if (source.parent_session_id) group.parents.add(source.parent_session_id);
    }
    const sessions = [...groups.values()];
    for (const group of sessions) {
      if (!group.parents.size) continue;
      const parents = [...group.parents];
      group.parent = parents[0];
      group.relation = parents.length > 1 ? 'conflicting' : group.parent === group.id ? 'self' : 'missing';
      if (group.relation !== 'missing') continue;
      const target = groups.get(JSON.stringify([group.harness, group.parent]));
      if (target) { group.target = sessions.indexOf(target); group.relation = 'linked'; }
    }
    const cycles = new Set();
    sessions.forEach((group, index) => {
      const path = new Set(); let cursor = index;
      while (sessions[cursor]?.relation === 'linked') {
        if (path.has(cursor)) { path.forEach(i => cycles.add(i)); break; }
        path.add(cursor); cursor = sessions[cursor].target;
      }
    });
    cycles.forEach(index => { sessions[index].relation = 'cycle'; });
    return { sessions, unassigned, limited: Boolean(value?.has_more_sources) };
  }

  return { retentionPresentation, contentReason, coverageSections, readableContent, sessionDirectory };
})();
