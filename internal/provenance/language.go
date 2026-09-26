package provenance

import (
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

func presentationLocale(languages []i18n.Locale) i18n.Locale {
	if len(languages) > 0 {
		return languages[0]
	}
	return i18n.English
}

// Translate only summaries that match this version's generated text. This also
// works for manifests decoded from the daemon without rewriting unknown text.
func translateSummary(lines, english, translated []string) []string {
	result := append([]string(nil), lines...)
	for i, line := range result {
		for j, source := range english {
			if line == source {
				result[i] = translated[j]
				break
			}
		}
	}
	return result
}

func graphLensDisplaySummary(m GraphLensManifest, lang i18n.Locale) []string {
	render := func(locale i18n.Locale) []string {
		return []string{
			fmt.Sprintf(i18n.T(locale, "lens=%s layout=%s"), m.Lens, m.Query.LayoutHint),
			fmt.Sprintf(i18n.T(locale, "detail=%s raw_events=%d nodes=%d edges=%d derived_edges=%d omitted_nodes=%d omitted_edges=%d"), m.Query.Detail, m.Query.RawEventCount, m.Query.NodeCount, len(m.Edges), len(m.DerivedEdges), m.Query.OmittedNodes, m.Query.OmittedEdges),
		}
	}
	return translateSummary(m.Summary, render(i18n.English), render(lang))
}

func explainDisplaySummary(m ExplainManifest, lang i18n.Locale) []string {
	render := func(locale i18n.Locale) []string {
		if m.Target.Type == "file" && m.FileDiff != nil && m.FileBlame != nil {
			return []string{
				fmt.Sprintf(i18n.T(locale, "file %s has %d attempt diff entries"), m.Target.File, len(m.FileDiff.Attempts)),
				fmt.Sprintf(i18n.T(locale, "file %s has %d blame entries"), m.Target.File, len(m.FileBlame.Entries)),
				fmt.Sprintf(i18n.T(locale, "file %s has %d runtime file events"), m.Target.File, len(m.RuntimeEvents)),
			}
		}
		return []string{fmt.Sprintf(i18n.T(locale, "%s %s has %d runtime causality edges"), m.Target.Type, m.Target.ID, len(m.RuntimeEdges))}
	}
	return translateSummary(m.Summary, render(i18n.English), render(lang))
}
