package dashboard

import (
	"context"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

func offlineReaderAssets() map[string][]byte {
	return map[string][]byte{"reader.js": readerJS, "workbench.js": workbenchJS, "workbench.css": workbenchCSS,
		"offline.js": offlineJS, "replay.js": replayJS}
}

// DemoReaderFiles renders only the presentation of an unsigned gallery copy.
// The catalog, shards, frozen selection and downloadable originals stay intact.
func DemoReaderFiles(ctx context.Context, inventory ReplayInventory, run string, gallery bool) (map[string][]byte, error) {
	if inventory.Signed || inventory.Signature != nil || (inventory.DeliveryMode != "" && inventory.DeliveryMode != DeliveryReading) {
		return nil, fmt.Errorf("gallery requires an unsigned reading copy")
	}
	runs := inventory.Runs
	if len(runs) == 0 {
		if inventory.SelectionSummary == nil {
			return nil, fmt.Errorf("missing frozen selection")
		}
		runs = []ReplayRunInventory{{RunID: inventory.RunID, Scope: inventory.Scope, SelectionSummary: *inventory.SelectionSummary, AnalysisOmissions: inventory.AnalysisOmissions}}
	}
	var selections []ReplaySelection
	var partial, omitted, found bool
	for _, item := range runs {
		if item.RunID == "" || item.SelectionSummary.Selection.RunID != item.RunID || item.SelectionSummary.Selection.Scope != item.Scope {
			return nil, fmt.Errorf("missing or inconsistent frozen selection for %q", item.RunID)
		}
		sel := item.SelectionSummary.Selection
		selections = append(selections, sel)
		partial = partial || (&replaySelectionPlan{Selection: sel}).partial()
		omitted = omitted || len(item.AnalysisOmissions) != 0
		found = found || sel.RunID == run
	}
	if !found || run == "" {
		return nil, fmt.Errorf("default run is not in the frozen selection")
	}
	files := map[string][]byte{"index.html": []byte(offlineReplayIndex)}
	for name, data := range offlineReaderAssets() {
		files["assets/"+name] = data
	}
	get := replayResource(ctx, (Server{}).Handler())
	for _, locale := range []i18n.Locale{i18n.English, i18n.Chinese} {
		raw, err := get("/?lang=" + string(locale))
		if err != nil {
			return nil, err
		}
		page, err := renderReadingPage(raw, locale, selections, partial, omitted, run, gallery)
		if err != nil {
			return nil, err
		}
		files[string(locale)+"/index.html"] = page
		files["assets/i18n."+string(locale)+".js"], err = get("/assets/i18n.js?lang=" + string(locale))
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}
