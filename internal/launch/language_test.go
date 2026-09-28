package launch

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

func TestPreflightLocalizedWithoutChangingReport(t *testing.T) {
	r := PreflightReport{Checks: []Check{
		checkCommand([]string{"/__missing__/Copy"}),
		checkClaudeHooks([]string{"Copy"}),
		checkClaudeHooks([]string{"claude", "--settings", "user.json"}),
		checkDashboardAddr(false, ""), checkSensor("off", ""),
	}}
	before, _ := json.Marshal(r)
	var en, zh bytes.Buffer
	PrintPreflight(&en, r)
	PrintPreflightLocale(&zh, r, i18n.Chinese)
	after, _ := json.Marshal(r)
	if !bytes.Equal(before, after) {
		t.Fatal("machine report changed")
	}
	if !strings.Contains(en.String(), "no hooks recipe for") {
		t.Fatal("English compatibility lost")
	}
	for _, text := range []string{"启动检查", "尚无", "无法访问 /__missing__/Copy", "--settings", "处理方法", "已通过 --sensor=off 禁用"} {
		if !strings.Contains(zh.String(), text) {
			t.Errorf("missing %q in %s", text, zh.String())
		}
	}
	for _, english := range []string{"no hooks recipe for", "remove --settings", "disabled via", "command already passes"} {
		if strings.Contains(zh.String(), english) {
			t.Errorf("untranslated: %s", english)
		}
	}
	if strings.Contains(zh.String(), "%!") {
		t.Fatal("bad format")
	}
}

func TestLocalizedLaunchSummaryRetainsCommandsAndReport(t *testing.T) {
	recipe := detectRecipe([]string{"Copy"})
	r := Report{RunID: "Search", AppTier: recipe.tier, AppDetail: recipe.detail, appDetail: recipe.detailText,
		SysTier: "none", SysDegradeReason: "disabled via --sensor=off", sysReason: messagef("disabled via --sensor=off"),
		Verdict: "DEGRADED", BundlePath: "/original/Copy.forensics.json.gz"}
	before, _ := json.Marshal(r)
	var zh bytes.Buffer
	printBanner(&zh, r, []string{"Copy", "--command=Run"}, i18n.Chinese)
	printVerdict(&zh, r, i18n.Chinese)
	for _, text := range []string{"Copy --command=Run", "Search", "/original/Copy.forensics.json.gz", "覆盖不足", "未签名", "尚无", "已通过 --sensor=off 禁用"} {
		if !strings.Contains(zh.String(), text) {
			t.Errorf("missing %q: %s", text, zh.String())
		}
	}
	after, _ := json.Marshal(r)
	if !bytes.Equal(before, after) {
		t.Fatal("report mutated")
	}
}

func TestLaunchBannerDescribesConfigurationNotCapturedEvidence(t *testing.T) {
	for _, app := range []string{"hooks(claude-code)", "transcript(claude)", "transcript(codex)", "transcript(kimi)", "transcript(grok)", "transcript(deepseek)", "record", ""} {
		for _, system := range []string{"kernel", "none"} {
			t.Run(app+"/"+system, func(t *testing.T) {
				r := Report{AppTier: app, SysTier: system}
				before, _ := json.Marshal(r)
				var en, zh bytes.Buffer
				printBanner(&en, r, []string{"agent-command"}, i18n.English)
				printBanner(&zh, r, []string{"agent-command"}, i18n.Chinese)
				if !strings.Contains(en.String(), "configured") || !strings.Contains(en.String(), "checked after exit") ||
					!strings.Contains(zh.String(), "采集配置") || !strings.Contains(zh.String(), "执行结束后检查") {
					t.Fatalf("configuration/coverage distinction missing: %s / %s", en.String(), zh.String())
				}
				if strings.Contains(en.String(), "full:") || strings.Contains(en.String(), "agent intent (hooks)") || strings.Contains(zh.String(), "configured") {
					t.Fatalf("unsupported completeness claim or untranslated setup: %s / %s", en.String(), zh.String())
				}
				wantAdapter := app != "record" && app != ""
				if strings.Contains(captureSetup(r), "no agent context adapter") == wantAdapter ||
					strings.Contains(captureSetup(r), "kernel sensor +") != (system == "kernel") {
					t.Fatalf("wrong configured sources: %s", captureSetup(r))
				}
				after, _ := json.Marshal(r)
				if !bytes.Equal(before, after) {
					t.Fatal("presentation modified the machine report")
				}
			})
		}
	}
}
