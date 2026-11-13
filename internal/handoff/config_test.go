package handoff

import (
	"strings"
	"testing"
)

func TestExecutionConfig(t *testing.T) {
	valid := `{"target":{"producer_id":"vm","instance_id":"one","generation":"first"},"caller":{"principal_id":"router","producer_id":"mac","namespace":"user"}}`
	c, err := ReadConfig(strings.NewReader(valid))
	if err != nil || c.Concurrency != 2 || c.Principal().ID != "router" || c.Principal().AllowedTargets[0] != c.Target {
		t.Fatalf("valid configuration: %+v %v", c, err)
	}
	for _, input := range []string{"null", `{}`, valid + `{}`, valid + strings.Repeat(" ", 64<<10),
		strings.TrimSuffix(valid, "}") + `,"auth_token":"not-configurable"}`,
		strings.TrimSuffix(valid, "}") + `,"concurrency":33}`} {
		if _, err := ReadConfig(strings.NewReader(input)); err == nil {
			t.Fatal("accepted invalid execution configuration")
		}
	}
}
