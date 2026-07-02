package routing

import (
	"testing"

	"wing/pkg/common"
)

func TestEvaluateCmdRoutingMatchesExecutableBasePrefix(t *testing.T) {
	oldRules := CmdRules
	defer func() { CmdRules = oldRules }()

	CmdRules = []CmdRule{{Pattern: "go test", Type: "prefix", Action: "direct"}}

	action, matched := EvaluateCmdRouting(`"C:\Program Files\Go\bin\go.exe" test ./pkg/...`)
	if !matched {
		t.Fatal("expected go test prefix rule to match go.exe command line")
	}
	if action != "direct" {
		t.Fatalf("expected direct action, got %q", action)
	}
}

func TestEvaluateCmdRoutingExact(t *testing.T) {
	oldRules := CmdRules
	defer func() { CmdRules = oldRules }()

	CmdRules = []CmdRule{{Pattern: "curl https://example.com", Type: "exact", Action: "proxy"}}

	if _, matched := EvaluateCmdRouting("curl https://example.com/path"); matched {
		t.Fatal("did not expect exact rule to match a longer command line")
	}
	action, matched := EvaluateCmdRouting("curl https://example.com")
	if !matched {
		t.Fatal("expected exact rule to match identical command line")
	}
	if action != "proxy" {
		t.Fatalf("expected proxy action, got %q", action)
	}
}

func TestEvaluateCmdRoutingMatchesWindowsExecutablePrefix(t *testing.T) {
	oldRules := CmdRules
	defer func() { CmdRules = oldRules }()

	CmdRules = []CmdRule{{Pattern: "ping youtube.com", Type: "prefix", Action: "proxy"}}

	action, matched := EvaluateCmdRouting(`C:\Windows\System32\PING.EXE youtube.com -n 1`)
	if !matched {
		t.Fatal("expected ping prefix rule to match ping.exe command line")
	}
	if action != "proxy" {
		t.Fatalf("expected proxy action, got %q", action)
	}
}

func TestEvaluateCmdRoutingMatchesForwardedCmdCommand(t *testing.T) {
	oldRules := CmdRules
	defer func() { CmdRules = oldRules }()

	CmdRules = []CmdRule{{Pattern: "curl https://example.com", Type: "prefix", Action: "proxy"}}

	action, matched := EvaluateCmdRouting(`C:\Windows\System32\cmd.exe /c curl https://example.com`)
	if !matched {
		t.Fatal("expected cmd /c forwarded command to match")
	}
	if action != "proxy" {
		t.Fatalf("expected proxy action, got %q", action)
	}
}

func TestEvaluateRoutingCanGuardBingCNRedirect(t *testing.T) {
	oldRules := RuleGroups
	oldMode := common.GetProxyMode()
	oldGuard := common.PreventBingCNRedirect
	defer func() {
		RuleGroups = oldRules
		common.SetProxyMode(oldMode)
		common.PreventBingCNRedirect = oldGuard
	}()

	common.SetProxyMode("Rule")
	RuleGroups = normalizeRuleGroups([]RuleGroup{
		{
			ID:     "direct",
			Name:   "Direct",
			Action: "direct",
			Rules: []CustomRule{
				{Type: "domain_suffix", Value: "bing.com"},
				{Type: "domain", Value: "example.com"},
				{Type: "domain_suffix", Value: "bing.net", Action: "hk-group"},
			},
		},
	})

	common.PreventBingCNRedirect = false
	if got := EvaluateRouting("www.bing.com:443"); got != "direct" {
		t.Fatalf("guard off: www.bing.com route = %q, want direct", got)
	}

	common.PreventBingCNRedirect = true
	if got := EvaluateRouting("www.bing.com:443"); got != "proxy" {
		t.Fatalf("guard on: www.bing.com route = %q, want proxy", got)
	}
	if got := EvaluateRouting("cn.bing.com:443"); got != "proxy" {
		t.Fatalf("guard on: cn.bing.com route = %q, want proxy", got)
	}
	if got := EvaluateRouting("example.com:443"); got != "direct" {
		t.Fatalf("guard on: unrelated exact route = %q, want direct", got)
	}
	if got := EvaluateRouting("www.bing.net:443"); got != "hk-group" {
		t.Fatalf("guard on: explicit Bing proxy group route = %q, want hk-group", got)
	}
}

func TestDefaultRuleGroupsOmitBingDirectDefaults(t *testing.T) {
	for _, group := range DefaultRuleGroups() {
		for _, rule := range group.Rules {
			if isLegacyBingDirectDefaultRule(rule) {
				t.Fatalf("default rules should not include legacy Bing direct rule: %+v", rule)
			}
		}
	}
}

func TestRemoveLegacyBingDirectDefaultsKeepsExplicitActions(t *testing.T) {
	groups := removeLegacyBingDirectDefaults([]RuleGroup{
		{
			ID:     "direct",
			Name:   "Direct",
			Action: "direct",
			Rules: []CustomRule{
				{Type: "domain_suffix", Value: "bing.com"},
				{Type: "domain", Value: "cn.bing.com"},
				{Type: "domain_suffix", Value: "bing.com", Action: "proxy"},
				{Type: "domain", Value: "cn.bing.com", Action: "reject"},
				{Type: "domain", Value: "example.com"},
			},
		},
	})

	gotRules := groups[0].Rules
	if len(gotRules) != 3 {
		t.Fatalf("filtered rule count = %d, want 3: %+v", len(gotRules), gotRules)
	}
	for _, rule := range gotRules {
		if rule.Value == "bing.com" && rule.Action != "proxy" {
			t.Fatalf("unexpected non-explicit bing.com rule survived: %+v", rule)
		}
		if rule.Value == "cn.bing.com" && rule.Action != "reject" {
			t.Fatalf("unexpected non-explicit cn.bing.com rule survived: %+v", rule)
		}
	}
}

func TestRuleGroupSnapshotsAreIsolated(t *testing.T) {
	oldRules := GetRuleGroups()
	oldMode := common.GetProxyMode()
	defer func() {
		setRuleGroups(oldRules)
		common.SetProxyMode(oldMode)
	}()

	common.SetProxyMode("Rule")
	setRuleGroups([]RuleGroup{
		{
			ID:     "direct",
			Name:   "Direct",
			Action: "direct",
			Rules:  []CustomRule{{Type: "domain", Value: "example.com"}},
		},
	})

	snapshot := GetRuleGroups()
	snapshot[0].Rules[0].Value = "mutated.example"

	if got := EvaluateRouting("example.com:443"); got != "direct" {
		t.Fatalf("EvaluateRouting after snapshot mutation = %q, want direct", got)
	}
}

func TestCmdRuleSnapshotsAreIsolated(t *testing.T) {
	oldRules := GetCmdRules()
	defer setCmdRules(oldRules)

	setCmdRules([]CmdRule{{Pattern: "curl https://example.com", Type: "prefix", Action: "direct"}})
	snapshot := GetCmdRules()
	snapshot[0].Pattern = "mutated"

	action, matched := EvaluateCmdRouting("curl https://example.com/path")
	if !matched || action != "direct" {
		t.Fatalf("EvaluateCmdRouting after snapshot mutation = %q/%v, want direct/true", action, matched)
	}
}
