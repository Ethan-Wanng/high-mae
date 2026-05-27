package routing

import "testing"

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
