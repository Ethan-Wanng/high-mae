//go:build android

package proxy

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	sbrule "github.com/sagernet/sing-box/route/rule"
)

func TestBuildAndroidTunBoxOptionsRejectActionDoesNotPanic(t *testing.T) {
	opts, err := buildAndroidTunBoxOptions()
	if err != nil {
		t.Fatalf("buildAndroidTunBoxOptions() error = %v", err)
	}
	if opts.Route == nil || len(opts.Route.Rules) < 2 {
		t.Fatalf("unexpected route rules: %+v", opts.Route)
	}
	rejectRule := opts.Route.Rules[1].DefaultOptions
	if rejectRule.Action != C.RuleActionTypeReject {
		t.Fatalf("rule[1].Action = %q, want %q", rejectRule.Action, C.RuleActionTypeReject)
	}
	if rejectRule.RejectOptions.Method != C.RuleActionRejectMethodDefault {
		t.Fatalf("rule[1].RejectOptions.Method = %q, want %q", rejectRule.RejectOptions.Method, C.RuleActionRejectMethodDefault)
	}
	action, err := sbrule.NewRuleAction(context.Background(), nil, rejectRule.RuleAction)
	if err != nil {
		t.Fatalf("NewRuleAction() error = %v", err)
	}
	reject, ok := action.(*sbrule.RuleActionReject)
	if !ok {
		t.Fatalf("action type = %T, want *rule.RuleActionReject", action)
	}
	if rejectErr := reject.Error(context.Background()); rejectErr == nil {
		t.Fatalf("reject.Error() = nil, want non-nil reject error")
	}
}
