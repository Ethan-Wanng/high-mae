package routing

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"high-mae/pkg/common"
	"high-mae/pkg/utils"
)

var cancelAnyTLS interface{}

type CustomRule struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Action string `json:"action,omitempty"`
}

type RuleGroup struct {
	ID     string       `json:"id"`
	Name   string       `json:"name"`
	Action string       `json:"action"`
	Rules  []CustomRule `json:"rules"`
}

var RuleGroups []RuleGroup

const RuleGroupsFile = "rule_groups.json"

func LoadUserRules() {
	groups, err := ReadRuleGroups()
	if err != nil || len(groups) == 0 {
		groups = DefaultRuleGroups()
		_ = SaveRuleGroups(groups)
	}
	RuleGroups = normalizeRuleGroups(groups)
}

func SaveUserRules() error {
	return SaveRuleGroups(RuleGroups)
}

func ReadRuleGroups() ([]RuleGroup, error) {
	data, err := utils.SecureReadFile(RuleGroupsFile)
	if err == nil {
		var groups []RuleGroup
		if err := json.Unmarshal(data, &groups); err != nil {
			return nil, err
		}
		return normalizeRuleGroups(groups), nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	oldData, oldErr := os.ReadFile("rules.json")
	if oldErr == nil {
		var oldRules []CustomRule
		if json.Unmarshal(oldData, &oldRules) == nil && len(oldRules) > 0 {
			return []RuleGroup{{ID: "custom", Name: "自定义规则", Action: "direct", Rules: oldRules}}, nil
		}
	}
	return DefaultRuleGroups(), nil
}

func SaveRuleGroups(groups []RuleGroup) error {
	groups = normalizeRuleGroups(groups)
	data, err := json.MarshalIndent(groups, "", "  ")
	if err != nil {
		return err
	}
	if err := utils.SecureWriteFile(RuleGroupsFile, data); err != nil {
		return err
	}
	RuleGroups = groups
	return nil
}

func DefaultRuleGroups() []RuleGroup {
	rules := make([]CustomRule, 0, len(exactDomains)+len(suffixDomains)+len(keywordDomains))
	for _, d := range exactDomains {
		rules = append(rules, CustomRule{Type: "domain", Value: d})
	}
	for _, d := range suffixDomains {
		rules = append(rules, CustomRule{Type: "domain_suffix", Value: d})
	}
	for _, d := range keywordDomains {
		rules = append(rules, CustomRule{Type: "domain_keyword", Value: d})
	}
	return []RuleGroup{{ID: "direct", Name: "直连组", Action: "direct", Rules: rules}}
}

func normalizeRuleGroups(groups []RuleGroup) []RuleGroup {
	for i := range groups {
		if strings.TrimSpace(groups[i].ID) == "" {
			groups[i].ID = fmt.Sprintf("group_%d", i+1)
		}
		if strings.TrimSpace(groups[i].Name) == "" {
			groups[i].Name = groups[i].ID
		}
		groups[i].Action = normalizeRuleAction(groups[i].Action)
		for j := range groups[i].Rules {
			groups[i].Rules[j].Type = normalizeRuleType(groups[i].Rules[j].Type)
			groups[i].Rules[j].Value = strings.ToLower(strings.TrimSpace(groups[i].Rules[j].Value))
			if groups[i].Rules[j].Action != "" {
				groups[i].Rules[j].Action = normalizeRuleAction(groups[i].Rules[j].Action)
			}
		}
	}
	return groups
}

func normalizeRuleAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "direct":
		return "direct"
	case "reject", "block":
		return "reject"
	default:
		return "proxy"
	}
}

func normalizeRuleType(ruleType string) string {
	switch strings.ToLower(strings.TrimSpace(ruleType)) {
	case "exact", "domain":
		return "domain"
	case "keyword", "domain_keyword":
		return "domain_keyword"
	default:
		return "domain_suffix"
	}
}

// return value: 0=proxy, 1=direct, 2=reject
func EvaluateRouting(hostPort string) int {
	if common.ProxyMode == "Global" {
		return 0 // proxy
	}
	if len(RuleGroups) == 0 {
		RuleGroups = normalizeRuleGroups(DefaultRuleGroups())
	}
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() {
			return 1 // direct
		}
	}
	host = strings.ToLower(host)
	if IsStunDomain(host) {
		return 2 // reject STUN
	}

	for _, group := range RuleGroups {
		groupAction := normalizeRuleAction(group.Action)
		for _, r := range group.Rules {
			value := strings.ToLower(strings.TrimSpace(r.Value))
			if value == "" {
				continue
			}
			match := false
			switch normalizeRuleType(r.Type) {
			case "domain":
				match = (host == value)
			case "domain_suffix":
				match = (host == value || strings.HasSuffix(host, "."+value))
			case "domain_keyword":
				match = strings.Contains(host, value)
			}
			if !match {
				continue
			}
			action := groupAction
			if r.Action != "" {
				action = normalizeRuleAction(r.Action)
			}
			switch action {
			case "direct":
				return 1
			case "reject", "block":
				return 2
			case "proxy":
				return 0
			}
		}
	}
	return 0
}

func ShouldDirect(hostPort string) bool {
	return EvaluateRouting(hostPort) == 1
}

func StartAnyTLSHttpServer() {
	// 占位，稍后通过 import 修复或完全移除
}
