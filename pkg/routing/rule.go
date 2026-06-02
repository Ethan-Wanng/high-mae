package routing

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"wing/pkg/common"
	"wing/pkg/storage"
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

var bingRedirectProtectedSuffixes = []string{
	"bing.com",
	"bing.net",
	"bingapis.com",
}

type CmdRule struct {
	Pattern string `json:"pattern"`
	Type    string `json:"type"`   // "prefix" or "exact"
	Action  string `json:"action"` // "direct", "proxy", "reject"
}

var CmdRules []CmdRule

const CmdRulesFile = "cmd_rules.json"

func LoadCmdRules() {
	data, err := storage.ReadOrMigrateFile(CmdRulesFile)
	if err == nil {
		var rules []CmdRule
		if err := json.Unmarshal(data, &rules); err == nil {
			CmdRules = normalizeCmdRules(rules)
			return
		}
	}
	CmdRules = DefaultCmdRules()
	_ = SaveCmdRules(CmdRules)
}

func SaveCmdRules(rules []CmdRule) error {
	rules = normalizeCmdRules(rules)
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	if err := storage.Write(CmdRulesFile, data); err != nil {
		return err
	}
	CmdRules = rules
	return nil
}

func DefaultCmdRules() []CmdRule {
	return []CmdRule{
		{Pattern: "go test", Type: "prefix", Action: "direct"},
	}
}

func EvaluateCmdRouting(cmdline string) (string, bool) {
	if cmdline == "" {
		return "", false
	}
	if len(CmdRules) == 0 {
		CmdRules = DefaultCmdRules()
	}
	variants := commandLineVariants(cmdline)
	for _, rule := range CmdRules {
		if commandLineMatches(variants, rule) {
			return normalizeRuleAction(rule.Action), true
		}
	}
	return "", false
}

func normalizeCmdRules(rules []CmdRule) []CmdRule {
	out := make([]CmdRule, 0, len(rules))
	for _, rule := range rules {
		pattern := normalizeCommandText(rule.Pattern)
		if pattern == "" {
			continue
		}
		rule.Pattern = pattern
		rule.Type = normalizeCmdRuleType(rule.Type)
		rule.Action = normalizeRuleAction(rule.Action)
		if rule.Action == "" {
			rule.Action = "direct"
		}
		out = append(out, rule)
	}
	return out
}

func normalizeCmdRuleType(ruleType string) string {
	switch strings.ToLower(strings.TrimSpace(ruleType)) {
	case "exact", "full":
		return "exact"
	default:
		return "prefix"
	}
}

func commandLineMatches(variants []string, rule CmdRule) bool {
	pattern := normalizeCommandText(rule.Pattern)
	if pattern == "" {
		return false
	}
	for _, variant := range variants {
		if normalizeCmdRuleType(rule.Type) == "exact" {
			if variant == pattern {
				return true
			}
			continue
		}
		if strings.HasPrefix(variant, pattern) {
			return true
		}
	}
	return false
}

func commandLineVariants(cmdline string) []string {
	raw := normalizeCommandText(cmdline)
	if raw == "" {
		return nil
	}
	variants := []string{raw}

	exe, args := splitExecutableAndArgs(cmdline)
	exe = strings.Trim(exe, "\"")
	if exe != "" {
		base := commandExecutableBase(exe)
		base = strings.TrimSuffix(base, ".exe")
		short := normalizeCommandText(strings.TrimSpace(base + " " + args))
		if short != "" && short != raw {
			variants = append(variants, short)
		}
		if forwarded := forwardedShellCommand(base, args); forwarded != "" && forwarded != raw && forwarded != short {
			variants = append(variants, forwarded)
		}
	}
	return variants
}

func commandExecutableBase(exe string) string {
	exe = strings.TrimSpace(strings.Trim(exe, "\""))
	exe = strings.ReplaceAll(exe, "\\", "/")
	if idx := strings.LastIndex(exe, "/"); idx >= 0 {
		exe = exe[idx+1:]
	}
	return strings.ToLower(exe)
}

func forwardedShellCommand(base string, args string) string {
	base = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(base)), ".exe")
	args = strings.TrimSpace(args)
	if args == "" {
		return ""
	}
	lowerArgs := strings.ToLower(args)
	switch base {
	case "cmd":
		for _, prefix := range []string{"/c ", "/s /c "} {
			if strings.HasPrefix(lowerArgs, prefix) {
				return normalizeCommandText(args[len(prefix):])
			}
		}
	case "powershell", "pwsh":
		for _, flag := range []string{"-command ", "-c "} {
			if idx := strings.Index(lowerArgs, flag); idx >= 0 {
				return normalizeCommandText(args[idx+len(flag):])
			}
		}
	}
	return ""
}

func splitExecutableAndArgs(cmdline string) (string, string) {
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return "", ""
	}
	if cmdline[0] == '"' {
		if end := strings.Index(cmdline[1:], "\""); end >= 0 {
			pos := end + 1
			return cmdline[1:pos], strings.TrimSpace(cmdline[pos+1:])
		}
		return strings.Trim(cmdline, "\""), ""
	}
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return "", ""
	}
	rest := ""
	if len(fields) > 1 {
		rest = strings.Join(fields[1:], " ")
	}
	return fields[0], rest
}

func normalizeCommandText(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "\"", "")
	return strings.Join(strings.Fields(value), " ")
}

func LoadUserRules() {
	groups, err := ReadRuleGroups()
	if err != nil || len(groups) == 0 {
		groups = DefaultRuleGroups()
		_ = SaveRuleGroups(groups)
	}
	groups = removeLegacyBingDirectDefaults(groups)
	RuleGroups = normalizeRuleGroups(groups)
	_ = SaveRuleGroups(RuleGroups)
	LoadCmdRules()
}

func SaveUserRules() error {
	_ = SaveCmdRules(CmdRules)
	return SaveRuleGroups(RuleGroups)
}

func ReadRuleGroups() ([]RuleGroup, error) {
	data, err := storage.ReadOrMigrateFile(RuleGroupsFile)
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
	if err := storage.Write(RuleGroupsFile, data); err != nil {
		return err
	}
	RuleGroups = groups
	return nil
}

func DefaultRuleGroups() []RuleGroup {
	rules := make([]CustomRule, 0, len(exactDomains)+len(suffixDomains)+len(keywordDomains))
	for _, d := range exactDomains {
		rule := CustomRule{Type: "domain", Value: d}
		if isLegacyBingDirectDefaultRule(rule) {
			continue
		}
		rules = append(rules, rule)
	}
	for _, d := range suffixDomains {
		rule := CustomRule{Type: "domain_suffix", Value: d}
		if isLegacyBingDirectDefaultRule(rule) {
			continue
		}
		rules = append(rules, rule)
	}
	for _, d := range keywordDomains {
		rules = append(rules, CustomRule{Type: "domain_keyword", Value: d})
	}
	return []RuleGroup{{ID: "direct", Name: "直连组", Action: "direct", Rules: rules}}
}

func removeLegacyBingDirectDefaults(groups []RuleGroup) []RuleGroup {
	groups = normalizeRuleGroups(groups)
	for i := range groups {
		if normalizeRuleAction(groups[i].Action) != "direct" {
			continue
		}
		filtered := groups[i].Rules[:0]
		for _, rule := range groups[i].Rules {
			if isLegacyBingDirectDefaultRule(rule) {
				continue
			}
			filtered = append(filtered, rule)
		}
		groups[i].Rules = filtered
	}
	return groups
}

func isLegacyBingDirectDefaultRule(rule CustomRule) bool {
	if strings.TrimSpace(rule.Action) != "" {
		return false
	}
	ruleType := normalizeRuleType(rule.Type)
	value := strings.ToLower(strings.TrimSpace(rule.Value))
	return (ruleType == "domain" && value == "cn.bing.com") ||
		(ruleType == "domain_suffix" && value == "bing.com")
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
	act := strings.TrimSpace(action)
	switch strings.ToLower(act) {
	case "direct":
		return "direct"
	case "reject", "block":
		return "reject"
	case "proxy":
		return "proxy"
	default:
		return act // Keep the original node name or group name
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

// return value: "proxy", "direct", "reject", or specific node/group name
func EvaluateRouting(hostPort string) string {
	if common.ProxyMode == "Global" {
		return "proxy"
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
			return "direct"
		}
	}
	host = strings.ToLower(host)
	if IsStunDomain(host) {
		return "reject"
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
			if common.PreventBingCNRedirect && action == "direct" && isBingRedirectProtectedHost(host) {
				return "proxy"
			}
			return action
		}
	}
	return "proxy"
}

func isBingRedirectProtectedHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, suffix := range bingRedirectProtectedSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func ShouldDirect(hostPort string) bool {
	return EvaluateRouting(hostPort) == "direct"
}

func StartAnyTLSHttpServer() {
	// 占位，稍后通过 import 修复或完全移除
}
