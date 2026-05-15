//go:build ignore
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	replacements := map[string]map[string]string{
		"pkg/webui": {
			"CheckWebRTCLeakStatus":      "routing.CheckWebRTCLeakStatus",
			"ToggleWebRTCLeak":           "routing.ToggleWebRTCLeak",
			"SaveRuleGroups":             "routing.SaveRuleGroups",
			"RuleGroups":                 "routing.RuleGroups",
			"RuleGroup":                  "routing.RuleGroup",
			"SaveNodesToYAML":            "sub.SaveNodesToYAML",
			"RefreshNodeMenu":            "sub.RefreshNodeMenu",
			"RefreshSupplierMenu":        "sub.RefreshSupplierMenu",
			"ReadSubscriptions":          "sub.ReadSubscriptions",
			"AppendSubscriptionWithTraffic": "sub.AppendSubscriptionWithTraffic",
			"DeleteSubscription":         "sub.DeleteSubscription",
			"ParseSubscriptionWithInfo":  "sub.ParseSubscriptionWithInfo",
			"ParseSubscription":          "sub.ParseSubscription",
			"SubscriptionTraffic":        "sub.SubscriptionTraffic",
			"SubInfo":                    "sub.SubInfo",
			"SubscriptionsFile":          "sub.SubscriptionsFile",
			"CurrentConfigFile":          "sub.CurrentConfigFile",
			"SaveDNSConfig":              "proxy.SaveDNSConfig",
			"GlobalDNSConfig":            "proxy.GlobalDNSConfig",
			"DNSConfig":                  "proxy.DNSConfig",
			"FastTCPPing":                "proxy.FastTCPPing",
			"CreateTempHTTPClient":       "proxy.CreateTempHTTPClient",
		},
		"pkg/sub": {
			"nodeMenuCancel":     "common.NodeMenuCancel",
			"NodeMenuItems":      "common.NodeMenuItems",
			"supplierMenuCancel": "common.SupplierMenuCancel",
			"SupplierMenuItems":  "common.SupplierMenuItems",
			"MSupplierMenu":      "common.MSupplierMenu",
			"FastTCPPing":        "proxy.FastTCPPing",
		},
		"pkg/proxy": {
			"common.TrackingConn": "TrackingConn",
		},
	}

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		if strings.Contains(path, "scripts") || strings.Contains(path, ".git") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		content := string(data)
		orig := content

		// Global cleanups
		content = strings.ReplaceAll(content, "common.common.", "common.")
		content = strings.ReplaceAll(content, "proxy.proxy.", "proxy.")
		content = strings.ReplaceAll(content, "utils.utils.", "utils.")
		content = strings.ReplaceAll(content, "routing.routing.", "routing.")
		content = strings.ReplaceAll(content, "sub.sub.", "sub.")

		for pkgPath, pkgRepls := range replacements {
			if strings.Contains(filepath.ToSlash(path), pkgPath) {
				// Sort keys by length descending to avoid partial replacements
				keys := make([]string, 0, len(pkgRepls))
				for k := range pkgRepls {
					keys = append(keys, k)
				}
				sort.Slice(keys, func(i, j int) bool {
					return len(keys[i]) > len(keys[j])
				})

				for _, k := range keys {
					v := pkgRepls[k]
					content = strings.ReplaceAll(content, k, v)
				}
			}
		}

		if content != orig {
			return os.WriteFile(path, []byte(content), 0644)
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Smart cleanup successful")
	}
}
