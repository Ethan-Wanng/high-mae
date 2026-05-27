//go:build ignore
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var mappings = map[string]string{
	"IsSystemProxyOn":   "common",
	"ProxyMode":         "common",
	"IsTunModeOn":       "common",
	"IsWebRTCPolicyOn":  "common",
	"PrivacyMode":       "common",
	"TunCmd":            "common",
	"AllNodes":          "common",
	"MCurrentNode":      "common",
	"MNodeMenu":         "common",
	"MSupplierMenu":     "common",
	"MTestAll":          "common",
	"MToggleProxy":      "common",
	"MToggleMode":       "common",
	"MToggleTun":        "common",
	"MQuit":             "common",
	"ActiveNodeName":    "common",
	"GlobalNodeIP":      "common",
	"GlobalNodeServer":  "common",
	"globalNodeServer":  "common.GlobalNodeServer",
	"TunIP":             "common",
	"LocalHttpPort":     "common",
	"CurrentConfigFile": "sub",
	"Tun2socksBytes":    "common",
	"WintunBytes":       "common",
	"ClientMu":          "common",
	"clientMu":          "common.ClientMu",
	"ActiveClient":      "common",
	"activeClient":      "common.ActiveClient",
	"TrackingConn":      "common",

	"AddConnLog":        "stats",
	"UpdateConnLog":     "stats",
	"GetConnLogs":       "stats",
	"ClearConnLogs":     "stats",
	"ActiveConnections": "stats",
	"CurrentSpeedIn":    "stats",
	"CurrentSpeedOut":   "stats",

	"IsAdmin":           "utils",
	"RunHiddenCommand":  "utils",
	"SecureReadFile":    "utils",
	"SecureWriteFile":   "utils",
	"GetDefaultGateway": "utils",
	"GetRealLocalIP":    "utils",
	"ToggleTunMode":     "utils",
	"FastTCPPing":       "utils",
	"ShowWindowsMsgBox": "utils",

	"LoadUserRules":         "routing",
	"EvaluateRouting":       "routing",
	"CheckWebRTCLeakStatus": "routing",
	"SetWebRTCLeakPolicy":   "routing",

	"SwitchNode":                   "proxy",
	"StartLocalDNS":                "proxy",
	"StartWebUI":                   "webui",
	"StartAnyTLSHttpServer":        "proxy",
	"StartNetSpeedMonitor":         "stats",
	"ReadSubscriptions":            "sub",
	"ImportNodeFromClipboard":      "sub",
	"StartAutoUpdateSubscriptions": "sub",
	"SetSystemProxy":               "utils",
}

func main() {
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		// Exclude git, vendor and SCRIPTS
		if strings.Contains(path, ".git") || strings.Contains(path, "vendor") || strings.Contains(path, "scripts") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		content := string(data)
		needs := make(map[string]bool)

		dir := filepath.Base(filepath.Dir(path))
		currentPkg := dir
		if currentPkg == "wing" {
			currentPkg = "main"
		}

		for oldMember, newPkg := range mappings {
			targetPkg := newPkg
			targetMember := oldMember

			// If mapping is "pkg.Member", split it
			if strings.Contains(newPkg, ".") {
				parts := strings.Split(newPkg, ".")
				targetPkg = parts[0]
				targetMember = parts[1]
			}

			if targetPkg != currentPkg {
				// Replace "ins.oldMember"
				if strings.Contains(content, "ins."+oldMember) {
					needs[targetPkg] = true
					content = strings.ReplaceAll(content, "ins."+oldMember, targetPkg+"."+targetMember)
				}

				// Match bare word
				re := regexp.MustCompile(`\b` + oldMember + `\b`)
				if re.MatchString(content) && !isDefinedInFile(content, oldMember) && !isLikelyLocal(content, oldMember) {
					needs[targetPkg] = true
					content = re.ReplaceAllString(content, targetPkg+"."+targetMember)
				}
			}
		}

		if len(needs) > 0 {
			importList := []string{}
			for pkg := range needs {
				importList = append(importList, fmt.Sprintf("\t\"wing/pkg/%s\"", pkg))
			}

			if strings.Contains(content, "import (") {
				content = strings.Replace(content, "import (", "import (\n"+strings.Join(importList, "\n"), 1)
			} else {
				pkgRe := regexp.MustCompile(`package \w+`)
				content = pkgRe.ReplaceAllString(content, "$0\n\nimport (\n"+strings.Join(importList, "\n")+"\n)")
			}
		}

		content = strings.ReplaceAll(content, "\"wing/ins\"", "")

		return os.WriteFile(path, []byte(content), 0644)
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Successfully reorganized imports and member calls")
	}
}

func isDefinedInFile(content, member string) bool {
	return strings.Contains(content, "func "+member) ||
		strings.Contains(content, "var "+member) ||
		strings.Contains(content, "type "+member)
}

func isLikelyLocal(content, member string) bool {
	// Simple heuristic: if it's used as a receiver or field in this file, it might be local
	// but for our case, most things in mappings were in 'ins'
	return false
}
