//go:build ignore
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
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
		
		content = strings.ReplaceAll(content, "common.common.", "common.")
		content = strings.ReplaceAll(content, "proxy.proxy.", "proxy.")
		content = strings.ReplaceAll(content, "utils.utils.", "utils.")
		content = strings.ReplaceAll(content, "routing.routing.", "routing.")
		content = strings.ReplaceAll(content, "stats.stats.", "stats.")
		content = strings.ReplaceAll(content, "sub.sub.", "sub.")
		content = strings.ReplaceAll(content, "webui.webui.", "webui.")

		if content != orig {
			return os.WriteFile(path, []byte(content), 0644)
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Double prefix cleanup successful")
	}
}
