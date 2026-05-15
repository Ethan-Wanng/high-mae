//go:build ignore
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	pkgs := []string{"common", "utils", "stats", "proxy", "routing", "sub", "webui"}

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		content := string(data)
		changed := false

		for _, pkg := range pkgs {
			old := pkg + "." + pkg + "."
			new := pkg + "."
			if strings.Contains(content, old) {
				content = strings.ReplaceAll(content, old, new)
				changed = true
			}
		}

		if changed {
			return os.WriteFile(path, []byte(content), 0644)
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Cleanup successful")
	}
}
