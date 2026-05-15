//go:build ignore
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	err := filepath.Walk("pkg", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		content := string(data)
		lines := strings.Split(content, "\n")

		// Determine new package name from directory
		dir := filepath.Base(filepath.Dir(path))

		// Update package name
		if strings.HasPrefix(lines[0], "package ") {
			lines[0] = "package " + dir
		}

		newContent := strings.Join(lines, "\n")
		return os.WriteFile(path, []byte(newContent), 0644)
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Successfully updated package names in pkg/ directory")
	}
}
