//go:build windows

package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureCronetDllCopiesOnlyMatchingHash(t *testing.T) {
	originalHash := expectedCronetDLLSHA256
	t.Cleanup(func() { expectedCronetDLLSHA256 = originalHash })

	workspace := t.TempDir()
	gopath := t.TempDir()
	sourceData := []byte("verified cronet dll fixture")
	sum := sha256.Sum256(sourceData)
	expectedCronetDLLSHA256 = hex.EncodeToString(sum[:])

	sourcePath := cronetModuleDLLPath(gopath)
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, sourceData, 0600); err != nil {
		t.Fatal(err)
	}

	t.Chdir(workspace)
	t.Setenv("GOPATH", gopath)

	EnsureCronetDll()

	got, err := os.ReadFile(filepath.Join(workspace, cronetDLLName))
	if err != nil {
		t.Fatalf("expected copied %s: %v", cronetDLLName, err)
	}
	if !bytes.Equal(got, sourceData) {
		t.Fatalf("copied %s = %q, want %q", cronetDLLName, got, sourceData)
	}
}

func TestEnsureCronetDllRejectsHashMismatch(t *testing.T) {
	originalHash := expectedCronetDLLSHA256
	t.Cleanup(func() { expectedCronetDLLSHA256 = originalHash })

	workspace := t.TempDir()
	gopath := t.TempDir()
	expectedCronetDLLSHA256 = strings.Repeat("0", 64)

	sourcePath := cronetModuleDLLPath(gopath)
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("tampered cronet dll fixture"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Chdir(workspace)
	t.Setenv("GOPATH", gopath)

	EnsureCronetDll()

	if _, err := os.Stat(filepath.Join(workspace, cronetDLLName)); !os.IsNotExist(err) {
		t.Fatalf("%s exists after hash mismatch, stat error = %v", cronetDLLName, err)
	}
}
