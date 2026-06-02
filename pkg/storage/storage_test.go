package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDatabasePathUsesUserConfigDirWhenNoLocalDatabaseExists(t *testing.T) {
	_ = Close()
	t.Chdir(t.TempDir())
	configDir := t.TempDir()
	t.Setenv("WING_DB_PATH", "")
	t.Setenv("APPDATA", configDir)
	t.Setenv("XDG_CONFIG_HOME", configDir)

	got := filepath.Clean(databasePath())
	want := filepath.Clean(filepath.Join(configDir, AppDirName, DBFile))
	if got != want {
		t.Fatalf("databasePath() = %q, want %q", got, want)
	}
}

func TestInitCreatesDatabaseParentDirectory(t *testing.T) {
	_ = Close()
	dbPath := filepath.Join(t.TempDir(), "nested", "state", DBFile)
	t.Setenv("WING_DB_PATH", dbPath)
	t.Cleanup(func() {
		_ = Close()
	})

	if err := Init(); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected database file to exist: %v", err)
	}
}
