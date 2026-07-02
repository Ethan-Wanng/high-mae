package secure

import (
	"bytes"
	"path/filepath"
	"testing"

	"wing/pkg/storage"
)

func TestEncryptDataUsesRandomSalt(t *testing.T) {
	plaintext := []byte("sensitive subscription")

	first, err := EncryptData(plaintext)
	if err != nil {
		t.Fatalf("EncryptData() first error = %v", err)
	}
	second, err := EncryptData(plaintext)
	if err != nil {
		t.Fatalf("EncryptData() second error = %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("EncryptData() produced identical ciphertexts for the same plaintext")
	}

	got, err := DecryptData(first)
	if err != nil {
		t.Fatalf("DecryptData() error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("DecryptData() = %q, want %q", got, plaintext)
	}
}

func TestSecureWriteFileUsesV2KDFFormat(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	plaintext := []byte(`{"url":"https://example.com/sub?token=secret"}`)
	if err := SecureWriteFile("subscription.json", plaintext); err != nil {
		t.Fatalf("SecureWriteFile() error = %v", err)
	}

	raw, err := storage.ReadOrMigrateFile("subscription.json")
	if err != nil {
		t.Fatalf("storage.ReadOrMigrateFile() error = %v", err)
	}
	if !bytes.HasPrefix(raw, []byte(MagicHeaderV2)) {
		t.Fatalf("stored data prefix = %q, want %q", raw[:len(MagicHeaderV2)], MagicHeaderV2)
	}
	if bytes.Contains(raw, []byte("token=secret")) {
		t.Fatal("stored encrypted data contains plaintext subscription token")
	}

	got, err := SecureReadFile("subscription.json")
	if err != nil {
		t.Fatalf("SecureReadFile() error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("SecureReadFile() = %q, want %q", got, plaintext)
	}
}

func TestSecureReadFileStillReadsLegacyV1Format(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	plaintext := []byte("legacy secret")
	legacyCiphertext, err := encryptWithKey(deriveLegacyKey(), plaintext)
	if err != nil {
		t.Fatalf("legacy encryptWithKey() error = %v", err)
	}
	raw := append([]byte(MagicHeader), legacyCiphertext...)
	if err := storage.Write("legacy.json", raw); err != nil {
		t.Fatalf("storage.Write() error = %v", err)
	}

	got, err := SecureReadFile("legacy.json")
	if err != nil {
		t.Fatalf("SecureReadFile() legacy error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("SecureReadFile() legacy = %q, want %q", got, plaintext)
	}
}

func TestSecureReadFileMigratesPlaintextToV2Format(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	plaintext := []byte("plain migration secret")
	if err := storage.Write("subscription.json", plaintext); err != nil {
		t.Fatalf("storage.Write() error = %v", err)
	}

	got, err := SecureReadFile("subscription.json")
	if err != nil {
		t.Fatalf("SecureReadFile() plaintext migration error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("SecureReadFile() plaintext = %q, want %q", got, plaintext)
	}

	raw, err := storage.ReadOrMigrateFile("subscription.json")
	if err != nil {
		t.Fatalf("storage.ReadOrMigrateFile() error = %v", err)
	}
	if !bytes.HasPrefix(raw, []byte(MagicHeaderV2)) {
		t.Fatalf("migrated plaintext prefix = %q, want %q", raw[:len(MagicHeaderV2)], MagicHeaderV2)
	}
	if bytes.Contains(raw, plaintext) {
		t.Fatal("migrated plaintext still appears in raw storage")
	}
}

func TestSecureReadFileRejectsUnexpectedPlaintext(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	plaintext := []byte("unexpected plaintext")
	if err := storage.Write("plain.json", plaintext); err != nil {
		t.Fatalf("storage.Write() error = %v", err)
	}

	if _, err := SecureReadFile("plain.json"); err == nil {
		t.Fatal("SecureReadFile() accepted plaintext for unexpected key")
	}

	raw, err := storage.ReadOrMigrateFile("plain.json")
	if err != nil {
		t.Fatalf("storage.ReadOrMigrateFile() error = %v", err)
	}
	if !bytes.Equal(raw, plaintext) {
		t.Fatalf("unexpected plaintext was rewritten: %q", raw)
	}
}
