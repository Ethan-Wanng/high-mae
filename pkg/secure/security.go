package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"wing/pkg/storage"
)

const (
	MagicHeader       = "HMSEC\x01"
	MagicHeaderV2     = "HMSEC\x02"
	kdfSaltSize       = 16
	kdfIterations     = 120000
	encryptionKeySize = 32
)

var (
	cachedMachineID string
	cachedLegacyKey []byte
	legacyKeyOnce   sync.Once
)

func GetMachineID() string {
	if cachedMachineID != "" {
		return cachedMachineID
	}

	var id string
	if runtime.GOOS == "windows" {
		if out, err := runMachineIDCommand("cmd", "/c", "reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid"); err == nil {
			id = parseRegValue(string(out), "MachineGuid")
		}
		if id == "" {
			if out, err := runMachineIDCommand("wmic", "csproduct", "get", "uuid"); err == nil {
				lines := strings.Split(string(out), "\n")
				if len(lines) >= 2 {
					id = strings.TrimSpace(lines[1])
				}
			}
		}
	}
	if id == "" {
		hostname, _ := os.Hostname()
		home, _ := os.UserHomeDir()
		id = hostname + "|" + home + "|wing-fallback-key"
	}
	cachedMachineID = id
	return id
}

func parseRegValue(output string, valueName string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && strings.EqualFold(fields[0], valueName) {
			return strings.Join(fields[2:], " ")
		}
	}
	return ""
}

func deriveLegacyKey() []byte {
	legacyKeyOnce.Do(func() {
		hash := sha256.Sum256([]byte(GetMachineID() + "AnyTLS-Security-Salt"))
		cachedLegacyKey = hash[:]
	})
	return cachedLegacyKey
}

func deriveKey(salt []byte) ([]byte, error) {
	if len(salt) != kdfSaltSize {
		return nil, fmt.Errorf("无效的加密 salt")
	}
	return pbkdf2.Key(sha256.New, GetMachineID(), salt, kdfIterations, encryptionKeySize)
}

func EncryptData(data []byte) ([]byte, error) {
	salt := make([]byte, kdfSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key, err := deriveKey(salt)
	if err != nil {
		return nil, err
	}
	encrypted, err := encryptWithKey(key, data)
	if err != nil {
		return nil, err
	}
	return append(salt, encrypted...), nil
}

func encryptWithKey(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func DecryptData(data []byte) ([]byte, error) {
	if len(data) < kdfSaltSize+12 {
		return nil, fmt.Errorf("数据太短，不符合加密格式")
	}
	salt, encrypted := data[:kdfSaltSize], data[kdfSaltSize:]
	key, err := deriveKey(salt)
	if err != nil {
		return nil, err
	}
	return decryptWithKey(key, encrypted)
}

func decryptLegacyData(data []byte) ([]byte, error) {
	return decryptWithKey(deriveLegacyKey(), data)
}

func decryptWithKey(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("无效的密文")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func SecureWriteFile(filename string, data []byte) error {
	if len(data) == 0 {
		return storage.Write(filename, nil)
	}
	encrypted, err := EncryptData(data)
	if err != nil {
		return err
	}
	finalData := append([]byte(MagicHeaderV2), encrypted...)
	return storage.Write(filename, finalData)
}

func SecureReadFile(filename string) ([]byte, error) {
	data, err := storage.ReadOrMigrateFile(filename)
	if err != nil {
		return nil, err
	}

	if len(data) > len(MagicHeaderV2) && string(data[:len(MagicHeaderV2)]) == MagicHeaderV2 {
		return DecryptData(data[len(MagicHeaderV2):])
	}
	if len(data) > len(MagicHeader) && string(data[:len(MagicHeader)]) == MagicHeader {
		return decryptLegacyData(data[len(MagicHeader):])
	}
	if len(data) > 0 {
		if !allowPlaintextSecureMigration(filename) {
			return nil, fmt.Errorf("拒绝迁移未加密的安全存储文件: %s", filename)
		}
		if err := SecureWriteFile(filename, data); err != nil {
			return nil, err
		}
	}
	return data, nil
}

var plaintextMigrationExactFiles = map[string]struct{}{
	"aggregate_groups.json":   {},
	"auto_select_config.json": {},
	"cmd_rules.json":          {},
	"dns_config.json":         {},
	"rule_groups.json":        {},
	"site_test_targets.json":  {},
	"subscription.json":       {},
}

func allowPlaintextSecureMigration(filename string) bool {
	name := secureStorageBaseName(filename)
	if name == "" {
		return false
	}
	if _, ok := plaintextMigrationExactFiles[name]; ok {
		return true
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".yml", ".yaml":
		return true
	default:
		return false
	}
}

func secureStorageBaseName(filename string) string {
	name := strings.TrimSpace(filename)
	if name == "" || filepath.IsAbs(name) {
		return ""
	}
	name = filepath.Clean(name)
	name = strings.ReplaceAll(name, "\\", "/")
	if name == "." || name == ".." || strings.Contains(name, "/") {
		return ""
	}
	return name
}
