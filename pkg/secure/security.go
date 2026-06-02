package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"wing/pkg/storage"
)

const MagicHeader = "HMSEC\x01"

var (
	cachedMachineID string
	cachedKey       []byte
	cachedKeyOnce   sync.Once
)

func GetMachineID() string {
	if cachedMachineID != "" {
		return cachedMachineID
	}

	var id string
	if runtime.GOOS == "windows" {
		cmd1 := exec.Command("cmd", "/c", "reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid")
		if out, err := cmd1.Output(); err == nil {
			id = parseRegValue(string(out), "MachineGuid")
		}
		if id == "" {
			cmd2 := exec.Command("wmic", "csproduct", "get", "uuid")
			out, err := cmd2.Output()
			if err == nil {
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

func DeriveKey() []byte {
	cachedKeyOnce.Do(func() {
		hash := sha256.Sum256([]byte(GetMachineID() + "AnyTLS-Security-Salt"))
		cachedKey = hash[:]
	})
	return cachedKey
}

func EncryptData(data []byte) ([]byte, error) {
	key := DeriveKey()
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
	if len(data) < 12 {
		return nil, fmt.Errorf("数据太短，不符合加密格式")
	}

	key := DeriveKey()
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
	finalData := append([]byte(MagicHeader), encrypted...)
	return storage.Write(filename, finalData)
}

func writeFileBestEffortAtomic(filename string, data []byte, perm os.FileMode) error {
	dir := "."
	if idx := strings.LastIndexAny(filename, `\/`); idx >= 0 {
		dir = filename[:idx]
	}
	tmp, err := os.CreateTemp(dir, ".wing-*")
	if err != nil {
		return os.WriteFile(filename, data, perm)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filename); err != nil {
		if removeErr := os.Remove(filename); removeErr != nil && !os.IsNotExist(removeErr) {
			return err
		}
		return os.Rename(tmpName, filename)
	}
	return nil
}

func SecureReadFile(filename string) ([]byte, error) {
	data, err := storage.ReadOrMigrateFile(filename)
	if err != nil {
		return nil, err
	}

	if len(data) > len(MagicHeader) && string(data[:len(MagicHeader)]) == MagicHeader {
		return DecryptData(data[len(MagicHeader):])
	}
	return data, nil
}
