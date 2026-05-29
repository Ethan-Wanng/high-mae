package storage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "github.com/sagernet/bbolt"
)

const DBFile = "wing.db"

var (
	dataBucket = []byte("data")
	globalDB   *bolt.DB
	dbMutex    sync.Mutex
)

func databasePath() string {
	if path := strings.TrimSpace(os.Getenv("WING_DB_PATH")); path != "" {
		return path
	}
	return DBFile
}

func getDB() (*bolt.DB, error) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	if globalDB != nil {
		return globalDB, nil
	}

	path, err := filepath.Abs(databasePath())
	if err != nil {
		return nil, err
	}

	opened, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	err = opened.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(dataBucket)
		return err
	})
	if err != nil {
		_ = opened.Close()
		return nil, err
	}
	globalDB = opened
	return globalDB, nil
}

func Close() error {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	if globalDB != nil {
		err := globalDB.Close()
		globalDB = nil
		return err
	}
	return nil
}

func normalizeKey(key string) []byte {
	clean := filepath.Clean(strings.TrimSpace(key))
	clean = strings.ReplaceAll(clean, "\\", "/")
	return []byte(clean)
}

func Read(key string) ([]byte, error) {
	database, err := getDB()
	if err != nil {
		return nil, err
	}

	var out []byte
	err = database.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(dataBucket)
		value := bucket.Get(normalizeKey(key))
		if value == nil {
			return os.ErrNotExist
		}
		out = append([]byte(nil), value...)
		return nil
	})
	return out, err
}

func Write(key string, data []byte) error {
	database, err := getDB()
	if err != nil {
		return err
	}
	return database.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(dataBucket)
		if err != nil {
			return err
		}
		return bucket.Put(normalizeKey(key), data)
	})
}

func Delete(key string) error {
	database, err := getDB()
	if err != nil {
		return err
	}
	return database.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(dataBucket)
		if bucket == nil {
			return nil
		}
		return bucket.Delete(normalizeKey(key))
	})
}

func ReadOrMigrateFile(key string) ([]byte, error) {
	if fileData, ok := readNewerFile(key); ok {
		if err := Write(key, fileData); err != nil {
			return nil, err
		}
		return fileData, nil
	}

	data, err := Read(key)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return data, err
	}

	data, err = os.ReadFile(key)
	if err != nil {
		return nil, err
	}
	if writeErr := Write(key, data); writeErr != nil {
		return nil, writeErr
	}
	return data, nil
}

func readNewerFile(key string) ([]byte, bool) {
	fileInfo, err := os.Stat(key)
	if err != nil {
		return nil, false
	}
	dbInfo, err := os.Stat(databasePath())
	if err == nil && !fileInfo.ModTime().After(dbInfo.ModTime()) {
		return nil, false
	}
	data, err := os.ReadFile(key)
	if err != nil {
		return nil, false
	}
	return data, true
}
