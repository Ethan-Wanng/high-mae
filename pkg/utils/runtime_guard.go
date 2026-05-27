package utils

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"time"
)

func SafeGo(name string, fn func()) {
	go func() {
		defer RecoverPanic(name)
		fn()
	}()
}

func RecoverPanic(name string) {
	if r := recover(); r != nil {
		WriteCrashLog(name, r)
		log.Printf("%s panic recovered: %v", name, r)
	}
}

func WriteCrashLog(name string, recovered any) {
	f, err := os.OpenFile("wing-crash.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	_, _ = fmt.Fprintf(f, "[%s] %s panic: %v\n%s\n",
		time.Now().Format(time.RFC3339),
		name,
		recovered,
		debug.Stack(),
	)
}
