//go:build android && cgo

package main

import "log"

func configureAndroidDNS() {
	log.Println("[Android Core] Using Bionic system DNS resolver (cgo enabled)")
}
