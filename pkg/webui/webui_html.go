package webui

import (
	_ "embed"
	"io"
	"net/http"
)

//go:embed ui/index.html
var indexHTML string

//go:embed ui/style.css
var styleCSS string

//go:embed ui/script.js
var scriptJS string

//go:embed ui/logo-mark.png
var logoMarkPNG []byte

func setWebUISecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), hid=(), interest-cohort=()")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
}

func serveHTML(w http.ResponseWriter, r *http.Request) {
	setWebUISecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, indexHTML)
}

func serveCSS(w http.ResponseWriter, r *http.Request) {
	setWebUISecurityHeaders(w)
	w.Header().Set("Content-Type", "text/css")
	io.WriteString(w, styleCSS)
}

func serveJS(w http.ResponseWriter, r *http.Request) {
	setWebUISecurityHeaders(w)
	w.Header().Set("Content-Type", "application/javascript")
	io.WriteString(w, scriptJS)
}

func serveLogoMark(w http.ResponseWriter, r *http.Request) {
	setWebUISecurityHeaders(w)
	w.Header().Set("Content-Type", "image/png")
	w.Write(logoMarkPNG)
}
