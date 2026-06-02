package webui

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
)

//go:embed ui/*
var webuiFS embed.FS

func GetEmbeddedAssets() fs.FS {
	subFS, err := fs.Sub(webuiFS, "ui")
	if err != nil {
		return webuiFS
	}
	return subFS
}

//go:embed ui/index.html
var indexHTML string

//go:embed ui/style.css
var styleCSS string

//go:embed ui/script.js
var scriptJS string

func setWebUISecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
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
