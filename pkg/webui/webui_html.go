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

func serveHTML(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, indexHTML)
}

func serveCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css")
	io.WriteString(w, styleCSS)
}

func serveJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	io.WriteString(w, scriptJS)
}
