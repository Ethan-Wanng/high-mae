package webui

import (
	_ "embed"
	"html"
	"io"
	"net/http"
	"strings"
)

//go:embed ui/index.html
var indexHTML string

//go:embed ui/style.css
var styleCSS string

//go:embed ui/script.js
var scriptJS string

//go:embed ui/logo-mark.png
var logoMarkPNG []byte

//go:embed ui/logo-mark-app.png
var logoMarkAppPNG []byte

//go:embed ui/logo-mark-direct-dark.png
var logoMarkDirectDarkPNG []byte

//go:embed ui/logo-mark-direct-light.png
var logoMarkDirectLightPNG []byte

//go:embed ui/logo-mark-proxy.png
var logoMarkProxyPNG []byte

//go:embed ui/logo-mark-tun.png
var logoMarkTunPNG []byte

//go:embed ui/logo-mark-proxy-tun.png
var logoMarkProxyTunPNG []byte

func setWebUISecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), hid=(), interest-cohort=()")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
}

func serveHTML(w http.ResponseWriter, r *http.Request) {
	setWebUISecurityHeaders(w)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, renderIndexHTML())
}

func serveHealth(w http.ResponseWriter, r *http.Request) {
	setWebUISecurityHeaders(w)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func renderIndexHTML() string {
	tokenMeta := `<meta name="wing-api-token" content="` + html.EscapeString(apiRequestToken) + `">`
	if strings.Contains(indexHTML, `name="wing-api-token"`) {
		return indexHTML
	}
	if strings.Contains(indexHTML, "</head>") {
		return strings.Replace(indexHTML, "</head>", "    "+tokenMeta+"\n</head>", 1)
	}
	return tokenMeta + indexHTML
}

func serveCSS(w http.ResponseWriter, r *http.Request) {
	setWebUISecurityHeaders(w)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Type", "text/css")
	io.WriteString(w, styleCSS)
}

func serveJS(w http.ResponseWriter, r *http.Request) {
	setWebUISecurityHeaders(w)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Type", "application/javascript")
	io.WriteString(w, scriptJS)
}

func serveLogoMark(w http.ResponseWriter, r *http.Request) {
	setWebUISecurityHeaders(w)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Type", "image/png")
	w.Write(logoMarkPNG)
}

func servePNGBytes(w http.ResponseWriter, _ *http.Request, data []byte) {
	setWebUISecurityHeaders(w)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Type", "image/png")
	w.Write(data)
}
