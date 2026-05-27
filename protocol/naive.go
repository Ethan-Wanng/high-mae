package protocol

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func ParseNaive(link string) (Node, error) {
	raw := strings.TrimSpace(link)
	if raw == "" {
		return Node{}, fmt.Errorf("empty naive link")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return Node{}, err
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "naive+https" {
		scheme = "https"
	} else if scheme == "naive+http" {
		scheme = "http"
	} else if scheme == "naive+quic" {
		scheme = "https"
	}

	if u.Hostname() == "" && strings.HasPrefix(strings.ToLower(raw), "naive+") {
		reparsed, reparseErr := url.Parse(strings.TrimPrefix(raw, "naive+"))
		if reparseErr == nil {
			u = reparsed
			scheme = strings.ToLower(u.Scheme)
		}
	}
	if u.Hostname() == "" {
		return Node{}, fmt.Errorf("naive link missing server")
	}

	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		if scheme == "http" {
			port = 80
		} else {
			port = 443
		}
	}

	name, _ := url.QueryUnescape(u.Fragment)
	if name == "" {
		name = u.Hostname()
	}

	password, _ := u.User.Password()
	q := u.Query()
	skipCert := queryBool(q, "insecure") || queryBool(q, "allow_insecure") || queryBool(q, "allowInsecure") || queryBool(q, "skip_cert_verify")
	quic := queryBool(q, "quic") || strings.EqualFold(u.Scheme, "naive+quic")

	return Node{
		Type:                "naive",
		Name:                name,
		Server:              u.Hostname(),
		Port:                port,
		Username:            u.User.Username(),
		Password:            password,
		SNI:                 firstNonEmpty(q.Get("sni"), q.Get("server_name"), q.Get("servername")),
		TLS:                 scheme != "http",
		Tls:                 scheme != "http",
		SkipCertVerify:      skipCert,
		Insecure:            skipCert,
		AllowInsecure:       skipCert,
		QUIC:                quic,
		QUICCongestion:      firstNonEmpty(q.Get("quic_congestion_control"), q.Get("quic-congestion-control")),
		InsecureConcurrency: queryInt(q, "insecure_concurrency"),
	}, nil
}

func queryBool(q url.Values, key string) bool {
	switch strings.ToLower(strings.TrimSpace(q.Get(key))) {
	case "1", "true", "yes", "y":
		return true
	default:
		return false
	}
}

func queryInt(q url.Values, key string) int {
	value, _ := strconv.Atoi(strings.TrimSpace(q.Get(key)))
	return value
}
