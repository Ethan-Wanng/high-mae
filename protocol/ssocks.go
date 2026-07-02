package protocol

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func ParseSSocks(link string) (Node, error) {
	raw := strings.TrimSpace(strings.TrimPrefix(link, "ssocks://"))
	name := ""
	method := "auto"

	if i := strings.Index(raw, "?"); i >= 0 {
		queryStr := raw[i+1:]
		raw = raw[:i]
		q, _ := url.ParseQuery(queryStr)
		if r := q.Get("remarks"); r != "" {
			name = r
		}
		if m := q.Get("method"); m != "" {
			method = m
		}
	}
	if decoded, ok := tryBase64Variants(raw); ok {
		raw = string(decoded)
	}

	at := strings.LastIndex(raw, "@")
	if at < 0 {
		return Node{}, fmt.Errorf("invalid ssocks uri")
	}
	auth := raw[:at]
	hostPort := raw[at+1:]

	colon := strings.Index(auth, ":")
	if colon < 0 {
		return Node{}, fmt.Errorf("invalid ssocks auth")
	}
	host, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		return Node{}, fmt.Errorf("invalid ssocks hostport")
	}
	port, _ := strconv.Atoi(portText)

	return Node{
		Type:     "socks5", // mapping ssocks to socks5 type
		Name:     name,
		Server:   host,
		Port:     port,
		Username: auth[:colon],
		Password: auth[colon+1:],
		Method:   method,
		TLS:      true,
		Tls:      true,
		SNI:      host,
	}, nil
}
