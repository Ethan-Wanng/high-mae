package protocol

import (
	"fmt"
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
	hp := strings.Split(hostPort, ":")
	if len(hp) != 2 {
		return Node{}, fmt.Errorf("invalid ssocks hostport")
	}
	port, _ := strconv.Atoi(hp[1])

	return Node{
		Type:     "socks5", // mapping ssocks to socks5 type
		Name:     name,
		Server:   hp[0],
		Port:     port,
		Username: auth[:colon],
		Password: auth[colon+1:],
		Method:   method,
		TLS:      true,
		Tls:      true,
		SNI:      hp[0],
	}, nil
}
