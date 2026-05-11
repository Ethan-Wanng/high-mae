package protocol

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func ParseSS(link string) (Node, error) {
	raw := strings.TrimSpace(strings.TrimPrefix(link, "ss://"))
	name := ""
	if i := strings.Index(raw, "#"); i >= 0 {
		name, _ = url.QueryUnescape(raw[i+1:])
		raw = raw[:i]
	}
	if i := strings.Index(raw, "?"); i >= 0 {
		raw = raw[:i]
	}
	if decoded, ok := tryBase64Variants(raw); ok {
		raw = string(decoded)
	}
	at := strings.LastIndex(raw, "@")
	if at < 0 {
		return Node{}, fmt.Errorf("invalid ss uri")
	}
	auth := raw[:at]
	hostPort := raw[at+1:]
	colon := strings.Index(auth, ":")
	if colon < 0 {
		return Node{}, fmt.Errorf("invalid ss auth")
	}
	hp := strings.Split(hostPort, ":")
	if len(hp) != 2 {
		return Node{}, fmt.Errorf("invalid ss hostport")
	}
	port, _ := strconv.Atoi(hp[1])
	return Node{Type: "ss", Name: name, Server: hp[0], Port: port, Method: auth[:colon], Password: auth[colon+1:]}, nil
}
