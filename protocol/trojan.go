package protocol

import (
	"net/url"
	"strconv"
)

func ParseTrojan(link string) (Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Node{}, err
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	name, _ := url.QueryUnescape(u.Fragment)
	return Node{Type: "trojan", Name: name, Server: u.Hostname(), Port: port, Password: u.User.Username(), SNI: u.Query().Get("sni"), SkipCertVerify: u.Query().Get("allowInsecure") == "1" || u.Query().Get("skip_cert_verify") == "true"}, nil
}
