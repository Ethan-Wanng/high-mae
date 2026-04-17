package protocol

import (
	"net/url"
	"strconv"
)

func ParseTUIC(link string) (Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Node{}, err
	}
	port, _ := strconv.Atoi(u.Port())
	name, _ := url.QueryUnescape(u.Fragment)
	password, _ := u.User.Password()
	if password == "" {
		password = u.Query().Get("password")
	}
	return Node{
			Type:           "tuic",
			Name:           name,
			Server:         u.Hostname(),
			Port:           port,
			UUID:           u.User.Username(),
			Password:       password,
			SNI:            u.Query().Get("sni"),
			ALPN:           []string{u.Query().Get("alpn")},
			SkipCertVerify: u.Query().Get("allow_insecure") == "1"},
		nil
}
