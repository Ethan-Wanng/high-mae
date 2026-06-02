//go:build !windows

package routing

import "strings"

func ToggleWebRTCLeak(enable bool) {}

func CheckWebRTCLeakStatus() bool {
	return false
}

var StunDomains = []string{
	"stun.l.google.com",
	"stun1.l.google.com",
	"stun2.l.google.com",
	"stun3.l.google.com",
	"stun4.l.google.com",
	"stun.voipbuster.com",
	"stun.voipstunt.com",
	"stun.ekiga.net",
	"stun.ideasip.com",
	"stun.schlund.de",
	"stun.softjoys.com",
	"stun.voiparound.com",
	"stun.voipgate.com",
	"stun.xten.com",
	"stun.turnserver.net",
	"stun.rixtelecom.se",
	"stun.iptel.org",
	"stun.fwdnet.net",
	"stun.mit.edu",
	"stun.callwithus.com",
	"stun.counterpath.com",
	"stun.internetcalls.com",
}

func IsStunDomain(domain string) bool {
	domain = strings.ToLower(domain)
	if host, _, found := strings.Cut(domain, ":"); found {
		domain = host
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if isStunLikeLabel(label) {
			return true
		}
	}
	for _, d := range StunDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

func isStunLikeLabel(label string) bool {
	for _, prefix := range []string{"stun", "turn"} {
		if label == prefix {
			return true
		}
		if strings.HasPrefix(label, prefix) && len(label) > len(prefix) {
			next := label[len(prefix)]
			if next >= '0' && next <= '9' {
				return true
			}
		}
	}
	return false
}
