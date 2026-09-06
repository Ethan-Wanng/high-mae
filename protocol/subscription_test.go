package protocol

import "testing"

func TestParseClashMetaSubscriptionVariants(t *testing.T) {
	raw := []byte(`proxies:
  - {name: hy2-basic, type: hysteria2, server: hy.example, port: 443, password: secret, sni: hy.example, fingerprint: cert-hash, skip-cert-verify: true, udp: true}
  - {name: hy2-hopping, type: hysteria2, server: hop.example, port: 443, ports: 20000-30000, mport: 20000-30000, password: secret, sni: hop.example, skip-cert-verify: true, udp: true}
  - {name: vless-ws, type: vless, server: ws.example, port: 443, uuid: test-uuid, tls: true, network: ws, servername: ws.example, client-fingerprint: chrome, ws-opts: {path: /ws, headers: {Host: edge.example}}}
  - {name: vless-reality, type: vless, server: reality.example, port: 443, uuid: test-uuid, tls: true, servername: reality.example, client-fingerprint: chrome, reality-opts: {public-key: test-key, short-id: abcd}}
  - {name: vless-tcp, type: vless, server: tcp.example, port: 443, uuid: test-uuid, tls: true, servername: tcp.example, client-fingerprint: chrome}
proxy-groups: []
`)

	nodes, err := ParseSubscriptionRaw(raw)
	if err != nil {
		t.Fatalf("ParseSubscriptionRaw() error = %v", err)
	}
	if len(nodes) != 5 {
		t.Fatalf("ParseSubscriptionRaw() returned %d nodes, want 5", len(nodes))
	}
	if nodes[0].CertificateFingerprint != "cert-hash" || !nodes[0].SkipCertVerify {
		t.Fatalf("hysteria2 certificate fields were not preserved: %+v", nodes[0])
	}
	if nodes[1].Ports != "20000-30000" || nodes[1].MPort != "20000-30000" {
		t.Fatalf("hysteria2 port hopping fields were not preserved: %+v", nodes[1])
	}
	if nodes[2].Network != "ws" || nodes[2].WSOpts.Path != "/ws" || nodes[2].WSOpts.Headers["Host"] != "edge.example" {
		t.Fatalf("VLESS WebSocket fields were not preserved: %+v", nodes[2])
	}
	if nodes[3].RealityOpts == nil || nodes[3].RealityOpts.PublicKey != "test-key" || nodes[3].RealityOpts.ShortID != "abcd" {
		t.Fatalf("VLESS Reality fields were not preserved: %+v", nodes[3])
	}
}
