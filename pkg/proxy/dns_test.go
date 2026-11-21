package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wing/pkg/common"
	"wing/pkg/routing"

	"github.com/miekg/dns"
)

func TestGetDNSServerByIDReturnsCopy(t *testing.T) {
	oldConfig := GetDNSConfig()
	t.Cleanup(func() { SetDNSConfig(oldConfig) })

	SetDNSConfig(DNSConfig{
		Servers: []DNSServer{{ID: "one", Name: "One", Address: "1.1.1.1:53", Type: "udp"}},
		Default: "one",
	})

	server := GetDNSServerByID("one")
	if server == nil {
		t.Fatal("expected DNS server")
	}
	server.Address = "8.8.8.8:53"

	snapshot := GetDNSConfig()
	if snapshot.Servers[0].Address != "1.1.1.1:53" {
		t.Fatalf("DNS server mutation leaked into config: %+v", snapshot.Servers[0])
	}
}

func TestPruneDNSCacheDoesNotClearEntireCache(t *testing.T) {
	dnsCacheMu.Lock()
	oldCache := dnsCache
	dnsCache = make(map[string]dnsCacheEntry)
	now := time.Now()
	for i := 0; i < maxDnsCacheSize+10; i++ {
		dnsCache[fmt.Sprintf("example-%d", i)] = dnsCacheEntry{
			msg:       &dns.Msg{},
			expiresAt: now.Add(time.Minute),
		}
	}
	pruneDNSCacheLocked(now)
	got := len(dnsCache)
	dnsCache = oldCache
	dnsCacheMu.Unlock()

	if got == 0 {
		t.Fatal("pruneDNSCacheLocked() cleared the entire cache")
	}
	if got > dnsCacheTrimTarget {
		t.Fatalf("pruneDNSCacheLocked() size = %d, want <= %d", got, dnsCacheTrimTarget)
	}
}

func TestIPDomainMapPrunesAtHardLimit(t *testing.T) {
	oldMap := IPToDomainMap
	oldSize := ipDomainMapSize.Load()
	IPToDomainMap = sync.Map{}
	ipDomainMapSize.Store(0)
	t.Cleanup(func() {
		IPToDomainMap = oldMap
		ipDomainMapSize.Store(oldSize)
	})

	now := time.Now()
	for i := 0; i < maxIPDomainMapSize; i++ {
		storeIPDomainMapping(fmt.Sprintf("192.0.2.%d", i), ipDomainEntry{
			domain:    "example.test",
			expiresAt: now.Add(time.Minute),
		})
	}

	got := ipDomainMapSize.Load()
	if got == 0 {
		t.Fatal("storeIPDomainMapping() pruned the entire IP-domain map")
	}
	if got > ipDomainMapTrimTarget {
		t.Fatalf("IP-domain map size = %d, want <= %d", got, ipDomainMapTrimTarget)
	}
}

func TestSelectDNSServerRoutesDirectDomainsDirectly(t *testing.T) {
	oldConfig := GetDNSConfig()
	oldRules := routing.RuleGroups
	oldMode := common.GetProxyMode()
	t.Cleanup(func() {
		SetDNSConfig(oldConfig)
		routing.RuleGroups = oldRules
		common.SetProxyMode(oldMode)
	})

	common.SetProxyMode("Rule")
	routing.RuleGroups = routing.DefaultRuleGroups()
	cfg := defaultDNSConfig()

	for _, domain := range []string{"www.douyin.com.", "v26-web.douyinvod.com.", "example.cn."} {
		srv, direct := selectDNSServer(cfg, domain)
		if !direct {
			t.Fatalf("selectDNSServer(%q) resolveDirect = false, want true", domain)
		}
		if srv == nil || srv.ID != "aliyun" {
			t.Fatalf("selectDNSServer(%q) server = %+v, want aliyun", domain, srv)
		}
	}

	srv, direct := selectDNSServer(cfg, "www.google.com.")
	if direct {
		t.Fatalf("selectDNSServer(google) resolveDirect = true, want false")
	}
	if srv == nil || srv.ID != "google" {
		t.Fatalf("selectDNSServer(google) server = %+v, want google", srv)
	}

	cfg.Rules = append(cfg.Rules, DNSRule{Type: "domain_suffix", Value: "custom.example", ServerID: "tencent"})
	srv, direct = selectDNSServer(cfg, "sub.custom.example.")
	if !direct || srv == nil || srv.ID != "tencent" {
		t.Fatalf("selectDNSServer(custom tencent) = (%+v, %v), want (tencent, true)", srv, direct)
	}
}

func TestIPDomainMapMinTTLFloorAndHTTPSHints(t *testing.T) {
	oldMap := IPToDomainMap
	oldSize := ipDomainMapSize.Load()
	IPToDomainMap = sync.Map{}
	ipDomainMapSize.Store(0)
	dnsCacheMu.Lock()
	oldCache := dnsCache
	dnsCache = make(map[string]dnsCacheEntry)
	dnsCacheMu.Unlock()
	t.Cleanup(func() {
		IPToDomainMap = oldMap
		ipDomainMapSize.Store(oldSize)
		dnsCacheMu.Lock()
		dnsCache = oldCache
		dnsCacheMu.Unlock()
	})

	now := time.Now()
	if got := ipDomainEntryExpiry(13, now).Sub(now); got != time.Duration(minIPDomainMapTTL)*time.Second {
		t.Fatalf("ipDomainEntryExpiry(13) = %v, want %v", got, time.Duration(minIPDomainMapTTL)*time.Second)
	}

	msg := new(dns.Msg)
	msg.SetQuestion("www.douyin.com.", dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "www.douyin.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 13},
			A:   net.ParseIP("113.105.155.53").To4(),
		},
		&dns.HTTPS{
			SVCB: dns.SVCB{
				Hdr:      dns.RR_Header{Name: "www.douyin.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 19},
				Priority: 1,
				Target:   ".",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("42.123.118.71").To4()}},
				},
			},
		},
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("msg.Pack(): %v", err)
	}

	cacheKey := dnsCacheKey("www.douyin.com", dns.TypeA)
	if parsed := cacheDNSResponse("www.douyin.com", cacheKey, packed); parsed == nil {
		t.Fatal("cacheDNSResponse returned nil")
	}

	for _, ip := range []string{"113.105.155.53", "42.123.118.71"} {
		domain, ok := domainForIP(ip)
		if !ok || domain != "www.douyin.com" {
			t.Fatalf("domainForIP(%s) = (%q, %v), want (\"www.douyin.com\", true)", ip, domain, ok)
		}
		raw, _ := IPToDomainMap.Load(ip)
		entry := raw.(ipDomainEntry)
		if time.Until(entry.expiresAt) < 25*time.Minute {
			t.Fatalf("IPToDomainMap[%s] expiry %v too short", ip, time.Until(entry.expiresAt))
		}
	}

	dnsCacheMu.RLock()
	cached, ok := dnsCache[cacheKey]
	dnsCacheMu.RUnlock()
	if !ok {
		t.Fatalf("expected dnsCache entry for %s", cacheKey)
	}
	if time.Until(cached.expiresAt) < 45*time.Second {
		t.Fatalf("dnsCache TTL %v too short", time.Until(cached.expiresAt))
	}
}

func TestDomainForIPDecrementsMapSizeOnExpiry(t *testing.T) {
	oldMap := IPToDomainMap
	oldSize := ipDomainMapSize.Load()
	IPToDomainMap = sync.Map{}
	ipDomainMapSize.Store(0)
	t.Cleanup(func() {
		IPToDomainMap = oldMap
		ipDomainMapSize.Store(oldSize)
	})

	storeIPDomainMapping("203.0.113.55", ipDomainEntry{
		domain:    "expired.example",
		expiresAt: time.Now().Add(-time.Second),
	})
	if got := ipDomainMapSize.Load(); got != 1 {
		t.Fatalf("ipDomainMapSize after store = %d, want 1", got)
	}

	if domain, ok := domainForIP("203.0.113.55"); ok || domain != "" {
		t.Fatalf("domainForIP(expired) = (%q, %v), want (\"\", false)", domain, ok)
	}
	if got := ipDomainMapSize.Load(); got != 0 {
		t.Fatalf("ipDomainMapSize after expired lookup = %d, want 0", got)
	}
}

func TestResolveDNSWithDedupeCoalescesConcurrentQueries(t *testing.T) {
	dnsCacheMu.Lock()
	oldCache := dnsCache
	dnsCache = make(map[string]dnsCacheEntry)
	dnsCacheMu.Unlock()
	t.Cleanup(func() {
		dnsCacheMu.Lock()
		dnsCache = oldCache
		dnsCacheMu.Unlock()
	})

	var upstreamCalls atomic.Int32
	gate := make(chan struct{})
	queryFn := func(ctx context.Context, domain string, reqData []byte) ([]byte, error) {
		upstreamCalls.Add(1)
		<-gate
		reply := new(dns.Msg)
		reply.SetQuestion("dedupe.example.", dns.TypeA)
		reply.Response = true
		reply.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "dedupe.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
				A:   net.ParseIP("198.51.100.10").To4(),
			},
		}
		return reply.Pack()
	}

	cacheKey := dnsCacheKey("dedupe.example", dns.TypeA)
	const workers = 6
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()
			msg, err := resolveDNSWithDedupe(cacheKey, "dedupe.example", nil, queryFn)
			if err != nil {
				errs <- err
				return
			}
			packed, ok := packDNSReply(msg, id, "dedupe.example.")
			if !ok {
				errs <- fmt.Errorf("packDNSReply failed for id=%d", id)
				return
			}
			decoded := new(dns.Msg)
			if err := decoded.Unpack(packed); err != nil {
				errs <- err
				return
			}
			if decoded.Id != id {
				errs <- fmt.Errorf("decoded ID = %d, want %d", decoded.Id, id)
			}
		}(uint16(100 + i))
	}

	// Allow all goroutines to join the in-flight call before completing upstream query.
	time.Sleep(40 * time.Millisecond)
	close(gate)
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatal(err)
	}
	if calls := upstreamCalls.Load(); calls != 1 {
		t.Fatalf("upstream calls = %d, want 1 coalesced query", calls)
	}
}
