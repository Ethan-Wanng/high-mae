package proxy

import (
	"fmt"
	"sync"
	"testing"
	"time"

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
