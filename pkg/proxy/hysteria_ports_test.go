package proxy

import (
	"reflect"
	"testing"
)

func TestNormalizeHysteriaPorts(t *testing.T) {
	for _, input := range []string{"[40000:50000]", "40000-50000", "[\"40000:50000\"]"} {
		if got := normalizeHysteriaPorts(input); !reflect.DeepEqual(got, []string{"40000:50000"}) {
			t.Fatalf("%q: got %v", input, got)
		}
		if got := parseFirstPort(input); got != 40000 {
			t.Fatalf("first port of %q: %d", input, got)
		}
	}
	if got := normalizeHysteriaPorts("[443, 40000-50000]"); !reflect.DeepEqual(got, []string{"443", "40000:50000"}) {
		t.Fatalf("multiple ports: %v", got)
	}
}
