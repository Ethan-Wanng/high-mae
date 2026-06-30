package proxy

import (
	"path/filepath"
	"testing"

	"wing/pkg/storage"
)

func TestResolveNetworkModeForPrivilegeDisablesTunWithoutAdmin(t *testing.T) {
	tests := []struct {
		name          string
		state         NetworkModeState
		isAdmin       bool
		wantPreset    string
		wantProxy     bool
		wantTun       bool
		wantDowngrade bool
	}{
		{
			name:          "proxy tun without admin becomes proxy",
			state:         NetworkModeState{Proxy: true, Tun: true, Preset: "proxy_tun"},
			wantPreset:    "proxy",
			wantProxy:     true,
			wantTun:       false,
			wantDowngrade: true,
		},
		{
			name:          "tun without admin becomes direct",
			state:         NetworkModeState{Proxy: false, Tun: true, Preset: "tun"},
			wantPreset:    "direct",
			wantProxy:     false,
			wantTun:       false,
			wantDowngrade: true,
		},
		{
			name:          "proxy tun with admin is kept",
			state:         NetworkModeState{Proxy: true, Tun: true, Preset: "proxy_tun"},
			isAdmin:       true,
			wantPreset:    "proxy_tun",
			wantProxy:     true,
			wantTun:       true,
			wantDowngrade: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, downgraded := resolveNetworkModeForPrivilege(tt.state, tt.isAdmin)
			if got.Preset != tt.wantPreset || got.Proxy != tt.wantProxy || got.Tun != tt.wantTun || downgraded != tt.wantDowngrade {
				t.Fatalf("resolveNetworkModeForPrivilege() = %+v/%v, want preset=%s proxy=%v tun=%v downgrade=%v",
					got, downgraded, tt.wantPreset, tt.wantProxy, tt.wantTun, tt.wantDowngrade)
			}
		})
	}
}

func TestSaveLoadLastNetworkMode(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	if err := SaveLastNetworkMode(true, true); err != nil {
		t.Fatalf("SaveLastNetworkMode() error = %v", err)
	}
	state, ok, err := LoadLastNetworkMode()
	if err != nil {
		t.Fatalf("LoadLastNetworkMode() error = %v", err)
	}
	if !ok {
		t.Fatal("LoadLastNetworkMode() ok = false, want true")
	}
	if !state.Proxy || !state.Tun || state.Preset != "proxy_tun" {
		t.Fatalf("loaded state = %+v, want proxy_tun", state)
	}
}
