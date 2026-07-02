package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"wing/pkg/common"
	"wing/pkg/stats"
	"wing/pkg/storage"
	"wing/pkg/utils"
)

const LastNetworkModeFile = "last_network_mode.json"

type NetworkModeState struct {
	Proxy   bool   `json:"proxy"`
	Tun     bool   `json:"tun"`
	Preset  string `json:"preset"`
	SavedAt int64  `json:"savedAt,omitempty"`
}

type NetworkModeRestoreResult struct {
	HadStored               bool
	Stored                  NetworkModeState
	Applied                 NetworkModeState
	TunDisabledForPrivilege bool
}

var (
	shutdownModeOverrideMu sync.Mutex
	shutdownModeOverride   *NetworkModeState
)

func networkModePreset(proxyOn, tunOn bool) string {
	switch {
	case proxyOn && tunOn:
		return "proxy_tun"
	case proxyOn:
		return "proxy"
	case tunOn:
		return "tun"
	default:
		return "direct"
	}
}

func normalizeNetworkModeState(state NetworkModeState) NetworkModeState {
	switch state.Preset {
	case "direct":
		state.Proxy = false
		state.Tun = false
	case "proxy":
		state.Proxy = true
		state.Tun = false
	case "tun":
		state.Proxy = false
		state.Tun = true
	case "proxy_tun":
		state.Proxy = true
		state.Tun = true
	default:
		state.Preset = networkModePreset(state.Proxy, state.Tun)
		return state
	}
	state.Preset = networkModePreset(state.Proxy, state.Tun)
	return state
}

func resolveNetworkModeForPrivilege(state NetworkModeState, isAdmin bool) (NetworkModeState, bool) {
	state = normalizeNetworkModeState(state)
	if state.Tun && !isAdmin {
		state.Tun = false
		state.Preset = networkModePreset(state.Proxy, state.Tun)
		return state, true
	}
	return state, false
}

func NewNetworkModeState(proxyOn, tunOn bool) NetworkModeState {
	return NetworkModeState{
		Proxy:   proxyOn,
		Tun:     tunOn,
		Preset:  networkModePreset(proxyOn, tunOn),
		SavedAt: time.Now().Unix(),
	}
}

func SaveLastNetworkMode(proxyOn, tunOn bool) error {
	state := NewNetworkModeState(proxyOn, tunOn)
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return storage.Write(LastNetworkModeFile, data)
}

func LoadLastNetworkMode() (NetworkModeState, bool, error) {
	data, err := storage.Read(LastNetworkModeFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewNetworkModeState(false, false), false, nil
		}
		return NetworkModeState{}, false, err
	}
	var state NetworkModeState
	if err := json.Unmarshal(data, &state); err != nil {
		return NetworkModeState{}, true, err
	}
	state = normalizeNetworkModeState(state)
	return state, true, nil
}

func SetShutdownNetworkModeOverride(proxyOn, tunOn bool) {
	state := NewNetworkModeState(proxyOn, tunOn)
	shutdownModeOverrideMu.Lock()
	shutdownModeOverride = &state
	shutdownModeOverrideMu.Unlock()
}

func SaveShutdownNetworkMode() error {
	shutdownModeOverrideMu.Lock()
	override := shutdownModeOverride
	shutdownModeOverride = nil
	shutdownModeOverrideMu.Unlock()
	if override != nil {
		return SaveLastNetworkMode(override.Proxy, override.Tun)
	}
	proxyOn, tunOn, _ := common.GetNetworkState()
	return SaveLastNetworkMode(proxyOn, tunOn)
}

func RestoreLastNetworkMode() (NetworkModeRestoreResult, error) {
	stored, hadStored, err := LoadLastNetworkMode()
	if err != nil {
		return NetworkModeRestoreResult{}, err
	}
	applied, tunDisabled := resolveNetworkModeForPrivilege(stored, utils.IsAdmin())
	result := NetworkModeRestoreResult{
		HadStored:               hadStored,
		Stored:                  stored,
		Applied:                 applied,
		TunDisabledForPrivilege: tunDisabled,
	}
	if err := SetSystemProxyEnabled(applied.Proxy); err != nil {
		return result, err
	}
	if !applied.Proxy {
		if err := utils.SetSystemProxy(false); err != nil {
			return result, err
		}
		common.SetSystemProxyOn(false)
	}
	if msg := SetTunMode(applied.Tun); msg != "" {
		return result, fmt.Errorf("%s", msg)
	}
	proxyOn, tunOn, _ := common.GetNetworkState()
	stats.SyncTrafficSession(proxyOn, tunOn)
	return result, nil
}
