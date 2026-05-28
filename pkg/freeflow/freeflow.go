package freeflow

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
	"wing/pkg/storage"
	"wing/protocol"
)

const (
	NodeName      = "免费流量"
	nodeSourceKey = "builtin_free_flow"
	stateFile     = "free_flow_state.json"
	weeklyLimit   = int64(1024 * 1024 * 1024)
	saveStep      = int64(1024 * 1024)
	weekDuration  = 7 * 24 * time.Hour
)

const builtinNodeLink = "vless://02b016d1-91e5-4b2a-8de1-93813a923a48@129.153.90.9:443?flow=xtls-rprx-vision&fp=ios&pbk=qkP2pqQ3NHNBkyzqsC2W9wChp3OfeXdVjOhUv8vQW0o&security=reality&sid=aac4df9d05a5ba8f&sni=iosapps.itunes.apple.com&type=tcp#free"

type State struct {
	PeriodStart int64 `json:"periodStart"`
	ResetAt     int64 `json:"resetAt"`
	Used        int64 `json:"used"`
	Limit       int64 `json:"limit"`
	Remaining   int64 `json:"remaining"`
	Active      bool  `json:"active"`
	Exceeded    bool  `json:"exceeded"`
}

var (
	mu            sync.Mutex
	loaded        bool
	cachedState   State
	lastSavedUsed int64
)

func Node() (protocol.Node, error) {
	nodes, err := protocol.ParseSubscriptionRaw([]byte(builtinNodeLink))
	if err != nil {
		return protocol.Node{}, err
	}
	if len(nodes) == 0 {
		return protocol.Node{}, fmt.Errorf("内置免费节点不可用")
	}
	node := nodes[0]
	node.Name = NodeName
	node.SourceKey = nodeSourceKey
	node.SourceName = NodeName
	return node, nil
}

func IsNodeName(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), NodeName)
}

func IsNode(node protocol.Node) bool {
	return node.SourceKey == nodeSourceKey || IsNodeName(node.Name)
}

func Snapshot(active bool) State {
	mu.Lock()
	defer mu.Unlock()
	state := loadLocked(time.Now())
	state.Active = active
	state.Exceeded = state.Remaining <= 0
	return state
}

func AddUsage(node string, bytes uint64) State {
	mu.Lock()
	defer mu.Unlock()
	state := loadLocked(time.Now())
	if IsNodeName(node) && bytes > 0 {
		if bytes > uint64(^uint64(0)>>1) {
			state.Used = weeklyLimit
		} else {
			state.Used += int64(bytes)
		}
		if state.Used > weeklyLimit {
			state.Used = weeklyLimit
		}
		refreshDerived(&state)
		cachedState = state
		if state.Remaining <= 0 || state.Used-lastSavedUsed >= saveStep {
			saveLocked(state)
		}
	}
	state.Exceeded = state.Remaining <= 0
	return state
}

func CanUse(node string) bool {
	if !IsNodeName(node) {
		return true
	}
	return Snapshot(false).Remaining > 0
}

func loadLocked(now time.Time) State {
	state := cachedState
	if !loaded {
		data, err := storage.ReadOrMigrateFile(stateFile)
		if err == nil && len(data) > 0 {
			_ = json.Unmarshal(data, &state)
		}
		loaded = true
		lastSavedUsed = state.Used
	}
	if state.PeriodStart <= 0 || now.Unix() >= state.PeriodStart+int64(weekDuration.Seconds()) {
		state.PeriodStart = now.Unix()
		state.Used = 0
		lastSavedUsed = 0
	}
	refreshDerived(&state)
	cachedState = state
	return state
}

func refreshDerived(state *State) {
	state.Limit = weeklyLimit
	state.ResetAt = state.PeriodStart + int64(weekDuration.Seconds())
	state.Remaining = weeklyLimit - state.Used
	if state.Remaining < 0 {
		state.Remaining = 0
	}
}

func saveLocked(state State) {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return
	}
	_ = storage.Write(stateFile, data)
	lastSavedUsed = state.Used
}
