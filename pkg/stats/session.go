package stats

import (
	"encoding/json"
	"high-mae/pkg/storage"
	"strings"
	"sync"
	"time"
)

type TrafficSession struct {
	ID          int64     `json:"id"`
	StartTime   time.Time `json:"startTime"`
	EndTime     time.Time `json:"endTime,omitempty"`
	Duration    string    `json:"duration,omitempty"`
	Mode        string    `json:"mode"`
	ProxyIn     uint64    `json:"proxyIn"`
	ProxyOut    uint64    `json:"proxyOut"`
	ProxyTotal  uint64    `json:"proxyTotal"`
	DirectIn    uint64    `json:"directIn"`
	DirectOut   uint64    `json:"directOut"`
	DirectTotal uint64    `json:"directTotal"`
	Total       uint64    `json:"total"`
	Status      string    `json:"status"`
}

type TrafficSessionResponse struct {
	Current *TrafficSession  `json:"current,omitempty"`
	History []TrafficSession `json:"history"`
}

const trafficSessionFile = "traffic_sessions.json"
const maxTrafficSessions = 100

var (
	sessionMu      sync.Mutex
	sessionLoaded  bool
	currentSession *TrafficSession
	sessionHistory []TrafficSession
	nextSessionID  int64
)

func SyncTrafficSession(proxyOn, tunOn bool) {
	mode := trafficMode(proxyOn, tunOn)
	if mode == "" {
		EndTrafficSession()
		return
	}
	StartTrafficSession(mode)
}

func StartTrafficSession(mode string) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	loadTrafficSessionsLocked()

	if currentSession != nil {
		currentSession.Mode = mode
		return
	}

	nextSessionID++
	currentSession = &TrafficSession{
		ID:        nextSessionID,
		StartTime: time.Now(),
		Mode:      mode,
		Status:    "Active",
	}
}

func EndTrafficSession() {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	loadTrafficSessionsLocked()

	if currentSession == nil {
		return
	}
	closeTrafficSessionLocked(currentSession)
	sessionHistory = append(sessionHistory, *currentSession)
	if len(sessionHistory) > maxTrafficSessions {
		copy(sessionHistory, sessionHistory[len(sessionHistory)-maxTrafficSessions:])
		sessionHistory = sessionHistory[:maxTrafficSessions]
	}
	currentSession = nil
	saveTrafficSessionsLocked()
}

func AddSessionTraffic(node string, in, out uint64) {
	if in == 0 && out == 0 {
		return
	}
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if currentSession == nil {
		return
	}
	if strings.EqualFold(node, "direct") {
		currentSession.DirectIn += in
		currentSession.DirectOut += out
	} else {
		currentSession.ProxyIn += in
		currentSession.ProxyOut += out
	}
	refreshTrafficTotals(currentSession)
}

func GetTrafficSessions() TrafficSessionResponse {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	loadTrafficSessionsLocked()

	res := TrafficSessionResponse{}
	if currentSession != nil {
		snapshot := *currentSession
		snapshot.Duration = time.Since(snapshot.StartTime).Round(time.Second).String()
		refreshTrafficTotals(&snapshot)
		res.Current = &snapshot
	}

	n := len(sessionHistory)
	res.History = make([]TrafficSession, n)
	for i, s := range sessionHistory {
		res.History[n-1-i] = s
	}
	return res
}

func trafficMode(proxyOn, tunOn bool) string {
	switch {
	case proxyOn && tunOn:
		return "系统代理 + TUN"
	case tunOn:
		return "TUN"
	case proxyOn:
		return "系统代理"
	default:
		return ""
	}
}

func closeTrafficSessionLocked(s *TrafficSession) {
	s.EndTime = time.Now()
	s.Duration = s.EndTime.Sub(s.StartTime).Round(time.Second).String()
	s.Status = "Closed"
	refreshTrafficTotals(s)
}

func refreshTrafficTotals(s *TrafficSession) {
	s.ProxyTotal = s.ProxyIn + s.ProxyOut
	s.DirectTotal = s.DirectIn + s.DirectOut
	s.Total = s.ProxyTotal + s.DirectTotal
}

func loadTrafficSessionsLocked() {
	if sessionLoaded {
		return
	}
	sessionLoaded = true

	data, err := storage.ReadOrMigrateFile(trafficSessionFile)
	if err != nil || len(data) == 0 {
		return
	}
	var history []TrafficSession
	if err := json.Unmarshal(data, &history); err != nil {
		return
	}
	if len(history) > maxTrafficSessions {
		history = history[len(history)-maxTrafficSessions:]
	}
	sessionHistory = history
	for _, s := range sessionHistory {
		if s.ID > nextSessionID {
			nextSessionID = s.ID
		}
	}
}

func saveTrafficSessionsLocked() {
	data, err := json.MarshalIndent(sessionHistory, "", "  ")
	if err != nil {
		return
	}
	_ = storage.Write(trafficSessionFile, data)
}
