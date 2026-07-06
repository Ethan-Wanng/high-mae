package common

import (
	"context"
	"net"
	"sync"
	"wing/protocol"

	"github.com/getlantern/systray"

	"github.com/sagernet/sing/common/metadata"
)

type GenericClient interface {
	CreateProxy(ctx context.Context, destination metadata.Socksaddr) (net.Conn, error)
}

const AppVersion = "1.0.6"

var LocalHttpPort = "10808"

const LocalSocksPort = "10810"
const TunHttpPort = "10811"
const TunIP = "10.0.0.2"

var (
	StateMu               sync.RWMutex
	IsSystemProxyOn       = false
	ProxyMode             = "Rule"
	IsTunModeOn           = false
	IsSystemDNSHijacked   = false // 是否已经覆写了系统 DNS
	IsWebRTCPolicyOn      = false
	PrivacyMode           = true
	PreventBingCNRedirect = false
	GlobalNodeServer      string
	GlobalNodeIP          string
	ActiveNode            protocol.Node
	ActiveNodeName        string // 当前激活的节点名称（用于精准匹配）
	GlobalProxyIn         uint64
	GlobalProxyOut        uint64
	ActiveDNSQueries      int32
	ActiveSpeedtests      int32

	RealLocalIPBeforeTun string
	BlockUDP443          = false // 默认关闭：封锁 UDP 443 (QUIC) 强制浏览器回退 TCP。这是内部实验开关，暂不暴露 WebUI。

	ClientMu     sync.RWMutex
	ActiveClient GenericClient     // 当前正在工作的代理客户端引擎
	AllNodes     []protocol.Node   // 保存所有已加载的节点
	MCurrentNode *systray.MenuItem // 顶部显示的当前节点
	MNodeMenu    *systray.MenuItem // 托盘上的节点菜单父级
	MTestAll     *systray.MenuItem // 根菜单上的一键测速按钮
	MToggleProxy *systray.MenuItem
	MToggleMode  *systray.MenuItem
	MToggleTun   *systray.MenuItem
	MQuit        *systray.MenuItem

	RefreshTrayIcon func()

	NodeMenuItems      []*systray.MenuItem // 保存所有的节点子菜单项，用于动态刷新
	NodeMenuCancel     context.CancelFunc  // 用于取消旧节点的监听协程，防止内存泄漏
	MSupplierMenu      *systray.MenuItem   // 托盘上的供应商菜单父级
	SupplierMenuItems  []*systray.MenuItem // 供应商子菜单项
	SupplierMenuCancel context.CancelFunc  // 用于取消旧供应商的监听协程
)

type RuntimeState struct {
	SystemProxyOn  bool
	TunModeOn      bool
	ProxyMode      string
	ActiveNode     protocol.Node
	ActiveNodeName string
	GlobalNodeIP   string
}

func GetActiveClient() GenericClient {
	ClientMu.RLock()
	defer ClientMu.RUnlock()
	return ActiveClient
}

func SetActiveClient(node protocol.Node, resolvedIP string, client GenericClient) GenericClient {
	ClientMu.Lock()
	defer ClientMu.Unlock()
	oldClient := ActiveClient
	GlobalNodeServer = node.Server
	GlobalNodeIP = resolvedIP
	ActiveNode = node
	ActiveNodeName = node.Name
	ActiveClient = client
	return oldClient
}

func GetActiveNodeSnapshot() (protocol.Node, string, string) {
	ClientMu.RLock()
	defer ClientMu.RUnlock()
	return ActiveNode, ActiveNodeName, GlobalNodeIP
}

func ActiveNodeSnapshot() (protocol.Node, string) {
	ClientMu.RLock()
	defer ClientMu.RUnlock()
	return ActiveNode, ActiveNodeName
}

func SetActiveNode(node protocol.Node) {
	ClientMu.Lock()
	ActiveNode = node
	ActiveNodeName = node.Name
	GlobalNodeServer = node.Server
	ClientMu.Unlock()
}

func ClearActiveNode() {
	ClientMu.Lock()
	ActiveNode = protocol.Node{}
	ActiveNodeName = ""
	ClientMu.Unlock()
}

func SetAllNodes(nodes []protocol.Node) {
	StateMu.Lock()
	AllNodes = cloneNodes(nodes)
	StateMu.Unlock()
}

func AppendAllNodes(nodes []protocol.Node) []protocol.Node {
	StateMu.Lock()
	AllNodes = append(AllNodes, nodes...)
	snapshot := cloneNodes(AllNodes)
	StateMu.Unlock()
	return snapshot
}

func ClearAllNodes() {
	StateMu.Lock()
	AllNodes = nil
	StateMu.Unlock()
}

func GetAllNodes() []protocol.Node {
	StateMu.RLock()
	defer StateMu.RUnlock()
	return cloneNodes(AllNodes)
}

func GetAllNode(index int) (protocol.Node, bool) {
	StateMu.RLock()
	defer StateMu.RUnlock()
	if index < 0 || index >= len(AllNodes) {
		return protocol.Node{}, false
	}
	return AllNodes[index], true
}

func UpdateAllNode(index int, update func(*protocol.Node)) ([]protocol.Node, bool) {
	StateMu.Lock()
	defer StateMu.Unlock()
	if index < 0 || index >= len(AllNodes) {
		return nil, false
	}
	update(&AllNodes[index])
	return cloneNodes(AllNodes), true
}

func cloneNodes(nodes []protocol.Node) []protocol.Node {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]protocol.Node, len(nodes))
	copy(out, nodes)
	return out
}

func SetSystemProxyOn(enabled bool) {
	StateMu.Lock()
	IsSystemProxyOn = enabled
	StateMu.Unlock()
}

func GetSystemProxyOn() bool {
	StateMu.RLock()
	defer StateMu.RUnlock()
	return IsSystemProxyOn
}

func SetTunModeOn(enabled bool) {
	StateMu.Lock()
	IsTunModeOn = enabled
	StateMu.Unlock()
}

func GetTunModeOn() bool {
	StateMu.RLock()
	defer StateMu.RUnlock()
	return IsTunModeOn
}

func SetProxyMode(mode string) {
	StateMu.Lock()
	ProxyMode = mode
	StateMu.Unlock()
}

func GetProxyMode() string {
	StateMu.RLock()
	defer StateMu.RUnlock()
	return ProxyMode
}

func GetNetworkState() (bool, bool, string) {
	StateMu.RLock()
	defer StateMu.RUnlock()
	return IsSystemProxyOn, IsTunModeOn, ProxyMode
}

func SnapshotRuntimeState() RuntimeState {
	StateMu.RLock()
	systemProxyOn := IsSystemProxyOn
	tunModeOn := IsTunModeOn
	proxyMode := ProxyMode
	StateMu.RUnlock()

	ClientMu.RLock()
	activeNode := ActiveNode
	activeNodeName := ActiveNodeName
	globalNodeIP := GlobalNodeIP
	ClientMu.RUnlock()

	return RuntimeState{
		SystemProxyOn:  systemProxyOn,
		TunModeOn:      tunModeOn,
		ProxyMode:      proxyMode,
		ActiveNode:     activeNode,
		ActiveNodeName: activeNodeName,
		GlobalNodeIP:   globalNodeIP,
	}
}
