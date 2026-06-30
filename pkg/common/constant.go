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

const AppVersion = "1.0.5"

var LocalHttpPort = "10808"

const LocalSocksPort = "10810"
const TunHttpPort = "10811"
const TunIP = "10.0.0.2"

var (
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

func GetActiveClient() GenericClient {
	ClientMu.RLock()
	defer ClientMu.RUnlock()
	return ActiveClient
}
