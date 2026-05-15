package common

import (
	"context"
	"high-mae/protocol"
	"net"
	"sync"

	"github.com/getlantern/systray"

	"github.com/sagernet/sing/common/metadata"
)

type GenericClient interface {
	CreateProxy(ctx context.Context, destination metadata.Socksaddr) (net.Conn, error)
}

const LocalHttpPort = "10808"
const LocalSocksPort = "10810"
const TunIP = "172.19.0.1"

var (
	IsSystemProxyOn  = true
	ProxyMode        = "Rule"
	IsTunModeOn      = false
	IsWebRTCPolicyOn = false
	PrivacyMode      = false
	GlobalNodeServer string
	GlobalNodeIP     string
	ActiveNodeName   string // 当前激活的节点名称（用于精准匹配）
	GlobalProxyIn    uint64
	GlobalProxyOut   uint64

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
