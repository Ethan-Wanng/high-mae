package ins

import (
	"context"
	"github.com/getlantern/systray"
	"high-mae/protocol"
	"net"
	"sync"

	"github.com/sagernet/sing/common/metadata"
	"os/exec"
)

type GenericClient interface {
	CreateProxy(ctx context.Context, destination metadata.Socksaddr) (net.Conn, error)
}

const LocalHttpPort = "10808"
const TunIP = "10.0.0.2"

var (
	IsSystemProxyOn  = true
	ProxyMode        = "Rule"
	IsTunModeOn      = false
	TunCmd           *exec.Cmd
	globalNodeServer string
	GlobalNodeIP     string
	ActiveNodeName   string // 当前激活的节点名称（用于精准匹配）

	clientMu          sync.RWMutex
	activeClient      GenericClient       // 当前正在工作的代理客户端引擎
	AllNodes          []protocol.Node     // 保存所有已加载的节点
	MCurrentNode      *systray.MenuItem   // 顶部显示的当前节点
	MNodeMenu          *systray.MenuItem   // 托盘上的节点菜单父级
	MTestAll           *systray.MenuItem   // 根菜单上的一键测速按钮
	MToggleProxy       *systray.MenuItem
	MToggleMode        *systray.MenuItem
	MToggleTun         *systray.MenuItem
	MQuit              *systray.MenuItem

	Tun2socksBytes     []byte
	WintunBytes        []byte
	NodeMenuItems      []*systray.MenuItem // 保存所有的节点子菜单项，用于动态刷新
	nodeMenuCancel     context.CancelFunc  // 用于取消旧节点的监听协程，防止内存泄漏
	MSupplierMenu      *systray.MenuItem   // 托盘上的供应商菜单父级
	SupplierMenuItems  []*systray.MenuItem // 供应商子菜单项
	supplierMenuCancel context.CancelFunc  // 用于取消旧供应商的监听协程
)

func GetActiveClient() GenericClient {
	clientMu.RLock()
	defer clientMu.RUnlock()
	return activeClient
}
