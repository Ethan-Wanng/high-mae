package ins

import (
	"context"
	"net"
	"github.com/getlantern/systray"
	"high-mae/protocol"
	"os/exec"
	"sync"
	"github.com/sagernet/sing/common/metadata"
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

	// ---- 节点管理核心变量 ----
	clientMu      sync.RWMutex
	activeClient  GenericClient // 当前正在工作的代理客户端引擎
	AllNodes      []protocol.Node     // 保存所有已加载的节点
	MNodeMenu     *systray.MenuItem   // 托盘上的节点菜单父级
	NodeMenuItems []*systray.MenuItem // 保存所有的节点子菜单项，用于动态刷新
)

func GetActiveClient() GenericClient {
	clientMu.RLock()
	defer clientMu.RUnlock()
	return activeClient
}
