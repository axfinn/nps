package tool

import (
	"math"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/file"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

var (
	portsMu      sync.RWMutex
	ports        []int
	ServerStatus []map[string]interface{}
)

func StartSystemInfo() {
	if b, err := beego.AppConfig.Bool("system_info_display"); err == nil && b {
		ServerStatus = make([]map[string]interface{}, 0, 1500)
		go getSeverStatus()
	}
}

func InitAllowPort() {
	p := common.GetPorts(beego.AppConfig.String("allow_ports"))
	portsMu.Lock()
	ports = p
	portsMu.Unlock()
}

func snapshotPorts() []int {
	portsMu.RLock()
	defer portsMu.RUnlock()
	return append([]int(nil), ports...)
}

// InitPortPool refreshes the two port ranges and the list of system listeners
// from nps.conf. Called at startup and on SIGUSR1 reload.
func InitPortPool() {
	cfg := file.DefaultPortPoolConfig()
	cfg.Enabled = beego.AppConfig.DefaultBool("port_pool_enable", true)
	cfg.UserStart = beego.AppConfig.DefaultInt("port_pool_user_start", 40000)
	cfg.UserEnd = beego.AppConfig.DefaultInt("port_pool_user_end", 49999)
	cfg.UserQuota = beego.AppConfig.DefaultInt("port_pool_user_quota", 100)
	cfg.SharedStart = beego.AppConfig.DefaultInt("port_pool_shared_start", 50000)
	cfg.SharedEnd = beego.AppConfig.DefaultInt("port_pool_shared_end", 60000)

	reserved := make([]int, 0, 12)
	for _, key := range []string{"web_port", "bridge_port", "tls_bridge_port",
		"http_proxy_port", "https_proxy_port", "pprof_port"} {
		if v, err := beego.AppConfig.Int(key); err == nil && v > 0 {
			reserved = append(reserved, v)
		}
	}
	// p2p binds three consecutive UDP ports.
	if v, err := beego.AppConfig.Int("p2p_port"); err == nil && v > 0 {
		reserved = append(reserved, v, v+1, v+2)
	}
	cfg.SystemPorts = reserved
	// The global allow_ports stays a hard ceiling even for pool-allocated
	// ports. An empty whitelist (the default) leaves the shared range intact.
	cfg.GlobalPorts = common.GetPorts(beego.AppConfig.String("allow_ports"))
	file.GetPortPool().Configure(cfg)
}

// AllowedPorts resolves the effective whitelist for a tunnel creation.
// u is the operator: when provided (web path) it is the logged-in user; when
// nil (bridge / internal startup) the client's owner is used instead.
// The global allow_ports is a hard ceiling for everyone. A normal user's own
// AllowPorts can only narrow it further. A super admin is never bound by a
// per-user range. restricted=false means no whitelist at all.
func AllowedPorts(u *file.User, c *file.Client) (allowed []int, restricted bool) {
	global := snapshotPorts()
	globalRestricted := len(global) != 0
	var userPorts []int
	userRestricted := false

	var owner *file.User
	if u != nil {
		owner = u
	} else if c != nil {
		owner = file.GetDb().GetUserByClientId(c.Id)
	}
	if owner != nil && !owner.IsSuperAdmin() && strings.TrimSpace(owner.AllowPorts) != "" {
		userPorts = common.GetPorts(owner.AllowPorts)
		userRestricted = true
	}

	if !globalRestricted && !userRestricted {
		return nil, false
	}
	if !globalRestricted {
		return userPorts, true
	}
	if !userRestricted {
		return global, true
	}
	set := make(map[int]struct{}, len(global))
	for _, p := range global {
		set[p] = struct{}{}
	}
	allowed = make([]int, 0, len(userPorts))
	for _, p := range userPorts {
		if _, ok := set[p]; ok {
			allowed = append(allowed, p)
		}
	}
	return allowed, true
}

func portAvailable(p int, m string) bool {
	if m == "udp" {
		return common.TestUdpPort(p)
	}
	return common.TestTcpPort(p)
}

// IsFixedPortAllowed reports whether p is a shared-range port that has been
// converted into a permanent fixed port by a tunnel the current operator is
// allowed to manage. It is the only case where a shared-range port may be
// typed manually in the web form or a npc config.
func IsFixedPortAllowed(p int, u *file.User, c *file.Client) bool {
	clientId, ok := file.GetPortPool().FixedPortClient(p)
	if !ok {
		return false
	}
	if u != nil && u.IsSuperAdmin() {
		return true
	}
	owner := u
	if owner == nil && c != nil {
		owner = file.GetDb().GetUserByClientId(c.Id)
	}
	if owner != nil && !owner.IsSuperAdmin() {
		return owner.HasClient(clientId)
	}
	// Legacy setups without a user record: only the very client owning the
	// pinned tunnel may reuse the number.
	return c != nil && c.Id == clientId
}

func TestServerPort(p int, m string, u *file.User, c *file.Client) bool {
	// p2p and secret tunnels never bind a server-side port.
	if m == "p2p" || m == "secret" {
		return true
	}
	if p > 65535 || p < 0 {
		return false
	}
	allowed, restricted := AllowedPorts(u, c)
	if restricted && (len(allowed) == 0 || !common.InIntArr(allowed, p)) {
		// A port rented by the shared pool is outside the user's exclusive
		// block by design. Only pool-owned ports get through; a manually typed
		// shared-range port is still rejected. A pinned (fixed) port belongs
		// to its owner and is therefore allowed as well.
		if !file.GetPortPool().IsSharedLeased(p) && !IsFixedPortAllowed(p, u, c) {
			return false
		}
	}
	return portAvailable(p, m)
}

// GenerateServerPort assigns a port automatically when the form leaves it
// blank. Shared pool first (random, auto-recycled); if exhausted, fall back to
// the user's exclusive block. The bool result says whether PortPool must be
// set to PortFromShared on the tunnel.
func GenerateServerPort(m string, u *file.User, c *file.Client, taskId int) (int, bool) {
	pool := file.GetPortPool()
	userId := 0
	if u != nil {
		userId = u.Id
	}
	if pool.Enabled() {
		if p, err := pool.AllocateShared(m, taskId, userId); err == nil {
			return p, true
		}
		logs.Warn("[portpool] shared range unavailable, falling back to exclusive block")
	}

	allowed, restricted := AllowedPorts(u, c)
	if restricted {
		if p, ok := pool.PickFromAllowed(allowed, m); ok {
			return p, false
		}
		return 0, false
	}
	blocked := pool.BlockedPorts()
	for i := 0; i < 20000; i++ {
		p := rand.Intn(65535)
		if p < 1024 {
			p = 1024
		}
		if blocked[p] {
			continue
		}
		if portAvailable(p, m) {
			return p, false
		}
	}
	return 0, false
}

func getSeverStatus() {
	for {
		if len(ServerStatus) < 10 {
			time.Sleep(time.Second)
		} else {
			time.Sleep(time.Minute)
		}
		cpuPercet, _ := cpu.Percent(0, true)
		var cpuAll float64
		for _, v := range cpuPercet {
			cpuAll += v
		}
		m := make(map[string]interface{})
		loads, _ := load.Avg()
		m["load1"] = loads.Load1
		m["load5"] = loads.Load5
		m["load15"] = loads.Load15
		m["cpu"] = math.Round(cpuAll / float64(len(cpuPercet)))
		swap, _ := mem.SwapMemory()
		m["swap_mem"] = math.Round(swap.UsedPercent)
		vir, _ := mem.VirtualMemory()
		m["virtual_mem"] = math.Round(vir.UsedPercent)
		conn, _ := net.ProtoCounters(nil)
		io1, _ := net.IOCounters(false)
		time.Sleep(time.Millisecond * 500)
		io2, _ := net.IOCounters(false)
		if len(io2) > 0 && len(io1) > 0 {
			m["io_send"] = (io2[0].BytesSent - io1[0].BytesSent) * 2
			m["io_recv"] = (io2[0].BytesRecv - io1[0].BytesRecv) * 2
		}
		t := time.Now()
		m["time"] = strconv.Itoa(t.Hour()) + ":" + strconv.Itoa(t.Minute()) + ":" + strconv.Itoa(t.Second())

		for _, v := range conn {
			m[v.Protocol] = v.Stats["CurrEstab"]
		}
		if len(ServerStatus) >= 1440 {
			ServerStatus = ServerStatus[1:]
		}
		ServerStatus = append(ServerStatus, m)
	}
}
