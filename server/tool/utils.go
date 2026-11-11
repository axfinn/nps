package tool

import (
	"math"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/file"
	"github.com/astaxie/beego"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

var (
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
	p := beego.AppConfig.String("allow_ports")
	ports = common.GetPorts(p)
}

// AllowedPorts resolves the effective whitelist for a tunnel creation.
// u is the operator: when provided (web path) it is the logged-in user; when
// nil (bridge / internal startup) the client's owner is used instead.
// The global allow_ports is a hard ceiling for everyone. A normal user's own
// AllowPorts can only narrow it further. A super admin is never bound by a
// per-user range. restricted=false means no whitelist at all.
func AllowedPorts(u *file.User, c *file.Client) (allowed []int, restricted bool) {
	globalRestricted := len(ports) != 0
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
		return ports, true
	}
	set := make(map[int]struct{}, len(ports))
	for _, p := range ports {
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
		return false
	}
	return portAvailable(p, m)
}

// GenerateServerPort picks a free port from the effective whitelist instead
// of blindly probing the whole 1024-65535 range.
func GenerateServerPort(m string, u *file.User, c *file.Client) int {
	allowed, restricted := AllowedPorts(u, c)
	if restricted {
		if len(allowed) == 0 {
			return 0
		}
		start := rand.Intn(len(allowed))
		for i := 0; i < len(allowed); i++ {
			p := allowed[(start+i)%len(allowed)]
			if portAvailable(p, m) {
				return p
			}
		}
		return 0
	}
	for i := 0; i < 20000; i++ {
		p := rand.Intn(65535)
		if p < 1024 {
			p = 1024
		}
		if portAvailable(p, m) {
			return p
		}
	}
	return 0
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
