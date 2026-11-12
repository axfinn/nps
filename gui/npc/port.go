package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/astaxie/beego/logs"
)

// DefaultWebPort 是本地 Web 管理面板的默认端口。
// 用户可以通过 -port 参数或管理页里的「面板端口」自行修改；
// 若选定的端口被占用，则自动改用内核分配的随机可用端口。
const DefaultWebPort = 9666

// portInfo 落盘为 npc_gui.port，供状态栏、开机提醒以及外部脚本读取「本次实际端口」。
// 端口可能因占用而变化，所以不能只靠配置文件推断。
type portInfo struct {
	Port      int    `json:"port"`
	URL       string `json:"url"`
	Preferred int    `json:"preferred"`
	Fallback  bool   `json:"fallback"`
	PID       int    `json:"pid"`
	StartedAt string `json:"started_at"`
}

var webState = struct {
	sync.RWMutex
	port      int
	url       string
	preferred int
	fallback  bool
}{}

// resolvePreferredPort 决定首选端口，优先级：命令行 -port > 配置文件 web_port > 9666。
func resolvePreferredPort(cliPort, cfgPort int) int {
	for _, p := range []int{cliPort, cfgPort} {
		if p > 0 && p <= 65535 {
			return p
		}
	}
	return DefaultWebPort
}

// listenWithFallback 先尝试绑定首选端口，被占用（或不可绑定）时自动换一个随机可用端口。
// 直接把已绑定的 listener 交给 http.Server.Serve，避免「先探测端口再重新绑定」的竞态窗口。
func listenWithFallback(preferred int) (net.Listener, int, bool, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", preferred)
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln, preferred, false, nil
	}

	logs.Warn("端口 %d 不可用（%v），按策略自动改用随机可用端口", preferred, err)
	fallbackLn, fallbackErr := net.Listen("tcp", "127.0.0.1:0")
	if fallbackErr != nil {
		return nil, 0, false, fmt.Errorf("首选端口 %d 不可用 (%v)，且自动分配端口失败: %w", preferred, err, fallbackErr)
	}
	port := fallbackLn.Addr().(*net.TCPAddr).Port
	logs.Warn("已自动分配端口 %d，管理面板地址 http://127.0.0.1:%d", port, port)
	return fallbackLn, port, true, nil
}

func setWebState(preferred, port int, fallback bool) {
	webState.Lock()
	webState.preferred = preferred
	webState.port = port
	webState.url = fmt.Sprintf("http://127.0.0.1:%d", port)
	webState.fallback = fallback
	webState.Unlock()
}

func getWebState() (port int, url string, preferred int, fallback bool) {
	webState.RLock()
	defer webState.RUnlock()
	return webState.port, webState.url, webState.preferred, webState.fallback
}

// getPortFilePath 端口文件与用户配置放在同一目录，保证普通用户（非 root）可写。
func getPortFilePath() string {
	return filepath.Join(filepath.Dir(getUserConfigPath()), "npc_gui.port")
}

func writePortFile(info portInfo) error {
	path := getPortFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	// 先写临时文件再改名，避免托盘/脚本读到写了一半的内容
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readPortFile() (portInfo, error) {
	var info portInfo
	data, err := os.ReadFile(getPortFilePath())
	if err != nil {
		return info, err
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return info, err
	}
	return info, nil
}

// removePortFile 仅在端口文件确实属于当前进程时才删除，避免误删另一个实例的记录。
func removePortFile() {
	path := getPortFilePath()
	info, err := readPortFile()
	if err != nil || info.PID != os.Getpid() {
		return
	}
	_ = os.Remove(path)
}

func newPortInfo(preferred, port int, fallback bool) portInfo {
	return portInfo{
		Port:      port,
		URL:       fmt.Sprintf("http://127.0.0.1:%d", port),
		Preferred: preferred,
		Fallback:  fallback,
		PID:       os.Getpid(),
		StartedAt: time.Now().Format(time.RFC3339),
	}
}
