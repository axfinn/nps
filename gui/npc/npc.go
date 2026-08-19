package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"ehang.io/nps/client"
	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/install"
	"ehang.io/nps/lib/version"
	"github.com/astaxie/beego/logs"
	"github.com/kardianos/service"
)

//go:embed static/*
var staticFiles embed.FS

var (
	cl        *client.TRPClient
	running   bool
	closing   bool
	mu        sync.Mutex
	curConfig Config
	svcStatus string
)

type Config struct {
	Server            string `json:"server"`
	Vkey              string `json:"vkey"`
	ConnType          string `json:"conn_type"`
	TlsEnable         bool   `json:"tls_enable"`
	ProxyUrl          string `json:"proxy_url"`
	DisconnectTimeout int    `json:"disconnect_timeout"`
}

type Status struct {
	Running   bool   `json:"running"`
	Version   string `json:"version"`
	Config    Config `json:"config"`
	Logs      string `json:"logs"`
	SvcStatus string `json:"svc_status"`
}

// kardianos/service 在 init() 里向全局 flag 注册了 -service 标志。
// 我们这里复用同一个变量名以便在 main() 早期判断是否以服务模式启动。
var serviceFlag = flag.String("service", "", "由 service 平台调用 (run|start|stop|install|uninstall 等)，请勿手动设置")

// getAvailablePort 获取一个可用的随机端口
func getAvailablePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func main() {
	// 命令行参数（一次性注册所有 flag，避免重复 flag.Parse 报错）
	port := flag.Int("port", 0, "指定Web GUI端口 (默认自动选择可用端口)")
	installServiceFlag := flag.Bool("install-service", false, "安装系统服务 (内部使用)")
	noSudo := flag.Bool("no-sudo", false, "不请求管理员权限（跳过自动提权）")
	homeFlag := flag.String("home", "", "用户主目录（root 上下文通过此参数找到 GUI 写入的用户配置）")
	flag.Parse()

	logs.SetLogger("store")

	// 调试信息
	logs.Info("========== NPC GUI 启动 ==========")
	logs.Info("操作系统: %s", runtime.GOOS)
	logs.Info("参数: noSudo=%v, installServiceFlag=%v, serviceFlag=%q, homeFlag=%q",
		*noSudo, *installServiceFlag, *serviceFlag, *homeFlag)
	logs.Info("================================")

	// 1) 服务模式：把控制权交给 kardianos/service，由它调用 prg.Start 并阻塞。
	//    注意：kardianos/service 不会自动拦截 -service run；必须显式调用 s.Run()。
	if !service.Interactive() || *serviceFlag == "run" {
		runAsService()
		return
	}

	// 2) 安装模式（由 osascript 以 root 身份调用 -install-service），完成 plist/unit 安装
	if *installServiceFlag {
		runInstallService(*homeFlag)
		return
	}

	// 3) 双击检测 + 自动提权：仅当用户主动以 GUI 形式启动时触发，
	//    排除 -no-sudo、-install-service、-service* 模式。
	if runtime.GOOS == "darwin" && !*noSudo && !isRunningInTerminal() {
		maybeRelaunchWithSudo(port)
	}

	runGUI(*port)
}

// runAsService 以系统服务模式运行：阻塞、调用 prg.Start()、后台拉起 client 连接。
func runAsService() {
	logs.Info("以服务模式启动 (service=%q)", *serviceFlag)

	svcConfig := getServiceConfig()
	prg := &npcService{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		logs.Error("创建服务失败: %v", err)
		os.Exit(1)
	}
	if err := s.Run(); err != nil {
		logs.Error("服务运行失败: %v", err)
		os.Exit(1)
	}
}

// runInstallService 在 root 上下文（macOS osascript / sudo）下执行实际的 plist/unit 安装。
// 必须已经写好用户配置（GUI 进程写入）或通过 -home 参数指定 HOME 找到用户配置。
func runInstallService(home string) {
	if home != "" {
		if err := os.Setenv("HOME", home); err != nil {
			fmt.Printf("设置 HOME=%s 失败: %v\n", home, err)
			os.Exit(1)
		}
	}

	// 优先读 GUI 进程写入的用户配置；fallback 系统配置
	cfg := loadConfig()
	if cfg.Server == "" || cfg.Vkey == "" {
		fmt.Println("错误: 配置无效 (找不到用户配置) ，请先在 GUI 中保存配置")
		os.Exit(1)
	}

	// 把配置同步到系统配置路径（service 启动时只读这个）
	if err := saveSystemConfig(cfg); err != nil {
		fmt.Printf("保存系统配置失败: %v\n", err)
		os.Exit(1)
	}

	// 把二进制复制到稳定路径，避免 service plist 里写绝对路径但用户移动了原文件
	stablePath, err := installStableBinary()
	if err != nil {
		fmt.Printf("复制二进制到稳定路径失败: %v\n", err)
		os.Exit(1)
	}

	svcConfig := getServiceConfig()
	svcConfig.Executable = stablePath
	prg := &npcService{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		fmt.Printf("创建服务失败: %v\n", err)
		os.Exit(1)
	}

	if err := s.Install(); err != nil {
		fmt.Printf("安装服务失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("服务安装成功")
	fmt.Println("已安装路径:", stablePath)
	os.Exit(0)
}

// runGUI 启动 HTTP Web GUI（普通用户交互模式）。
func runGUI(port int) {
	logs.Info("NPC Web GUI v%s starting...", version.VERSION)

	// 加载配置
	curConfig = loadConfig()
	svcStatus = getServiceStatus()

	// 静态文件
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		logs.Error("加载静态文件失败: %v", err)
		fmt.Printf("加载静态文件失败: %v\n", err)
		os.Exit(1)
	}

	// 创建路由
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/start", handleStart)
	mux.HandleFunc("/api/stop", handleStop)
	mux.HandleFunc("/api/config", handleConfig)
	mux.HandleFunc("/api/config/clear", handleClearConfig)
	mux.HandleFunc("/api/service/install", handleServiceInstall)
	mux.HandleFunc("/api/service/uninstall", handleServiceUninstall)

	// 确定端口
	var listenPort int
	if port > 0 {
		listenPort = port
	} else {
		availPort, err := getAvailablePort()
		if err != nil {
			fmt.Printf("获取可用端口失败: %v\n", err)
			os.Exit(1)
		}
		listenPort = availPort
	}

	addr := fmt.Sprintf("127.0.0.1:%d", listenPort)
	fmt.Printf("NPC Web GUI v%s\n", version.VERSION)
	fmt.Printf("请打开浏览器访问: http://%s\n", addr)
	fmt.Printf("按 Ctrl+C 退出\n")

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 自动打开浏览器
	go func() {
		time.Sleep(800 * time.Millisecond)
		openBrowser("http://" + addr)
	}()

	// 优雅关闭
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		logs.Info("收到关闭信号，正在停止...")
		fmt.Println("\n正在关闭...")

		// 停止客户端
		mu.Lock()
		if running && cl != nil {
			closing = true
			running = false
			cl.Close()
			cl = nil
		}
		mu.Unlock()

		// 优雅关闭 HTTP 服务器
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logs.Error("关闭服务器失败: %v", err)
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Printf("启动失败: %v\n", err)
		fmt.Printf("请检查端口 %d 是否被占用\n", listenPort)
		os.Exit(1)
	}

	logs.Info("NPC Web GUI 已退出")
}

// maybeRelaunchWithSudo 在 macOS 上以非终端方式启动时，弹出密码框请求 sudo 重启。
// 调用方已确认不是 service/install/no-sudo 模式。
func maybeRelaunchWithSudo(port *int) {
	exePath, err := os.Executable()
	if err != nil {
		logs.Error("获取可执行文件路径失败: %v", err)
		return
	}
	logs.Info("检测到 macOS GUI 双击运行，请求管理员权限...")

	args := []string{"-no-sudo"}
	if port != nil && *port > 0 {
		args = append(args, "-port", fmt.Sprintf("%d", *port))
	}
	argsStr := ""
	for _, a := range args {
		// AppleScript 字符串内嵌要对反斜杠和双引号做转义
		argsStr += fmt.Sprintf(" %s", shellQuote(a))
	}

	escapedPath := shellQuote(exePath)
	// 把 stdout/stderr 落到 /tmp/npc_gui.log，方便后续排障
	script := fmt.Sprintf(
		`do shell script "%s%s > /tmp/npc_gui.log 2>&1 &" with administrator privileges`,
		escapedPath, argsStr)

	logs.Info("执行 AppleScript: %s", script)
	cmd := exec.Command("osascript", "-e", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logs.Error("权限请求失败: %v, 输出: %s", err, string(output))
		fmt.Printf("⚠️  未能获取管理员权限: %v\n", err)
		fmt.Println("继续以普通用户模式运行（服务安装功能将不可用）")
		fmt.Println("按 Ctrl+C 退出，然后在终端中运行以获得完整功能")
		time.Sleep(3 * time.Second)
		return
	}

	logs.Info("权限请求成功，正在重启...")
	fmt.Println("✓ 已获取管理员权限，正在启动...")
	// 父进程退出，让子进程（已 detach）继续运行
	time.Sleep(500 * time.Millisecond)
	os.Exit(0)
}

// shellQuote 把字符串嵌入 AppleScript 双引号字符串，做最小转义。
// 仅对 \ 和 " 做转义，避免路径里偶发的奇怪字符破坏 AppleScript 解析。
// 该字符串最终会被 AppleScript 的 do shell script 喂给 /bin/sh。
func shellQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	status := Status{
		Running:   running,
		Version:   version.VERSION,
		Config:    curConfig,
		Logs:      common.GetLogMsg(),
		SvcStatus: svcStatus,
	}
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		mu.Lock()
		cfg := curConfig
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
		return
	}

	if r.Method == http.MethodPost {
		var cfg Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if cfg.ConnType == "" {
			cfg.ConnType = "tcp"
		}
		if cfg.DisconnectTimeout <= 0 {
			cfg.DisconnectTimeout = 60
		}

		mu.Lock()
		curConfig = cfg
		mu.Unlock()

		if err := saveConfig(cfg); err != nil {
			http.Error(w, "保存配置失败: "+err.Error(), 500)
			return
		}
		logs.Info("配置已保存到 %s", getUserConfigPath())

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func handleClearConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mu.Lock()
	curConfig = Config{
		ConnType:          "tcp",
		DisconnectTimeout: 60,
	}
	mu.Unlock()

	if err := clearAllConfigs(); err != nil {
		http.Error(w, "清除配置失败: "+err.Error(), 500)
		return
	}

	logs.Info("配置已清除")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mu.Lock()
	cfg := curConfig
	if cfg.Server == "" || cfg.Vkey == "" {
		mu.Unlock()
		http.Error(w, "请先配置服务器地址和验证密钥", 400)
		return
	}
	if running {
		mu.Unlock()
		http.Error(w, "已经在运行中", 400)
		return
	}
	running = true
	closing = false
	mu.Unlock()

	client.SetTlsEnable(cfg.TlsEnable)

	go runClientLoop(cfg)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mu.Lock()
	if !running {
		mu.Unlock()
		http.Error(w, "未在运行", 400)
		return
	}
	closing = true
	clientToClose := cl
	cl = nil
	mu.Unlock()

	if clientToClose != nil {
		clientToClose.Close()
	}

	logs.Info("客户端已停止")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// runClientLoop 与 service 模式共享的客户端连接循环。
func runClientLoop(cfg Config) {
	for {
		mu.Lock()
		if closing {
			running = false
			mu.Unlock()
			return
		}
		mu.Unlock()

		logs.Info("连接服务器: %s, vkey: %s, type: %s, tls: %v",
			cfg.Server, cfg.Vkey, cfg.ConnType, cfg.TlsEnable)
		newClient := client.NewRPClient(cfg.Server, cfg.Vkey, cfg.ConnType, cfg.ProxyUrl, nil, cfg.DisconnectTimeout)

		mu.Lock()
		if closing {
			running = false
			mu.Unlock()
			return
		}
		cl = newClient
		mu.Unlock()

		newClient.Start()

		mu.Lock()
		if closing {
			running = false
			mu.Unlock()
			return
		}
		mu.Unlock()

		logs.Warn("连接断开，5秒后重连...")
		time.Sleep(5 * time.Second)
	}
}

// 系统服务相关
func getServiceConfig() *service.Config {
	options := make(service.KeyValue)
	svcConfig := &service.Config{
		Name:        "npc-gui",
		DisplayName: "NPC 内网穿透客户端",
		Description: "NPS内网穿透客户端服务",
		Option:      options,
	}

	if runtime.GOOS == "darwin" {
		// macOS：默认走系统级 LaunchDaemon（/Library/LaunchDaemons/），真正做到开机自启。
		svcConfig.Option["RunAtLoad"] = true
		svcConfig.Option["KeepAlive"] = true
	} else if !common.IsWindows() {
		// Linux: systemd 配置
		svcConfig.Dependencies = []string{
			"Requires=network.target",
			"After=network-online.target syslog.target",
		}
		svcConfig.Option["SystemdScript"] = install.SystemdScript
		svcConfig.Option["SysvScript"] = install.SysvScript
	}

	exePath, err := os.Executable()
	if err != nil {
		logs.Error("获取可执行文件路径失败: %v", err)
	} else {
		svcConfig.Executable = exePath
	}

	return svcConfig
}

// getService 创建服务实例。
func getService() (service.Service, error) {
	svcConfig := getServiceConfig()
	prg := &npcService{}
	return service.New(prg, svcConfig)
}

func getServiceStatus() string {
	s, err := getService()
	if err != nil {
		logs.Warn("创建服务实例失败: %v", err)
		return "unknown"
	}
	status, err := s.Status()
	if err != nil {
		return "not_installed"
	}
	switch status {
	case service.StatusRunning:
		return "running"
	case service.StatusStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// isRunningInTerminal 检测是否在终端中运行
func isRunningInTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		logs.Info("检测终端状态失败: %v, 假定非终端运行", err)
		return false
	}

	isTerminal := (fileInfo.Mode() & os.ModeCharDevice) != 0

	if runtime.GOOS == "darwin" {
		termEnv := os.Getenv("TERM")
		sshConnection := os.Getenv("SSH_CONNECTION")
		logs.Info("终端检测: isCharDevice=%v, TERM=%s, SSH_CONNECTION=%s",
			isTerminal, termEnv, sshConnection)
		if termEnv == "" && sshConnection == "" {
			logs.Info("检测到 macOS 双击运行（无 TERM 环境变量）")
			return false
		}
	}

	return isTerminal
}

// installStableBinary 把当前二进制复制到 /usr/local/bin/npc_gui (root) 或
// ~/Library/Application Support/npc/npc_gui (用户级)，作为 service 启动的稳定路径。
// 调用方必须已经拥有写权限（root 或当前用户目录）。
func installStableBinary() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("获取当前可执行文件路径失败: %w", err)
	}

	var destDir, destPath string
	switch runtime.GOOS {
	case "windows":
		// Windows：使用 ProgramData 下的固定目录
		destDir = filepath.Join(os.Getenv("ProgramData"), "npc")
		destPath = filepath.Join(destDir, "npc_gui.exe")
	case "darwin":
		// macOS root 安装：使用系统级 LaunchDaemon 的常见路径
		destDir = "/usr/local/bin"
		destPath = "/usr/local/bin/npc_gui"
	default:
		// Linux：使用 /usr/local/bin
		destDir = "/usr/local/bin"
		destPath = "/usr/local/bin/npc_gui"
	}

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", fmt.Errorf("创建目录 %s 失败: %w", destDir, err)
	}

	if err := copyBinary(exePath, destPath); err != nil {
		return "", fmt.Errorf("复制 %s -> %s 失败: %w", exePath, destPath, err)
	}

	if !common.IsWindows() {
		_ = os.Chmod(destPath, 0755)
	}

	logs.Info("已安装稳定路径二进制: %s", destPath)
	return destPath, nil
}

// copyBinary 跨平台地复制可执行文件。
func copyBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := out.ReadFrom(in); err != nil {
		return err
	}
	return out.Close()
}

// handleServiceInstall 由 GUI HTTP 调用：保存配置 + 通过权限提升安装 service。
func handleServiceInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mu.Lock()
	cfg := curConfig
	mu.Unlock()

	if cfg.Server == "" || cfg.Vkey == "" {
		http.Error(w, "请先配置服务器地址和验证密钥", 400)
		return
	}

	// 1) 先把配置写到用户配置路径。提权后的 root 进程会从这里读。
	if err := saveConfig(cfg); err != nil {
		http.Error(w, "保存配置失败: "+err.Error(), 500)
		return
	}
	logs.Info("配置已保存到 %s", getUserConfigPath())

	// 2) 通过权限提升完成实际的 service 安装（二进制复制 + plist/unit 写入）
	if err := installServiceWithPrivilege(cfg); err != nil {
		http.Error(w, "安装服务失败: "+err.Error(), 500)
		return
	}

	svcStatus = getServiceStatus()
	logs.Info("服务安装成功")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// handleServiceUninstall 卸载 service。
func handleServiceUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s, err := getService()
	if err != nil {
		http.Error(w, "创建服务失败: "+err.Error(), 500)
		return
	}

	// 先 stop 一次，忽略 "未运行" 错误
	if err := s.Stop(); err != nil && !errors.Is(err, service.ErrNotInstalled) {
		logs.Warn("停止服务失败（继续尝试卸载）: %v", err)
	}

	if err := s.Uninstall(); err != nil {
		http.Error(w, "卸载服务失败: "+err.Error(), 500)
		return
	}

	svcStatus = getServiceStatus()
	logs.Info("服务已卸载")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// installServiceWithPrivilege 在 GUI 进程内被调用。
//
// 核心原则：GUI 进程几乎永远不是 root。所有"写 /usr/local/bin / /Library/LaunchDaemons / /etc/npc
// / /etc/systemd/system"的操作都必须在 root 上下文中完成。
//
//   - 已经 root（少数情况）：直接 installStableBinary + s.Install()
//   - macOS 普通用户：先试 ~/Library/LaunchAgents 用户级；失败则通过 osascript 提权走 /Library/LaunchDaemons
//   - Linux 普通用户：直接尝试 install，失败则尝试 pkexec 提权，再失败提示用户手动 sudo 重跑
//   - Windows：直接尝试，失败提示以管理员身份运行
func installServiceWithPrivilege(cfg Config) error {
	// 已经是 root：直接做完整安装流程
	if os.Geteuid() == 0 {
		return doInstall(cfg)
	}

	// macOS：先试用户级，失败再 osascript 提权走系统级
	if runtime.GOOS == "darwin" {
		exePath, _ := os.Executable()
		if testInstallAsUser(exePath, cfg) {
			return nil
		}
		return escalateViaOsascript()
	}

	// Linux：尝试 pkexec 提权
	if runtime.GOOS == "linux" {
		if err := tryLinuxPkexec(); err == nil {
			return nil
		} else {
			logs.Info("pkexec 提权失败或不可用: %v，将尝试直接 install", err)
		}
	}

	// fallback 直接 install（Windows 通常会直接失败，因为写注册表需要 admin）
	if err := doInstall(cfg); err != nil {
		return wrapInstallPermissionError(err)
	}
	return nil
}

// tryLinuxPkexec 通过 pkexec 拉起 root 上下文执行 -install-service。
func tryLinuxPkexec() error {
	if _, err := exec.LookPath("pkexec"); err != nil {
		return fmt.Errorf("pkexec 不可用: %w", err)
	}
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	homeDir, _ := os.UserHomeDir()
	args := []string{exePath, "-install-service"}
	if homeDir != "" {
		args = append(args, "-home", homeDir)
	}
	logs.Info("通过 pkexec 提权安装服务: %v", args)
	cmd := exec.Command("pkexec", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

// wrapInstallPermissionError 把 install 失败包装为更友好的提示。
func wrapInstallPermissionError(err error) error {
	if err == nil {
		return nil
	}
	switch runtime.GOOS {
	case "linux":
		return fmt.Errorf("%w\n提示：需要 root 权限。可在终端执行：sudo %s -install-service",
			err, os.Args[0])
	case "windows":
		return fmt.Errorf("%w\n提示：请以管理员身份运行本程序后再点击安装服务", err)
	default:
		return err
	}
}

// testInstallAsUser 尝试在用户级（~/Library/LaunchAgents/）安装，返回是否成功。
// 用于 macOS 用户级 fallback。注意：必须先把可执行文件复制到一个稳定位置，
// 否则 LaunchAgent plist 里写绝对路径用户移动了原文件就启动不了。
func testInstallAsUser(exePath string, cfg Config) bool {
	if exePath == "" {
		return false
	}
	// macOS 用户级：拷贝到 ~/Library/Application Support/npc/npc_gui
	home, err := os.UserHomeDir()
	if err != nil {
		logs.Info("获取用户主目录失败: %v", err)
		return false
	}
	userStableDir := filepath.Join(home, "Library", "Application Support", "npc")
	userStablePath := filepath.Join(userStableDir, "npc_gui")
	if err := os.MkdirAll(userStableDir, 0755); err != nil {
		logs.Info("创建 %s 失败: %v", userStableDir, err)
		return false
	}
	if err := copyBinary(exePath, userStablePath); err != nil {
		logs.Info("复制到 %s 失败: %v", userStablePath, err)
		return false
	}

	svcConfig := getServiceConfig()
	svcConfig.Option["UserService"] = true
	svcConfig.Executable = userStablePath
	prg := &npcService{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		logs.Info("创建服务实例失败: %v", err)
		return false
	}
	// 旧版本残留：先尝试 Install，遇到 "Init already exists" 才走 Uninstall + Install
	if err := s.Install(); err != nil {
		if !strings.Contains(err.Error(), "Init already exists") {
			logs.Info("用户级 install 失败（需要 root 走系统级 LaunchDaemon）: %v", err)
			return false
		}
		if uerr := s.Uninstall(); uerr != nil {
			logs.Info("用户级 Uninstall 失败: %v", uerr)
			return false
		}
		if err := s.Install(); err != nil {
			logs.Info("用户级 Install 二次失败: %v", err)
			return false
		}
	}
	logs.Info("已安装用户级 LaunchAgent: %s", userStablePath)
	return true
}

// escalateViaOsascript 通过 macOS 系统对话框请求管理员权限，重新拉起 -install-service。
func escalateViaOsascript() error {
	if !isRunningInTerminal() {
		return errors.New("需要管理员权限安装系统服务。请在终端中运行本程序后再点击安装服务：\n" +
			"  cd $(dirname \"$(which npc_gui)\")\n" +
			"  ./npc_gui\n" +
			"系统会弹出密码框请求管理员权限。")
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取可执行文件路径失败: %w", err)
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("获取用户主目录失败: %w", err)
	}

	quotedExe := shellQuote(exePath)
	quotedHome := shellQuote(homeDir)
	// -home 让 root 进程能找到 GUI 写入的用户配置
	script := fmt.Sprintf(
		`do shell script "%s -install-service -home %s" with administrator privileges`,
		quotedExe, quotedHome)
	logs.Info("通过 osascript 提权安装服务: %s", script)

	cmd := exec.Command("osascript", "-e", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("管理员权限请求失败: %w\nosascript 输出: %s\n\n"+
			"提示：也可以手动执行: sudo %s -install-service -home %s",
			err, string(output), exePath, homeDir)
	}
	return nil
}

// doInstall 直接执行安装：复制二进制 + 写 service。调用方必须已经 root 或在 sudo 上层。
func doInstall(cfg Config) error {
	stablePath, err := installStableBinary()
	if err != nil {
		return fmt.Errorf("复制二进制到稳定路径失败: %w", err)
	}

	if err := saveSystemConfig(cfg); err != nil {
		return fmt.Errorf("保存系统配置失败: %w", err)
	}

	svcConfig := getServiceConfig()
	svcConfig.Executable = stablePath
	prg := &npcService{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		return fmt.Errorf("创建服务实例失败: %w", err)
	}

	// 先尝试 Install；如果旧 plist 残留导致 "Init already exists" 则先 Uninstall 再 Install
	if err := s.Install(); err != nil {
		if !strings.Contains(err.Error(), "Init already exists") {
			return fmt.Errorf("安装服务失败: %w", err)
		}
		logs.Info("检测到旧 plist 残留，先卸载再安装")
		if uerr := s.Uninstall(); uerr != nil {
			return fmt.Errorf("卸载旧 plist 失败: %w（原错误: %v）", uerr, err)
		}
		if err := s.Install(); err != nil {
			return fmt.Errorf("二次安装服务失败: %w", err)
		}
	}
	logs.Info("服务安装完成: %s", stablePath)
	return nil
}

// npcService 实现 service.Interface
type npcService struct {
	exit     chan struct{}
	stopOnce sync.Once
}

func (p *npcService) Start(s service.Service) error {
	logs.Info("npcService.Start 被调用")
	p.exit = make(chan struct{})
	go p.run()
	return nil
}

func (p *npcService) Stop(s service.Service) error {
	logs.Info("npcService.Stop 被调用")
	if p.exit != nil {
		p.stopOnce.Do(func() {
			close(p.exit)
		})
	}
	return nil
}

func (p *npcService) run() {
	for {
		select {
		case <-p.exit:
			logs.Info("收到 Stop 信号，退出 client 循环")
			return
		default:
		}

		cfg := loadSystemConfig()
		if cfg.Server == "" || cfg.Vkey == "" {
			logs.Error("系统配置无效，等待 30 秒后重试（请通过 GUI 配置后再启动服务）")
			select {
			case <-p.exit:
				return
			case <-time.After(30 * time.Second):
			}
			continue
		}

		client.SetTlsEnable(cfg.TlsEnable)
		logs.Info("[service] 连接服务器: %s, vkey: %s, type: %s",
			cfg.Server, cfg.Vkey, cfg.ConnType)
		cl := client.NewRPClient(cfg.Server, cfg.Vkey, cfg.ConnType, cfg.ProxyUrl, nil, cfg.DisconnectTimeout)
		cl.Start()

		select {
		case <-p.exit:
			return
		default:
		}

		logs.Warn("[service] 连接断开，5秒后重连...")
		select {
		case <-p.exit:
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// 配置文件路径

// getConfigDir 返回 service 用的系统配置目录（跨平台）。
func getConfigDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "npc")
	}
	return "/etc/npc"
}

// getUserConfigPath 返回 GUI 用的用户配置路径。
func getUserConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		logs.Warn("获取用户配置目录失败: %v，使用当前目录", err)
		// 回退到可执行文件所在目录
		if exe, err := os.Executable(); err == nil {
			return filepath.Join(filepath.Dir(exe), "npc_gui.json")
		}
		return "npc_gui.json"
	}
	return filepath.Join(dir, "npc", "npc_gui.json")
}

// getSystemConfigPath 返回 service 用的系统配置路径。
func getSystemConfigPath() string {
	return filepath.Join(getConfigDir(), "npc_gui.json")
}

func saveConfig(cfg Config) error {
	return saveJSON(getUserConfigPath(), cfg, 0644)
}

func loadConfig() Config {
	// 优先读系统配置（service install 时写进去的），fallback 用户配置
	cfg, err := readConfigFile(getSystemConfigPath())
	if err != nil {
		cfg, err = readConfigFile(getUserConfigPath())
		if err != nil {
			cfg = defaultConfig()
		}
	}
	return cfg
}

func saveSystemConfig(cfg Config) error {
	dir := getConfigDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建配置目录 %s 失败: %w", dir, err)
	}
	return saveJSON(getSystemConfigPath(), cfg, 0644)
}

func loadSystemConfig() Config {
	cfg, err := readConfigFile(getSystemConfigPath())
	if err != nil {
		logs.Warn("读取系统配置失败: %v", err)
		return defaultConfig()
	}
	return cfg
}

func defaultConfig() Config {
	return Config{
		ConnType:          "tcp",
		DisconnectTimeout: 60,
	}
}

func saveJSON(path string, cfg Config, mode os.FileMode) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", path, err)
	}
	return nil
}

func readConfigFile(path string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	if cfg.ConnType == "" {
		cfg.ConnType = "tcp"
	}
	if cfg.DisconnectTimeout <= 0 {
		cfg.DisconnectTimeout = 60
	}
	return cfg, nil
}

// clearAllConfigs 同时清除用户配置和系统配置。
func clearAllConfigs() error {
	var firstErr error
	for _, p := range []string{getUserConfigPath(), getSystemConfigPath()} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			logs.Warn("删除 %s 失败: %v", p, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
