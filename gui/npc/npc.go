package main

import (
	"context"
	"embed"
	"encoding/json"
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
	// 命令行参数
	port := flag.Int("port", 0, "指定Web GUI端口 (默认自动选择可用端口)")
	installServiceFlag := flag.Bool("install-service", false, "安装系统服务 (内部使用)")
	noSudo := flag.Bool("no-sudo", false, "不请求管理员权限（跳过自动提权）")
	flag.Parse()

	logs.SetLogger("store")

	// 调试信息
	logs.Info("========== NPC GUI 启动 ==========")
	logs.Info("操作系统: %s", runtime.GOOS)
	logs.Info("参数: noSudo=%v, installServiceFlag=%v", *noSudo, *installServiceFlag)
	logs.Info("终端检测: %v", isRunningInTerminal())
	logs.Info("================================")

	// macOS: 如果双击运行（非终端），自动请求 sudo 重启
	if runtime.GOOS == "darwin" && !*noSudo && !*installServiceFlag && !isRunningInTerminal() {
		exePath, err := os.Executable()
		if err == nil {
			logs.Info("检测到双击运行，请求管理员权限...")

			// 构建参数
			args := []string{"-no-sudo"}
			if *port > 0 {
				args = append(args, "-port", fmt.Sprintf("%d", *port))
			}
			argsStr := ""
			for _, arg := range args {
				argsStr += fmt.Sprintf(" %s", arg)
			}

			// 使用 osascript 请求权限重启
			// 注意：需要转义路径中的空格
			escapedPath := fmt.Sprintf("'%s'", exePath)
			script := fmt.Sprintf(`do shell script "%s%s > /tmp/npc_gui.log 2>&1 &" with administrator privileges`, escapedPath, argsStr)

			logs.Info("执行 AppleScript: %s", script)
			cmd := exec.Command("osascript", "-e", script)
			output, err := cmd.CombinedOutput()

			if err != nil {
				logs.Error("权限请求失败: %v, 输出: %s", err, string(output))
				fmt.Printf("⚠️  未能获取管理员权限: %v\n", err)
				fmt.Println("继续以普通用户模式运行（服务安装功能将不可用）")
				fmt.Println("按 Ctrl+C 退出，然后在终端中运行以获得完整功能")
				time.Sleep(3 * time.Second)
			} else {
				logs.Info("权限请求成功，正在重启...")
				fmt.Println("✓ 已获取管理员权限，正在启动...")
				time.Sleep(1 * time.Second)
				os.Exit(0)
			}
		}
	}

	// 处理服务安装命令（用于 sudo/管理员权限安装）
	if *installServiceFlag {
		cfg := loadSystemConfig()
		if cfg.Server == "" || cfg.Vkey == "" {
			fmt.Println("错误: 配置无效")
			os.Exit(1)
		}

		svcConfig := getServiceConfig()
		svcConfig.Arguments = []string{"-service", "run"}
		prg := &npcService{}
		s, err := service.New(prg, svcConfig)
		if err != nil {
			fmt.Printf("创建服务失败: %v\n", err)
			os.Exit(1)
		}

		_ = s.Uninstall()
		if err := s.Install(); err != nil {
			fmt.Printf("安装服务失败: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("服务安装成功")
		os.Exit(0)
	}

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
	if *port > 0 {
		listenPort = *port
	} else {
		// 自动选择可用端口
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
		fmt.Printf("请检查端口 23333 是否被占用\n")
		os.Exit(1)
	}

	logs.Info("NPC Web GUI 已退出")
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
	json.NewEncoder(w).Encode(status)
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		mu.Lock()
		cfg := curConfig
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
		return
	}

	if r.Method == "POST" {
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
		logs.Info("配置已保存")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}

	http.Error(w, "Method not allowed", 405)
}

func handleClearConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	// 清除内存中的配置
	mu.Lock()
	curConfig = Config{
		ConnType:          "tcp",
		DisconnectTimeout: 60,
	}
	mu.Unlock()

	// 删除配置文件
	userConfigPath := getUserConfigPath()
	systemConfigPath := getSystemConfigPath()

	if err := os.Remove(userConfigPath); err != nil && !os.IsNotExist(err) {
		logs.Warn("删除用户配置文件失败: %v", err)
	}

	if err := os.Remove(systemConfigPath); err != nil && !os.IsNotExist(err) {
		logs.Warn("删除系统配置文件失败: %v", err)
	}

	logs.Info("配置已清除")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
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

	go func() {
		for {
			mu.Lock()
			if closing {
				running = false
				mu.Unlock()
				return
			}
			mu.Unlock()

			logs.Info("连接服务器: %s, vkey: %s, type: %s, tls: %v", cfg.Server, cfg.Vkey, cfg.ConnType, cfg.TlsEnable)
			newClient := client.NewRPClient(cfg.Server, cfg.Vkey, cfg.ConnType, cfg.ProxyUrl, nil, cfg.DisconnectTimeout)

			mu.Lock()
			if closing {
				running = false
				mu.Unlock()
				return
			}
			cl = newClient
			mu.Unlock()

			cl.Start()

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
	}()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
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

	// 在锁外关闭客户端，避免死锁
	if clientToClose != nil {
		clientToClose.Close()
	}

	logs.Info("客户端已停止")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
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
		// macOS: 使用 LaunchAgents (用户级别，不需要 root)
		svcConfig.Option["UserService"] = true
		svcConfig.Option["RunAtLoad"] = true
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
	}
	svcConfig.Executable = exePath

	return svcConfig
}

// getService 创建服务实例，减少重复代码
func getService() (service.Service, error) {
	svcConfig := getServiceConfig()
	prg := &npcService{}
	return service.New(prg, svcConfig)
}

func getServiceStatus() string {
	s, err := getService()
	if err != nil {
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
	// 检查是否有终端连接
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		logs.Info("检测终端状态失败: %v, 假定非终端运行", err)
		return false
	}

	isTerminal := (fileInfo.Mode() & os.ModeCharDevice) != 0

	// macOS 额外检查：检查 TERM 环境变量
	if runtime.GOOS == "darwin" {
		termEnv := os.Getenv("TERM")
		sshConnection := os.Getenv("SSH_CONNECTION")

		logs.Info("终端检测: isCharDevice=%v, TERM=%s, SSH_CONNECTION=%s",
			isTerminal, termEnv, sshConnection)

		// 如果没有 TERM 环境变量或 TERM 为空，很可能是双击运行
		if termEnv == "" && sshConnection == "" {
			logs.Info("检测到双击运行（无 TERM 环境变量）")
			return false
		}
	}

	return isTerminal
}

// installServiceWithSudo macOS 使用 sudo 安装服务
func installServiceWithSudo(s service.Service) error {
	if runtime.GOOS != "darwin" {
		return s.Install()
	}

	// macOS: 尝试用户级别安装
	err := s.Install()
	if err == nil {
		return nil
	}

	// 如果失败，需要管理员权限
	logs.Warn("用户级别安装失败，需要管理员权限: %v", err)

	// 检查是否在终端运行
	if !isRunningInTerminal() {
		return fmt.Errorf("需要管理员权限。请在终端中运行此程序，系统会提示输入密码：\n\n  终端命令示例:\n  cd 程序所在目录\n  ./npc_gui_darwin_arm64\n\n然后在浏览器中点击安装服务")
	}

	// 在终端中运行，尝试使用 osascript 请求权限
	exePath, _ := os.Executable()
	script := fmt.Sprintf(`do shell script "%s -install-service" with administrator privileges`, exePath)
	cmd := exec.Command("osascript", "-e", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("管理员权限请求失败: %v\n输出: %s\n\n提示：也可以在终端中运行: sudo %s -install-service", err, string(output), exePath)
	}

	return nil
}

func handleServiceInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	mu.Lock()
	cfg := curConfig
	mu.Unlock()

	if cfg.Server == "" || cfg.Vkey == "" {
		http.Error(w, "请先配置服务器地址和验证密钥", 400)
		return
	}

	if err := saveSystemConfig(cfg); err != nil {
		http.Error(w, "保存系统配置失败: "+err.Error(), 500)
		return
	}

	svcConfig := getServiceConfig()
	svcConfig.Arguments = []string{"-service", "run"}

	prg := &npcService{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		http.Error(w, "创建服务失败: "+err.Error(), 500)
		return
	}

	_ = s.Uninstall()

	// 使用带权限提示的安装方法
	if err := installServiceWithSudo(s); err != nil {
		errMsg := err.Error()
		if runtime.GOOS == "darwin" {
			errMsg = "安装服务失败。macOS 提示：请在终端运行程序并授予权限，或手动安装服务。错误: " + errMsg
		}
		http.Error(w, errMsg, 500)
		return
	}

	svcStatus = getServiceStatus()
	logs.Info("服务安装成功")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleServiceUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	s, err := getService()
	if err != nil {
		http.Error(w, "创建服务失败: "+err.Error(), 500)
		return
	}

	_ = s.Stop()
	if err := s.Uninstall(); err != nil {
		http.Error(w, "卸载服务失败: "+err.Error(), 500)
		return
	}

	svcStatus = getServiceStatus()
	logs.Info("服务已卸载")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// npcService 实现 service.Interface
type npcService struct {
	exit chan struct{}
}

func (p *npcService) Start(s service.Service) error {
	p.exit = make(chan struct{})
	go p.run()
	return nil
}

func (p *npcService) Stop(s service.Service) error {
	close(p.exit)
	return nil
}

func (p *npcService) run() {
	cfg := loadSystemConfig()
	if cfg.Server == "" || cfg.Vkey == "" {
		logs.Error("配置无效，服务退出")
		return
	}

	client.SetTlsEnable(cfg.TlsEnable)

	for {
		select {
		case <-p.exit:
			return
		default:
		}

		logs.Info("连接服务器: %s, vkey: %s, type: %s", cfg.Server, cfg.Vkey, cfg.ConnType)
		cl := client.NewRPClient(cfg.Server, cfg.Vkey, cfg.ConnType, cfg.ProxyUrl, nil, cfg.DisconnectTimeout)
		cl.Start()

		select {
		case <-p.exit:
			return
		default:
		}

		logs.Warn("连接断开，5秒后重连...")
		time.Sleep(5 * time.Second)
	}
}

// 配置文件路径
func getConfigDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "npc")
	}
	return "/etc/npc"
}

func getUserConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		logs.Warn("获取用户配置目录失败: %v", err)
		// 回退到当前目录
		return "npc_gui.json"
	}
	return filepath.Join(dir, "npc_gui.json")
}

func getSystemConfigPath() string {
	return filepath.Join(getConfigDir(), "npc_gui.json")
}

func saveConfig(cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		logs.Error("序列化配置失败: %v", err)
		return err
	}
	if err := os.WriteFile(getUserConfigPath(), data, 0644); err != nil {
		logs.Error("保存配置失败: %v", err)
		return err
	}
	return nil
}

func loadConfig() Config {
	var cfg Config
	cfg.ConnType = "tcp"
	cfg.DisconnectTimeout = 60

	data, err := os.ReadFile(getUserConfigPath())
	if err != nil {
		data, err = os.ReadFile(getSystemConfigPath())
	}
	if err != nil {
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		logs.Warn("解析配置失败: %v", err)
	}
	return cfg
}

func saveSystemConfig(cfg Config) error {
	dir := getConfigDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		logs.Error("创建配置目录失败: %v", err)
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		logs.Error("序列化配置失败: %v", err)
		return err
	}
	if err := os.WriteFile(getSystemConfigPath(), data, 0644); err != nil {
		logs.Error("保存系统配置失败: %v", err)
		return err
	}
	return nil
}

func loadSystemConfig() Config {
	var cfg Config
	cfg.ConnType = "tcp"
	cfg.DisconnectTimeout = 60

	data, err := os.ReadFile(getSystemConfigPath())
	if err != nil {
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		logs.Warn("解析系统配置失败: %v", err)
	}
	return cfg
}
