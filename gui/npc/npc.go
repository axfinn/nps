package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
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
	cl               *client.TRPClient
	running          bool
	closing          bool
	mu               sync.Mutex
	curConfig        Config
	svcStatus        string
	httpServer       *http.Server
	serviceMode      bool // 本次是否由开机自启服务拉起
	trayDisabled     bool // -no-tray
	autoOpenDisabled bool // -no-open
)

type Config struct {
	Server            string `json:"server"`
	Vkey              string `json:"vkey"`
	ConnType          string `json:"conn_type"`
	TlsEnable         bool   `json:"tls_enable"`
	ProxyUrl          string `json:"proxy_url"`
	DisconnectTimeout int    `json:"disconnect_timeout"`
	WebPort           int    `json:"web_port"`             // 本地管理面板端口，0/空表示使用默认 9666
	UpdateUrl         string `json:"update_url,omitempty"` // 在线更新源（下载页 base），为空时自动探测
}

type Status struct {
	Running       bool   `json:"running"`
	Version       string `json:"version"`
	Config        Config `json:"config"`
	Logs          string `json:"logs"`
	SvcStatus     string `json:"svc_status"`
	WebPort       int    `json:"web_port"` // 本次实际监听端口（可能与配置不同）
	WebURL        string `json:"web_url"`
	PreferredPort int    `json:"preferred_port"`
	PortFallback  bool   `json:"port_fallback"` // 首选端口被占用，已自动改用随机端口
	TrayRunning   bool   `json:"tray_running"`
	PortFile      string `json:"port_file"`
}

// 兼容旧版本参数。注意 kardianos/service 并不会注册 -service 标志，
// 真正判断是否服务模式改用显式的 -service-run（由 plist/unit 写入），不再靠 ppid 猜测。
var serviceFlag = flag.String("service", "", "兼容旧版服务参数（内部使用）")

func main() {
	// 命令行参数（一次性注册所有 flag，避免重复 flag.Parse 报错）
	cli := registerCLIFlags()
	port := flag.Int("port", 0, "本地管理面板端口（默认 9666；被占用时自动随机分配）")
	installServiceFlag := flag.Bool("install-service", false, "安装系统服务 (内部使用)")
	noSudo := flag.Bool("no-sudo", false, "兼容旧参数：不再自动提权")
	homeFlag := flag.String("home", "", "用户主目录（root 上下文通过此参数找到 GUI 写入的用户配置）")
	serviceRunFlag := flag.Bool("service-run", false, "以开机自启服务模式运行（由服务配置写入，内部使用）")
	noTrayFlag := flag.Bool("no-tray", false, "不显示状态栏图标")
	noOpenFlag := flag.Bool("no-open", false, "启动时不自动打开浏览器（无头/测试环境）")
	flag.Parse()

	if err := resolveCLI(cli); err != nil {
		fmt.Fprintf(os.Stderr, "参数错误: %v\n", err)
		os.Exit(2)
	}

	logs.SetLogger("store")
	configureLogging(cli)

	// 升级类命令是一次性动作，执行完直接退出，不进入面板/服务模式。
	if handled, code := runUpgradeCommands(cli); handled {
		if code != 0 {
			os.Exit(code)
		}
		return
	}

	if *cli.showVersion {
		printVersion()
		return
	}
	// -save 要放在 -print-config 之前，否则 "保存并查看" 组合会只查看不保存。
	if *cli.save {
		if err := saveEffectiveConfig(); err != nil {
			fmt.Fprintf(os.Stderr, "保存配置失败: %v\n", err)
			os.Exit(2)
		}
	}
	if *cli.printConfig {
		printEffectiveConfig(loadConfig())
		return
	}

	_ = noSudo
	trayDisabled = *noTrayFlag || headlessMode
	autoOpenDisabled = *noOpenFlag || headlessMode
	// 只认服务配置里显式写入的 -service-run（以及旧版 -service=run）。
	// 不再用 !service.Interactive() 猜：CI/systemd/无 tty 环境下会把 -headless
	// 误判成服务模式，导致面板被拉起、命令行参数失效。
	serviceMode = *serviceRunFlag || *serviceFlag == "run"

	logs.Info("========== NPC GUI 启动 ==========")
	logs.Info("操作系统: %s", runtime.GOOS)
	logs.Info("参数: installServiceFlag=%v, serviceFlag=%q, serviceRun=%v, serviceMode=%v, port=%d, homeFlag=%q, headless=%v, autostart=%v",
		*installServiceFlag, *serviceFlag, *serviceRunFlag, serviceMode, *port, *homeFlag, headlessMode, autoStartMode)
	logs.Info("================================")

	// 无界面模式：与命令行版 npc 一样跑隧道循环。服务模式优先（由 plist/unit 拉起）。
	if headlessMode && !serviceMode {
		runHeadless(loadConfig())
		return
	}

	// 1) 服务模式：由 plist/unit 带 -service-run 拉起。服务进程同样启动 Web 面板和状态栏，
	//    否则开机自启后就只剩一个无界面的隧道进程，用户根本找不到管理地址。
	if serviceMode {
		runAsService()
		return
	}

	// 2) 安装模式（Linux 提权上下文调用），完成 unit/plist 安装
	if *installServiceFlag {
		runInstallService(*homeFlag)
		return
	}

	// 3) 交互模式。不再在双击时自动提权重启整个 GUI：
	//    root 进程拿不到用户 Aqua 会话，显示不了状态栏，配置目录也会漂移到 /var/root。
	//    默认安装的是「用户级登录自启项」，普通用户权限即可完成，无需 sudo。
	runGUI(*port)
}

// runAsService 以系统服务（开机自启）模式运行：阻塞、调用 prg.Start() 拉起 client 连接。
// 与旧实现最大的不同：服务进程同样启动 Web 面板和状态栏。否则开机后只剩一个
// 无界面的隧道进程，用户既找不到管理地址，也收不到端口提醒。
func runAsService() {
	logs.Info("以服务模式启动 (service=%q)", *serviceFlag)

	curConfig = loadConfig()
	if err := startWebPanel(0, true); err != nil {
		logs.Error("管理面板启动失败（隧道服务仍会继续）: %v", err)
	}

	svcConfig := getServiceConfig()
	prg := &npcService{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		logs.Error("创建服务失败: %v", err)
		shutdownPanel()
		os.Exit(1)
	}
	if err := s.Run(); err != nil {
		logs.Error("服务运行失败: %v", err)
	}
	shutdownPanel()
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

	// 把配置同步到系统配置路径（root 上下文有写权限）
	if err := saveSystemConfig(cfg); err != nil {
		fmt.Printf("保存系统配置失败: %v\n", err)
		os.Exit(1)
	}

	// 与面板「安装服务」走同一套平滑升级引擎：发现并下掉旧实例、原子替换、
	// 重装并启动服务、失败自动回滚。提权子进程里不清理旧进程，避免误伤父 GUI。
	opts := defaultUpgradeOptions()
	opts.CleanProcesses = false
	res := performUpgrade(opts, func(s string) {
		fmt.Println("  " + s)
		logs.Info("[install] %s", s)
	})
	fmt.Println(resultJSON(res))
	if !res.OK {
		fmt.Println("安装/升级失败:", res.Error)
		os.Exit(1)
	}
	fmt.Println("服务安装成功（旧版本已自动下掉，新版本已启动）")
	os.Exit(0)
}

// startWebPanel 启动本地管理面板（HTTP）与状态栏，交互模式和服务模式共用。
// 端口优先级：-port > 配置 web_port > 默认 9666；首选端口被占用时自动随机分配。
// bootNotice=true 时额外发一次开机提醒（服务自启场景）。
func startWebPanel(cliPort int, bootNotice bool) error {
	preferred := resolvePreferredPort(cliPort, curConfig.WebPort)
	ln, actualPort, fallback, err := listenWithFallback(preferred)
	if err != nil {
		return err
	}
	setWebState(preferred, actualPort, fallback)
	url := fmt.Sprintf("http://127.0.0.1:%d", actualPort)

	if err := writePortFile(newPortInfo(preferred, actualPort, fallback)); err != nil {
		logs.Warn("写入端口文件失败（不影响面板使用）: %v", err)
	}

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("加载静态文件失败: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/start", handleStart)
	mux.HandleFunc("/api/stop", handleStop)
	mux.HandleFunc("/api/config", handleConfig)
	mux.HandleFunc("/api/config/clear", handleClearConfig)
	mux.HandleFunc("/api/port", handlePort)
	mux.HandleFunc("/api/service/install", handleServiceInstall)
	mux.HandleFunc("/api/service/uninstall", handleServiceUninstall)
	mux.HandleFunc("/api/upgrade/plan", handleUpgradePlan)
	mux.HandleFunc("/api/upgrade/status", handleUpgradeStatus)
	mux.HandleFunc("/api/upgrade/apply", handleUpgradeApply)
	mux.HandleFunc("/api/update/check", handleUpdateCheck)
	mux.HandleFunc("/api/update/apply", handleUpdateApply)

	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	mu.Lock()
	httpServer = server
	mu.Unlock()

	// 直接复用已绑定的 listener，避免「先探测再重新 bind」期间端口被别的进程抢走。
	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			logs.Error("管理面板异常退出: %v", err)
		}
	}()

	if !trayDisabled {
		tray.Start(actualPort, url, fallback, bootNotice)
	} else if bootNotice {
		go bootNotify(actualPort, url, fallback)
	}

	if fallback {
		logs.Warn("首选端口 %d 不可用，本次面板地址改为 %s", preferred, url)
		fmt.Printf("⚠ 端口 %d 已被占用，已自动改用 %d：%s\n", preferred, actualPort, url)
	}
	logs.Info("管理面板已就绪: %s", url)
	return nil
}

// runGUI 交互模式：启动面板后自动打开浏览器，并等待退出信号。
func runGUI(cliPort int) {
	logs.Info("NPC Web GUI v%s starting...", version.VERSION)

	curConfig = loadConfig()
	svcStatus = getServiceStatus()

	if err := startWebPanel(cliPort, false); err != nil {
		fmt.Printf("启动失败: %v\n", err)
		os.Exit(1)
	}

	port, url, preferred, fallback := getWebState()
	fmt.Printf("NPC Web GUI v%s\n", version.VERSION)
	fmt.Printf("管理面板: %s\n", url)
	if fallback {
		fmt.Printf("注意: 首选端口 %d 已被占用，已自动改用 %d\n", preferred, port)
	}
	fmt.Printf("端口文件: %s\n", getPortFilePath())
	fmt.Printf("状态栏点击图标即可打开面板；按 Ctrl+C 退出\n")

	if !autoOpenDisabled {
		go func() {
			time.Sleep(800 * time.Millisecond)
			openBrowser(url)
		}()
	}

	// 显式给了 -server/-vkey/-config 或 -autostart 时自动连，
	// 不必再进面板点「启动」；纯 GUI 启动（含编译期预置）仍保持原来的手动启动行为。
	if autoStartMode {
		cfg := loadConfig()
		if err := startClient(cfg); err != nil {
			logs.Warn("自动连接跳过: %v（可在面板配置后手动点「启动」）", err)
		} else {
			fmt.Printf("已按启动参数自动连接: %s\n", cfg.Server)
		}
	}

	waitForShutdown()
}

func waitForShutdown() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logs.Info("收到关闭信号，正在停止...")
	fmt.Println("\n正在关闭...")
	shutdownPanel()
	logs.Info("NPC Web GUI 已退出")
}

func shutdownPanel() {
	mu.Lock()
	if running && cl != nil {
		closing = true
		running = false
		cl.Close()
		cl = nil
	}
	srv := httpServer
	httpServer = nil
	mu.Unlock()

	tray.Stop()
	removePortFile()

	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			logs.Error("关闭服务器失败: %v", err)
		}
	}
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

	port, url, preferred, fallback := getWebState()
	status.WebPort = port
	status.WebURL = url
	status.PreferredPort = preferred
	status.PortFallback = fallback
	status.TrayRunning = tray.Running()
	status.PortFile = getPortFilePath()

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
		if cfg.WebPort < 0 || cfg.WebPort > 65535 {
			cfg.WebPort = 0
		}

		mu.Lock()
		// 面板表单不含「更新源」字段时保留已探测到的地址，别被整份覆盖掉。
		if cfg.UpdateUrl == "" {
			cfg.UpdateUrl = curConfig.UpdateUrl
		}
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

// handlePort 允许用户自定义本地管理面板端口。
// 端口在进程启动时绑定，改动保存后需重启才生效；想立即指定可用 -port 命令行参数。
// 无论配置成什么，被占用时都会自动随机分配，并把实际地址写进端口文件和状态栏。
func handlePort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		WebPort int `json:"web_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "参数解析失败: "+err.Error(), 400)
		return
	}
	if req.WebPort < 0 || req.WebPort > 65535 {
		http.Error(w, "端口不合法（1-65535，0 表示使用默认 9666）", 400)
		return
	}

	mu.Lock()
	curConfig.WebPort = req.WebPort
	cfg := curConfig
	mu.Unlock()

	if err := saveConfig(cfg); err != nil {
		http.Error(w, "保存端口失败: "+err.Error(), 500)
		return
	}
	_, currentURL, _, _ := getWebState()
	logs.Info("面板端口已设为 %d（重启后生效）", req.WebPort)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":               true,
		"web_port":         req.WebPort,
		"current_url":      currentURL,
		"restart_required": true,
	})
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
	mu.Unlock()
	if err := startClient(cfg); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// startClient 是面板「启动」按钮、自动启动共用的入口。
// 面板只维护一个 TRPClient，因此多 vkey 时连第一个（多 vkey 请用 -headless）。
func startClient(cfg Config) error {
	mu.Lock()
	if cfg.Server == "" || cfg.Vkey == "" {
		mu.Unlock()
		return fmt.Errorf("请先配置服务器地址和验证密钥")
	}
	if running {
		mu.Unlock()
		return fmt.Errorf("已经在运行中")
	}
	running = true
	closing = false
	mu.Unlock()

	client.SetTlsEnable(cfg.TlsEnable)
	if keys := splitVkeys(cfg.Vkey); len(keys) > 1 {
		logs.Warn("面板模式只连接第一个 vkey（共 %d 个）；多 vkey 请用 -headless", len(keys))
		cfg.Vkey = keys[0]
	} else if len(keys) == 1 {
		cfg.Vkey = keys[0]
	}

	go runClientLoop(cfg)
	return nil
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

// darwinLaunchdConfig 自定义 plist 模板。
// kardianos 的默认模板把 StandardOutPath/StandardErrorPath 写死在 /usr/local/var/log/，
// 用户级 LaunchAgent 以普通用户身份运行没有该目录的写权限，会直接导致 launchd 启动失败。
// 这里去掉不可写的 stdout 重定向，日志由 store logger 与端口文件承担。
const darwinLaunchdConfig = `<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd" >
<plist version='1.0'>
  <dict>
    <key>Label</key>
    <string>{{html .Name}}</string>
    <key>ProgramArguments</key>
    <array>
      <string>{{html .Path}}</string>
    {{range .Config.Arguments}}
      <string>{{html .}}</string>
    {{end}}
    </array>
    {{if .WorkingDirectory}}<key>WorkingDirectory</key>
    <string>{{html .WorkingDirectory}}</string>{{end}}
    <key>SessionCreate</key>
    <{{bool .SessionCreate}}/>
    <key>KeepAlive</key>
    <{{bool .KeepAlive}}/>
    <key>RunAtLoad</key>
    <{{bool .RunAtLoad}}/>
    <key>Disabled</key>
    <false/>
  </dict>
</plist>
`

func getServiceConfig() *service.Config {
	options := make(service.KeyValue)
	svcConfig := &service.Config{
		Name:        "npc-gui",
		DisplayName: "NPC 内网穿透客户端",
		Description: "NPS内网穿透客户端（本地管理面板 + 状态栏 + 隧道）",
		Option:      options,
		// 显式标记服务模式，不再依赖 os.Getppid()==1 去猜。
		// 加了 SessionCreate 的 LaunchAgent 用 ppid 判断并不可靠。
		Arguments: []string{"-service-run"},
	}

	if runtime.GOOS == "darwin" {
		// 用户级 LaunchAgent（~/Library/LaunchAgents）：普通用户权限即可安装，
		// 且进程活在登录用户的 Aqua 会话里 —— 状态栏图标和「点击打开浏览器」
		// 都必须依赖图形会话，系统级 LaunchDaemon（root）拿不到。
		svcConfig.Option["UserService"] = true
		svcConfig.Option["SessionCreate"] = true
		svcConfig.Option["RunAtLoad"] = true
		svcConfig.Option["KeepAlive"] = true
		svcConfig.Option["LaunchdConfig"] = darwinLaunchdConfig
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

	// 与升级引擎共用同一个稳定路径，避免两处逻辑漂移。
	destPath, err := stableBinaryPath()
	if err != nil {
		return "", fmt.Errorf("确定稳定路径失败: %w", err)
	}
	destDir := filepath.Dir(destPath)

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
	// 不能既 defer Close 又 return Close：重复关闭会掩盖真实的写入错误。
	if _, err := out.ReadFrom(in); err != nil {
		_ = out.Close()
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

	// 2) 「安装服务」本身就是一次平滑升级：异步执行后由 /api/upgrade/status 轮询进度，
	//    避免停服务 + 重启的耗时撞上面板的 HTTP 写超时。
	if !upgJob.start("install", func(emit func(string)) UpgradeResult {
		res := installServiceWithPrivilege(cfg, emit)
		svcStatus = getServiceStatus()
		return res
	}) {
		http.Error(w, "已有安装/升级任务正在进行", 409)
		return
	}
	logs.Info("安装/升级任务已启动")
	writeJSON(w, map[string]bool{"ok": true, "started": true})
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

// installServiceWithPrivilege 在 GUI 进程内被调用，完成「安装即升级」。
//
//   - macOS 用户级 LaunchAgent / Windows 管理员 / 已是 root：直接跑平滑升级引擎
//   - Linux 普通用户：优先 pkexec 提权，由 root 子进程（-install-service）跑同一套引擎；
//     提权不可用时仍尝试用户级 systemd（失败会明确报错，并提示 sudo ./npc_gui -upgrade）
//
// 不再使用旧的「直接 O_TRUNC 覆盖二进制 + s.Install()」路径：那条路径既不会
// 停掉旧进程，也不会启动新服务，正是本次要修掉的问题。
func installServiceWithPrivilege(cfg Config, emit func(string)) UpgradeResult {
	if emit == nil {
		emit = func(string) {}
	}
	if err := saveSystemConfig(cfg); err != nil {
		logs.Info("同步系统配置跳过（通常需要 root）: %v", err)
	}

	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		if err := tryLinuxPkexec(); err == nil {
			emit("已通过 pkexec 在 root 上下文完成平滑升级")
			return UpgradeResult{OK: true, ServiceRunning: true,
				Steps: []string{"已通过 pkexec 在 root 上下文完成平滑升级"}}
		}
		emit("pkexec 提权不可用，尝试在当前用户上下文安装（失败可用 sudo ./npc_gui -upgrade）")
	}
	return performUpgrade(defaultUpgradeOptions(), emit)
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

// testInstallAsUser 历史 fallback 入口，同样改走平滑升级引擎。
// Deprecated: 保留仅为兼容旧调用点。
func testInstallAsUser(exePath string, cfg Config) bool {
	_ = exePath
	return doInstall(cfg) == nil
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

// doInstall 是历史入口，保留签名给旧的调用点；内部统一走平滑升级引擎，
// 避免任何路径重新退回「直接覆盖二进制 + Install 不启动」的旧行为。
// Deprecated: 新代码请用 installServiceWithPrivilege / performUpgrade。
func doInstall(cfg Config) error {
	_ = cfg
	res := performUpgrade(defaultUpgradeOptions(), nil)
	if !res.OK {
		return fmt.Errorf("安装/升级失败: %s", res.Error)
	}
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
	if err := saveJSON(getUserConfigPath(), cfg, 0644); err != nil {
		return err
	}
	// 尽力同步给以 root 运行的旧版服务；普通用户无权限时忽略即可。
	if err := saveSystemConfig(cfg); err != nil {
		logs.Info("同步系统配置跳过（通常需要 root）: %v", err)
	}
	return nil
}

func loadConfig() Config {
	// 1) 编译期预置（最低优先级基底）
	cfg := Config{}
	applyBuildDefaults(&cfg)

	// 2) 优先读用户配置（GUI 保存的位置），再 fallback 到系统配置。
	//    旧实现优先 /etc/npc：用户在 GUI 改了配置，服务却仍读旧值，是「装完服务
	//    连接参数不对」的常见原因。这里只覆盖文件里显式写过的字段。
	saved, fields, err := readConfigFile(getUserConfigPath())
	if err != nil {
		saved, fields, err = readConfigFile(getSystemConfigPath())
	}
	if err == nil {
		mergeExplicitFields(&cfg, saved, fields)
	}

	// 3) 叠加 -config、环境变量、命令行参数（按注册顺序，低 → 高）。
	//    放在这里而不是 main 里一次性算好，是为了让服务循环每次重载配置时也能拿到参数。
	for _, patch := range configPatches {
		patch(&cfg)
	}
	normalizeConfig(&cfg)
	return cfg
}

// normalizeConfig 统一做默认填充与清洗；readConfigFile 只负责反序列化，
// 否则「文件里没写 conn_type」会被填成 tcp，挡住编译期预置的 kcp。
func normalizeConfig(cfg *Config) {
	cfg.Server = strings.TrimSpace(cfg.Server)
	cfg.Vkey = strings.TrimSpace(cfg.Vkey)
	cfg.ProxyUrl = strings.TrimSpace(cfg.ProxyUrl)
	if cfg.ConnType == "" {
		cfg.ConnType = "tcp"
	}
	if cfg.DisconnectTimeout <= 0 {
		cfg.DisconnectTimeout = 60
	}
	if cfg.WebPort < 0 || cfg.WebPort > 65535 {
		cfg.WebPort = 0
	}
}

func saveSystemConfig(cfg Config) error {
	dir := getConfigDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建配置目录 %s 失败: %w", dir, err)
	}
	return saveJSON(getSystemConfigPath(), cfg, 0644)
}

// loadSystemConfig 服务循环读取配置。复用 loadConfig 保证服务与 GUI 看到同一份数据；
// 系统级服务（root）会 fallback 到 /etc/npc/npc_gui.json。
func loadSystemConfig() Config {
	return loadConfig()
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
	// 首次运行时 ~/.config/npc（或 ~/Library/Application Support/npc）并不存在，
	// 旧实现直接 WriteFile 会报 no such file，导致「保存配置」按钮必然失败。
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("创建配置目录 %s 失败: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", path, err)
	}
	return nil
}

func readConfigFile(path string) (Config, map[string]bool, error) {
	var cfg Config
	fields := make(map[string]bool)
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fields, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fields, fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err == nil {
		for k := range raw {
			fields[k] = true
		}
	}
	return cfg, fields, nil
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
