package main

// npc_gui 的命令行参数层：让图形界面客户端也能像命令行版 npc 一样带参数运行。
//
// 配置优先级（低 → 高，逐字段覆盖）：
//
//	编译期预置 (-ldflags -X) < 已保存的 GUI 配置 < -config 文件
//	< NPC_* 环境变量 < 显式命令行参数
//
// 编译期预置只填「空字段」，所以用户自己保存过的配置始终优先；
// 想强制覆盖请用 -server/-vkey 等参数，或加 -save 把结果落盘。

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"ehang.io/nps/client"
	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/version"
	"github.com/astaxie/beego/logs"
)

// 编译期可注入的连接参数，配合 go build -ldflags "-X 'main.buildServer=...'" 使用。
// 全部留空时，npc_gui 与纯 GUI 版行为完全一致。
// 注意：真实地址/密钥不要写死在仓库里，构建时通过环境变量注入（见 build.assets.sh）。
var (
	buildServer            string
	buildVkey              string
	buildConnType          string
	buildTlsEnable         string
	buildProxyUrl          string
	buildDisconnectTimeout string
	buildLabel             string
)

var (
	// configPatches 由 resolveCLI 按优先级从低到高注册，loadConfig 末尾依次应用。
	// 服务循环每次重新读配置时也会走这里，保证服务模式与 GUI 看到同一份参数。
	configPatches []func(*Config)
	headlessMode  bool
	autoStartMode bool
	cliProvided   bool // 命令行显式提供了 -server / -vkey / -config
)

// configOverride 用指针表示「该字段被显式指定」，避免 bool false / int 0
// 与「未设置」混淆（这正是 flag.Bool 默认值最容易踩的坑）。
type configOverride struct {
	server            *string
	vkey              *string
	connType          *string
	proxyUrl          *string
	tlsEnable         *bool
	disconnectTimeout *int
	webPort           *int
}

func (o configOverride) apply(cfg *Config) {
	if o.server != nil {
		cfg.Server = *o.server
	}
	if o.vkey != nil {
		cfg.Vkey = *o.vkey
	}
	if o.connType != nil {
		cfg.ConnType = *o.connType
	}
	if o.proxyUrl != nil {
		cfg.ProxyUrl = *o.proxyUrl
	}
	if o.tlsEnable != nil {
		cfg.TlsEnable = *o.tlsEnable
	}
	if o.disconnectTimeout != nil {
		cfg.DisconnectTimeout = *o.disconnectTimeout
	}
	if o.webPort != nil {
		cfg.WebPort = *o.webPort
	}
}

func strPtr(v string) *string { return &v }
func boolPtr(v bool) *bool    { return &v }
func intPtr(v int) *int       { return &v }

func addConfigPatch(p func(*Config)) {
	configPatches = append(configPatches, p)
}

// applyBuildDefaults 把 -ldflags -X 注入的值作为配置基底。
// 已保存配置里显式写过的字段（包括 tls_enable=false）会在 loadConfig 里覆盖它。
func applyBuildDefaults(cfg *Config) {
	cfg.Server = strings.TrimSpace(buildServer)
	cfg.Vkey = strings.TrimSpace(buildVkey)
	cfg.ConnType = strings.TrimSpace(buildConnType)
	cfg.ProxyUrl = strings.TrimSpace(buildProxyUrl)
	if n, err := strconv.Atoi(strings.TrimSpace(buildDisconnectTimeout)); err == nil && n > 0 {
		cfg.DisconnectTimeout = n
	}
	if b, err := strconv.ParseBool(strings.TrimSpace(buildTlsEnable)); err == nil {
		cfg.TlsEnable = b
	}
}

// mergeExplicitFields 只覆盖 JSON 里真实出现过的字段，
// 这样「没写 tls_enable」和「写了 tls_enable:false」可以区分开。
func mergeExplicitFields(dst *Config, src Config, fields map[string]bool) {
	if fields["server"] {
		dst.Server = src.Server
	}
	if fields["vkey"] {
		dst.Vkey = src.Vkey
	}
	if fields["conn_type"] {
		dst.ConnType = src.ConnType
	}
	if fields["proxy_url"] {
		dst.ProxyUrl = src.ProxyUrl
	}
	if fields["tls_enable"] {
		dst.TlsEnable = src.TlsEnable
	}
	if fields["disconnect_timeout"] {
		dst.DisconnectTimeout = src.DisconnectTimeout
	}
	if fields["web_port"] {
		dst.WebPort = src.WebPort
	}
}

// cliFlags 汇总新增的运行参数。注册在默认的 flag.CommandLine 上，
// 由 main 统一 flag.Parse 一次，避免重复 Parse 报错。
type cliFlags struct {
	server            *string
	vkey              *string
	connType          *string
	tlsEnable         *bool
	proxyUrl          *string
	disconnectTimeout *int
	configPath        *string
	headless          *bool
	autoStart         *bool
	save              *bool
	showVersion       *bool
	printConfig       *bool
	logMode           *string
	logLevel          *string
	logPath           *string
	pprof             *string
}

func registerCLIFlags() *cliFlags {
	return &cliFlags{
		server:            flag.String("server", "", "服务器地址 ip:port（与命令行版 npc 的 -server 一致）"),
		vkey:              flag.String("vkey", "", "验证密钥；无界面模式可用英文逗号分隔多个"),
		connType:          flag.String("type", "tcp", "连接类型 tcp|kcp"),
		tlsEnable:         flag.Bool("tls_enable", false, "启用 TLS"),
		proxyUrl:          flag.String("proxy", "", "socks5 代理地址"),
		disconnectTimeout: flag.Int("disconnect_timeout", 60, "心跳超时（秒）"),
		configPath:        flag.String("config", "", "连接配置文件：npc_gui JSON 或命令行版 npc.conf（只取 [common] 段）"),
		headless:          flag.Bool("headless", false, "无界面模式：不启动面板/状态栏/浏览器，直接连服务器（等价命令行客户端）"),
		autoStart:         flag.Bool("autostart", false, "面板模式启动时自动连接（默认需手动点「启动」）"),
		save:              flag.Bool("save", false, "把本次生效的连接参数保存到用户配置（之后双击即用）"),
		showVersion:       flag.Bool("version", false, "显示版本后退出"),
		printConfig:       flag.Bool("print-config", false, "打印本次生效配置（vkey 打码）后退出"),
		logMode:           flag.String("log", "store", "日志输出：store(面板)|stdout|file|both"),
		logLevel:          flag.String("log_level", "7", "日志级别 0~7"),
		logPath:           flag.String("log_path", "", "日志文件路径（-log=file/both 时生效）"),
		pprof:             flag.String("pprof", "", "pprof 监听地址 ip:port"),
	}
}

// resolveCLI 在 flag.Parse 之后调用：确定运行模式并按优先级注册配置覆盖。
func resolveCLI(f *cliFlags) error {
	explicit := make(map[string]bool)
	flag.Visit(func(fl *flag.Flag) { explicit[fl.Name] = true })

	headlessMode = *f.headless
	cliProvided = explicit["server"] || explicit["vkey"] || explicit["config"]
	autoStartMode = *f.autoStart || headlessMode || cliProvided

	// 编译期预置是「最低优先级基底」，由 loadConfig 在读取已保存配置之前调用。
	// 不能做成最后叠加的 patch：那样 bool 类型的 tls_enable 分不清「用户显式写了
	// false」和「用户根本没写」，会把用户配置里的 false 又覆盖回 true。
	// -config 文件、环境变量、显式命令行参数才是逐级叠加的 patch。

	// 2) -config 文件
	if p := strings.TrimSpace(*f.configPath); p != "" {
		o, err := readOverrideFile(p)
		if err != nil {
			return err
		}
		addConfigPatch(o.apply)
	}

	// 3) 环境变量（与命令行版 npc 的 NPC_SERVER_ADDR / NPC_SERVER_VKEY 保持一致）
	envOverride := configOverride{}
	if v := os.Getenv("NPC_SERVER_ADDR"); v != "" {
		envOverride.server = strPtr(v)
	}
	if v := os.Getenv("NPC_SERVER_VKEY"); v != "" {
		envOverride.vkey = strPtr(v)
	}
	if v := os.Getenv("NPC_CONN_TYPE"); v != "" {
		envOverride.connType = strPtr(v)
	}
	if v := os.Getenv("NPC_PROXY_URL"); v != "" {
		envOverride.proxyUrl = strPtr(v)
	}
	if v := os.Getenv("NPC_TLS_ENABLE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			envOverride.tlsEnable = boolPtr(b)
		} else {
			logs.Warn("NPC_TLS_ENABLE=%q 不是合法的布尔值，已忽略", v)
		}
	}
	if v := os.Getenv("NPC_DISCONNECT_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			envOverride.disconnectTimeout = intPtr(n)
		} else {
			logs.Warn("NPC_DISCONNECT_TIMEOUT=%q 不是数字，已忽略", v)
		}
	}
	addConfigPatch(envOverride.apply)

	// 4) 显式命令行参数（最高优先级）。用 flag.Visit 判断，未传的参数不覆盖配置文件。
	flagOverride := configOverride{}
	if explicit["server"] {
		flagOverride.server = strPtr(*f.server)
	}
	if explicit["vkey"] {
		flagOverride.vkey = strPtr(*f.vkey)
	}
	if explicit["type"] {
		flagOverride.connType = strPtr(*f.connType)
	}
	if explicit["tls_enable"] {
		flagOverride.tlsEnable = boolPtr(*f.tlsEnable)
	}
	if explicit["proxy"] {
		flagOverride.proxyUrl = strPtr(*f.proxyUrl)
	}
	if explicit["disconnect_timeout"] {
		flagOverride.disconnectTimeout = intPtr(*f.disconnectTimeout)
	}
	addConfigPatch(flagOverride.apply)

	common.InitPProfFromArg(*f.pprof)
	return nil
}

// readOverrideFile 同时支持两种格式：
//   - npc_gui 自己的 JSON 配置（npc_gui.json）
//   - 命令行版 npc 的 npc.conf（只取 [common] 段的连接参数）
//
// npc.conf 里的 [tcp]/[web]/[secret] 等本地映射段不会生效：隧道由服务端下发，
// npc_gui 只需要 common 段的连接信息。
func readOverrideFile(path string) (configOverride, error) {
	var o configOverride
	data, err := os.ReadFile(path)
	if err != nil {
		return o, fmt.Errorf("读取 -config %s 失败: %w", path, err)
	}
	if strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
		var cfg Config
		if err := json.Unmarshal(data, &cfg); err != nil {
			return o, fmt.Errorf("解析 JSON 配置 %s 失败: %w", path, err)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			return o, fmt.Errorf("解析 JSON 配置 %s 失败: %w", path, err)
		}
		has := func(k string) bool { _, ok := raw[k]; return ok }
		if has("server") {
			o.server = strPtr(cfg.Server)
		}
		if has("vkey") {
			o.vkey = strPtr(cfg.Vkey)
		}
		if has("conn_type") {
			o.connType = strPtr(cfg.ConnType)
		}
		if has("proxy_url") {
			o.proxyUrl = strPtr(cfg.ProxyUrl)
		}
		if has("tls_enable") {
			o.tlsEnable = boolPtr(cfg.TlsEnable)
		}
		if has("disconnect_timeout") {
			o.disconnectTimeout = intPtr(cfg.DisconnectTimeout)
		}
		if has("web_port") {
			o.webPort = intPtr(cfg.WebPort)
		}
		return o, nil
	}
	return parseNpcConf(data)
}

func parseNpcConf(data []byte) (configOverride, error) {
	var o configOverride
	// 有些精简版 npc.conf 没有 [common] 头，默认先按 common 段读，
	// 遇到任意 [section] 再切换。
	inCommon := true
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inCommon = strings.EqualFold(line, "[common]")
			continue
		}
		if !inCommon {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, value := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch key {
		case "server_addr":
			o.server = strPtr(value)
		case "vkey":
			o.vkey = strPtr(value)
		case "conn_type":
			o.connType = strPtr(value)
		case "proxy_url":
			o.proxyUrl = strPtr(value)
		case "web_port":
			if n, err := strconv.Atoi(value); err == nil {
				o.webPort = intPtr(n)
			}
		case "tls_enable":
			b, err := strconv.ParseBool(value)
			if err != nil {
				return o, fmt.Errorf("npc.conf 的 tls_enable=%q 不是合法布尔值", value)
			}
			o.tlsEnable = boolPtr(b)
		case "disconnect_timeout":
			n, err := strconv.Atoi(value)
			if err != nil {
				return o, fmt.Errorf("npc.conf 的 disconnect_timeout=%q 不是数字", value)
			}
			o.disconnectTimeout = intPtr(n)
		}
	}
	if err := sc.Err(); err != nil {
		return o, fmt.Errorf("解析 npc.conf 失败: %w", err)
	}
	return o, nil
}

// configureLogging 保留面板用的 store adapter，按 -log 追加 stdout/file 输出。
// 无界面模式没有面板，默认改用 stdout，否则日志只进内存、终端什么都看不到。
func configureLogging(f *cliFlags) {
	level := strings.TrimSpace(*f.logLevel)
	if n, err := strconv.Atoi(level); err != nil || n < 0 || n > 7 {
		logs.Warn("log_level=%q 不合法，回退为 7", *f.logLevel)
		level = "7"
	}
	mode := strings.ToLower(strings.TrimSpace(*f.logMode))
	if headlessMode && mode == "store" {
		mode = "stdout"
	}
	switch mode {
	case "store", "stdout", "file", "both":
	default:
		logs.Warn("log=%q 不合法（store|stdout|file|both），回退为 store", mode)
		mode = "store"
	}

	if mode == "stdout" || mode == "both" {
		cfg := fmt.Sprintf(`{"level":%s,"color":false}`, level)
		if err := logs.SetLogger(logs.AdapterConsole, cfg); err != nil {
			logs.Warn("启用控制台日志失败: %v", err)
		}
	}
	if mode == "file" || mode == "both" {
		path := strings.TrimSpace(*f.logPath)
		if path == "" {
			path = common.GetNpcLogPath()
		}
		if common.IsWindows() {
			path = strings.ReplaceAll(path, `\`, `\\`)
		}
		cfg := fmt.Sprintf(`{"level":%s,"filename":"%s","daily":false,"maxlines":100000,"color":false}`, level, path)
		if err := logs.SetLogger(logs.AdapterFile, cfg); err != nil {
			logs.Warn("启用文件日志失败: %v", err)
		}
	}
}

func printVersion() {
	fmt.Printf("npc_gui %s (core %s)\n", version.VERSION, version.GetVersion())
	if buildLabel != "" {
		fmt.Printf("定制标签: %s\n", buildLabel)
	}
}

func maskVkey(v string) string {
	if v == "" {
		return ""
	}
	if len(v) <= 8 {
		return strings.Repeat("*", len(v))
	}
	return v[:4] + "***" + v[len(v)-4:]
}

// printEffectiveConfig 打印最终生效配置，vkey 打码（避免日志/终端泄露凭据）。
func printEffectiveConfig(cfg Config) {
	out := struct {
		Server            string `json:"server"`
		Vkey              string `json:"vkey_masked"`
		VkeyLength        int    `json:"vkey_length"`
		ConnType          string `json:"conn_type"`
		TlsEnable         bool   `json:"tls_enable"`
		ProxyUrl          string `json:"proxy_url"`
		DisconnectTimeout int    `json:"disconnect_timeout"`
		WebPort           int    `json:"web_port"`
		BuildLabel        string `json:"build_label"`
		Headless          bool   `json:"headless"`
		AutoStart         bool   `json:"autostart"`
	}{
		Server:            cfg.Server,
		Vkey:              maskVkey(cfg.Vkey),
		VkeyLength:        len(cfg.Vkey),
		ConnType:          cfg.ConnType,
		TlsEnable:         cfg.TlsEnable,
		ProxyUrl:          cfg.ProxyUrl,
		DisconnectTimeout: cfg.DisconnectTimeout,
		WebPort:           cfg.WebPort,
		BuildLabel:        buildLabel,
		Headless:          headlessMode,
		AutoStart:         autoStartMode,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
}

func saveEffectiveConfig() error {
	cfg := loadConfig()
	if cfg.Server == "" || cfg.Vkey == "" {
		return fmt.Errorf("生效配置缺少 server 或 vkey，未保存")
	}
	if err := saveConfig(cfg); err != nil {
		return err
	}
	// 提示走 stderr，保证 "-save -print-config" 的 stdout 仍是纯净 JSON
	fmt.Fprintf(os.Stderr, "已保存配置到 %s\n", getUserConfigPath())
	return nil
}

func splitVkeys(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// runHeadless 是「像命令行客户端一样」的运行方式：不启 Web 面板、状态栏、浏览器，
// 直接用参数连服务器并阻塞到收到 SIGINT/SIGTERM；支持逗号分隔多 vkey 并发重连。
func runHeadless(cfg Config) {
	if cfg.Server == "" || cfg.Vkey == "" {
		fmt.Fprintln(os.Stderr, "错误: 无界面模式需要 -server 与 -vkey")
		fmt.Fprintln(os.Stderr, "      也可通过 -config、NPC_SERVER_ADDR/NPC_SERVER_VKEY 或编译期预置提供")
		os.Exit(2)
	}

	client.SetTlsEnable(cfg.TlsEnable)
	vkeys := splitVkeys(cfg.Vkey)
	fmt.Printf("npc_gui 无界面模式 v%s | server=%s | vkey=%s | type=%s | tls=%v | %d 个连接\n",
		version.VERSION, cfg.Server, maskVkey(cfg.Vkey), cfg.ConnType, cfg.TlsEnable, len(vkeys))

	stop := make(chan struct{})
	var mu sync.Mutex
	active := make(map[int]*client.TRPClient)
	var wg sync.WaitGroup

	for i, vk := range vkeys {
		wg.Add(1)
		go func(idx int, vkey string) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				logs.Info("[headless] 连接 %s vkey=%s type=%s tls=%v",
					cfg.Server, maskVkey(vkey), cfg.ConnType, cfg.TlsEnable)
				c := client.NewRPClient(cfg.Server, vkey, cfg.ConnType, cfg.ProxyUrl, nil, cfg.DisconnectTimeout)
				mu.Lock()
				active[idx] = c
				mu.Unlock()
				c.Start()
				select {
				case <-stop:
					return
				case <-time.After(5 * time.Second):
					logs.Warn("[headless] 连接断开，5 秒后重连")
				}
			}
		}(i, vk)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Println("\n正在关闭...")
	close(stop)
	mu.Lock()
	for _, c := range active {
		if c != nil {
			c.Close()
		}
	}
	mu.Unlock()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		logs.Warn("[headless] 等待连接退出超时，强制结束")
	}
}
