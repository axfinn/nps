package main

// 客户端平滑升级引擎。
//
// 旧行为（升级前）：点「安装服务」只是把当前二进制 O_TRUNC 覆盖到稳定路径、
// 写 plist/unit，遇到 "Init already exists" 就卸载重装，装完还不会启动。
// 于是旧服务进程仍在跑旧代码，Linux/Windows 上覆盖正在执行的二进制还会直接失败。
//
// 现在的流程（只有全部前置校验通过才会碰旧实例，中断窗口被压到最短）：
//
//	发现旧服务/旧进程 → 快照(二进制 + 服务定义) → 停自身连接(避免同 vkey 双连)
//	→ 停并卸载旧服务 → 清理残留进程 → 原子替换二进制 → 重装并启动新服务
//	→ 健康检查；任一步失败自动回滚到旧二进制 + 旧服务定义 + 原运行状态
//
// 兼容范围：当前 GUI 服务 npc-gui、老命令行版服务 Npc / nps-client-<vkey>、
// 以及散落的 npc / npc_gui 进程；「自己」及其祖先进程永远不会被终止。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"ehang.io/nps/lib/version"
	"github.com/astaxie/beego/logs"
	"github.com/kardianos/service"
	"github.com/shirou/gopsutil/v3/process"
)

const (
	currentServiceName  = "npc-gui"
	legacyCLIService    = "Npc"
	legacyClientPrefix  = "nps-client-"
	upgradeManifestName = "client-version.json"
)

// ---------------------------------------------------------------------------
// 对外的数据结构（面板 / CLI 共用）
// ---------------------------------------------------------------------------

type LegacyInstance struct {
	Kind    string `json:"kind"` // service | process | binary
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	PID     int32  `json:"pid,omitempty"`
	Version string `json:"version,omitempty"`
	Running bool   `json:"running,omitempty"`
	Note    string `json:"note,omitempty"`
}

type UpgradePlan struct {
	CurrentVersion   string           `json:"current_version"`   // 本次运行的二进制版本
	NewVersion       string           `json:"new_version"`       // 待安装的版本（可能来自下载包）
	InstalledVersion string           `json:"installed_version"` // 稳定路径上旧二进制的版本
	CurrentPath      string           `json:"current_path"`
	StablePath       string           `json:"stable_path"`
	ServiceName      string           `json:"service_name"`
	ServiceInstalled bool             `json:"service_installed"`
	ServiceRunning   bool             `json:"service_running"`
	SelfIsService    bool             `json:"self_is_service"`
	LegacyServices   []LegacyInstance `json:"legacy_services"`
	LegacyProcesses  []LegacyInstance `json:"legacy_processes"`
	NeedUpgrade      bool             `json:"need_upgrade"`
	CanUpgrade       bool             `json:"can_upgrade"`
	Reason           string           `json:"reason,omitempty"`
}

type UpgradeResult struct {
	OK              bool             `json:"ok"`
	FromVersion     string           `json:"from_version"`
	ToVersion       string           `json:"to_version"`
	NewBinary       string           `json:"new_binary,omitempty"`
	BackupBinary    string           `json:"backup_binary,omitempty"`
	Steps           []string         `json:"steps"`
	Found           []LegacyInstance `json:"found"`
	ServiceRunning  bool             `json:"service_running"`
	ServicePortHint string           `json:"service_port_hint,omitempty"`
	RolledBack      bool             `json:"rolled_back"`
	Error           string           `json:"error,omitempty"`
	DurationMs      int64            `json:"duration_ms"`
}

type UpgradeOptions struct {
	FromBinary     string // 待安装的新二进制；空 = 当前正在运行的这个二进制
	CleanLegacy    bool   // 是否把老 CLI 版服务/进程一并下掉
	CleanProcesses bool   // 是否终止残留的旧进程（提权子进程里应关闭，避免误伤父 GUI）
	StartService   bool   // 升级完成后是否启动服务
}

func defaultUpgradeOptions() UpgradeOptions {
	return UpgradeOptions{CleanLegacy: true, CleanProcesses: true, StartService: true}
}

// ---------------------------------------------------------------------------
// 版本工具
// ---------------------------------------------------------------------------

var versionRe = regexp.MustCompile(`\b(?:v)?(\d+)\.(\d+)\.(\d+)\b`)
var embeddedVersionRe = regexp.MustCompile(`\b0\.\d+\.\d+\b`)

// compareVersions 按数字段比较，a>b 返回 1。v 前缀、_hotfix 之类后缀都会被忽略。
// 版本段数不一致时按 0 补齐（0.26.85 vs 0.26.85.1 也能比较）。
func compareVersions(a, b string) int {
	pa, pb := versionNumbers(a), versionNumbers(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		x, y := 0, 0
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x > y {
			return 1
		}
		if x < y {
			return -1
		}
	}
	return 0
}

func versionNumbers(s string) []int {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "v"))
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == ' '
	})
	out := make([]int, 0, 3)
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			break // 遇到 hotfix / rc 之类的非数字段即停止
		}
		out = append(out, n)
	}
	return out
}

// probeBinaryVersion 只读文件内容推测二进制版本，绝不执行未知旧程序：
// 老版本 npc_gui 未必支持 -version，直接执行会把旧面板再次拉起来。
// 找不到可识别版本串时返回 "unknown"，调用方按「有旧实例 → 需要升级」处理。
func probeBinaryVersion(path string) string {
	if path == "" {
		return "unknown"
	}
	if self, err := os.Executable(); err == nil && samePath(self, path) {
		return version.VERSION
	}
	f, err := os.Open(path)
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	// 版本常量一般落在二进制前段；只读前 32MB，避免把大文件整个吞进内存。
	data := make([]byte, 32<<20)
	n, _ := f.Read(data)
	data = data[:n]
	counts := map[string]int{}
	for _, m := range embeddedVersionRe.FindAllString(string(data), -1) {
		// 0.0.x 基本是第三方库的版本串，不是本项目版本；跳过避免误判。
		nums := versionNumbers(m)
		if len(nums) > 1 && nums[1] == 0 {
			continue
		}
		counts[m]++
	}
	if len(counts) == 0 {
		return "unknown"
	}
	versions := make([]string, 0, len(counts))
	for v := range counts {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool {
		if counts[versions[i]] != counts[versions[j]] {
			return counts[versions[i]] > counts[versions[j]]
		}
		return compareVersions(versions[i], versions[j]) > 0
	})
	return versions[0]
}

// verifyNewBinary 执行新二进制的 -version 自检：必须能在本机跑起来、且输出的版本
// 与预期一致。这样下错平台包 / 包被截断时会在「动旧实例之前」就失败。
func verifyNewBinary(path, expected string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("新二进制路径为空")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("新二进制无法运行（可能平台不匹配或文件损坏）: %v, 输出: %s", err, strings.TrimSpace(string(out)))
	}
	got := ""
	if m := versionRe.FindStringSubmatch(string(out)); len(m) == 4 {
		got = m[1] + "." + m[2] + "." + m[3]
	}
	if got == "" {
		return "", fmt.Errorf("新二进制未输出版本号: %s", strings.TrimSpace(string(out)))
	}
	if expected != "" && expected != "unknown" && got != expected {
		return "", fmt.Errorf("新二进制版本不匹配: 期望 %s, 实际 %s", expected, got)
	}
	return got, nil
}

func samePath(a, b string) bool {
	// macOS 上 /private/var 与 /var 是同一路径，EvalSymlinks 后再比。
	clean := func(p string) string {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Clean(r)
		}
		return filepath.Clean(p)
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(clean(a), clean(b))
	}
	return clean(a) == clean(b)
}

// ---------------------------------------------------------------------------
// 稳定路径 / 服务定义发现
// ---------------------------------------------------------------------------

// stableBinaryPath 返回服务实际执行的二进制路径，installStableBinary 与升级共用。
func stableBinaryPath() (string, error) {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			return "", fmt.Errorf("ProgramData 未设置")
		}
		return filepath.Join(base, "npc", "npc_gui.exe"), nil
	case "darwin":
		if os.Geteuid() == 0 {
			return "/usr/local/bin/npc_gui", nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", "npc", "npc_gui"), nil
	default:
		return "/usr/local/bin/npc_gui", nil
	}
}

type foundService struct {
	Name       string
	Definition string // plist / unit 文件路径
	Running    bool
	UserLevel  bool
	Legacy     bool // 老 CLI 版服务
}

// serviceDefinitionDirs 列出可能残留服务定义文件的目录（只读扫描）。
func serviceDefinitionDirs() []string {
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		return []string{
			filepath.Join(home, "Library", "LaunchAgents"),
			"/Library/LaunchAgents",
			"/Library/LaunchDaemons",
		}
	case "linux":
		return []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system", "/etc/init.d"}
	default:
		return nil
	}
}

func isNPCServiceBase(base string) bool {
	b := strings.ToLower(base)
	for _, ext := range []string{".plist", ".service"} {
		b = strings.TrimSuffix(b, ext)
	}
	return b == currentServiceName || b == "npc_gui" || b == "npc" ||
		strings.HasPrefix(b, legacyClientPrefix) || strings.HasPrefix(b, "npc_gui")
}

// scanServiceDefinitions 从定义文件名反推服务名，覆盖 kardianos Status() 探测不到的
// 情况（例如 launchd job 已卸载但 plist 还在、systemd unit disable 后残留）。
func scanServiceDefinitions() []foundService {
	var out []foundService
	seen := map[string]bool{}
	for _, dir := range serviceDefinitionDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !isNPCServiceBase(e.Name()) {
				continue
			}
			name := e.Name()
			for _, ext := range []string{".plist", ".service"} {
				name = strings.TrimSuffix(name, ext)
			}
			key := strings.ToLower(name) + "|" + dir
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, foundService{
				Name:       name,
				Definition: filepath.Join(dir, e.Name()),
				UserLevel:  strings.Contains(dir, "LaunchAgents") && strings.HasPrefix(dir, os.Getenv("HOME")),
			})
		}
	}
	return out
}

func serviceConfigFor(name string, userLevel bool) *service.Config {
	c := &service.Config{
		Name:        name,
		DisplayName: name,
		Option:      service.KeyValue{},
	}
	if runtime.GOOS == "darwin" && userLevel {
		c.Option["UserService"] = true
	}
	return c
}

func probeService(name string, userLevel bool) (installed, running bool) {
	s, err := service.New(&npcService{}, serviceConfigFor(name, userLevel))
	if err != nil {
		return false, false
	}
	st, err := s.Status()
	if err != nil {
		return false, false
	}
	switch st {
	case service.StatusRunning:
		return true, true
	case service.StatusStopped:
		return true, false
	default:
		return true, false
	}
}

// discoverServices 汇总「当前 GUI 服务 + 老 CLI 服务 + 定义文件残留」。
func discoverServices(cfg Config, cleanLegacy bool) []foundService {
	var out []foundService
	merge := func(s foundService) {
		for i := range out {
			if strings.EqualFold(out[i].Name, s.Name) {
				out[i].Running = out[i].Running || s.Running
				if out[i].Definition == "" {
					out[i].Definition = s.Definition
				}
				return
			}
		}
		out = append(out, s)
	}

	// 当前服务：优先用户级，其次系统级（老版本可能装在 LaunchDaemon/systemd）
	for _, userLevel := range []bool{true, false} {
		if installed, running := probeService(currentServiceName, userLevel); installed {
			merge(foundService{Name: currentServiceName, Running: running, UserLevel: userLevel})
			break
		}
	}

	// 定义文件残留（当前服务的 plist/unit 也在这里补上路径）
	for _, s := range scanServiceDefinitions() {
		s.Legacy = !strings.EqualFold(s.Name, currentServiceName) && s.Name != "npc_gui"
		installed, running := probeService(s.Name, s.UserLevel)
		s.Running = s.Running || running || installed
		merge(s)
	}

	if cleanLegacy {
		candidates := []string{legacyCLIService}
		if vkey := strings.TrimSpace(cfg.Vkey); vkey != "" {
			for _, k := range strings.Split(vkey, ",") {
				if k = strings.TrimSpace(k); k != "" {
					candidates = append(candidates, legacyClientPrefix+k)
				}
			}
		}
		for _, name := range candidates {
			for _, userLevel := range []bool{true, false} {
				if installed, running := probeService(name, userLevel); installed {
					merge(foundService{Name: name, Running: running, UserLevel: userLevel, Legacy: true})
					break
				}
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// 进程发现（绝不误杀自己 / 祖先 / 服务端 nps）
// ---------------------------------------------------------------------------

func isNPCClientProcess(name, exe, cmdline string) bool {
	base := strings.ToLower(filepath.Base(name))
	if base == "" && exe != "" {
		base = strings.ToLower(filepath.Base(exe))
	}
	if base == "" {
		base = strings.ToLower(filepath.Base(strings.Fields(cmdline)[0]))
	}
	base = strings.TrimSuffix(base, ".exe")
	if base == "" {
		return false
	}
	// 服务端 nps 与任何名字里带 server 的进程都不是客户端
	if base == "nps" || strings.Contains(base, "server") {
		return false
	}
	return base == "npc" || base == "npc_gui" || strings.HasPrefix(base, "npc_gui")
}

func protectedPIDs() map[int32]bool {
	protected := map[int32]bool{int32(os.Getpid()): true}
	pid := int32(os.Getpid())
	for i := 0; i < 8; i++ {
		p, err := process.NewProcess(pid)
		if err != nil {
			break
		}
		ppid, err := p.Ppid()
		if err != nil || ppid <= 0 {
			break
		}
		protected[ppid] = true
		pid = ppid
	}
	return protected
}

func discoverProcesses() []LegacyInstance {
	protected := protectedPIDs()
	procs, err := process.Processes()
	if err != nil {
		logs.Warn("列举进程失败: %v", err)
		return nil
	}
	var out []LegacyInstance
	for _, p := range procs {
		if protected[p.Pid] {
			continue
		}
		name, _ := p.Name()
		exe, _ := p.Exe()
		cmd, _ := p.Cmdline()
		if !isNPCClientProcess(name, exe, cmd) {
			continue
		}
		path := exe
		if path == "" {
			path = name
		}
		out = append(out, LegacyInstance{
			Kind:    "process",
			Name:    name,
			Path:    path,
			PID:     p.Pid,
			Version: probeBinaryVersion(path),
			Running: true,
			Note:    strings.TrimSpace(cmd),
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// 预检计划
// ---------------------------------------------------------------------------

func buildUpgradePlan(opts UpgradeOptions) UpgradePlan {
	cfg := loadConfig()
	stable, _ := stableBinaryPath()
	self, _ := os.Executable()
	newBin := opts.FromBinary
	if newBin == "" {
		newBin = self
	}

	plan := UpgradePlan{
		CurrentVersion:   version.VERSION,
		NewVersion:       version.VERSION,
		InstalledVersion: probeBinaryVersion(stable),
		CurrentPath:      self,
		StablePath:       stable,
		ServiceName:      currentServiceName,
		SelfIsService:    serviceMode,
	}
	if opts.FromBinary != "" {
		plan.NewVersion = probeBinaryVersion(newBin)
		// 内容扫描认不出版本时（例如新版改了版本串格式），再跑一次 -version 自检。
		// 这里执行的是「待安装的新包」，不是未知旧程序，不会把旧面板拉起来。
		if plan.NewVersion == "unknown" {
			if v, err := verifyNewBinary(newBin, ""); err == nil {
				plan.NewVersion = v
			}
		}
	}

	services := discoverServices(cfg, opts.CleanLegacy)
	for _, s := range services {
		installed, running := probeService(s.Name, s.UserLevel)
		if s.Name == currentServiceName {
			plan.ServiceInstalled = installed || s.Definition != ""
			plan.ServiceRunning = running || s.Running
		}
		kind := "当前服务"
		if s.Legacy {
			kind = "旧版服务"
		} else if s.Definition != "" && !installed {
			kind = "残留定义"
		}
		plan.LegacyServices = append(plan.LegacyServices, LegacyInstance{
			Kind:    "service",
			Name:    s.Name,
			Path:    s.Definition,
			Running: running || s.Running,
			Note:    kind,
		})
	}
	plan.LegacyProcesses = discoverProcesses()

	// 只要存在旧服务/旧进程，或已装二进制版本与待装版本不同，就需要升级。
	plan.NeedUpgrade = plan.ServiceInstalled || len(plan.LegacyServices) > 0 || len(plan.LegacyProcesses) > 0 ||
		compareVersions(plan.NewVersion, plan.InstalledVersion) != 0
	plan.CanUpgrade = true
	switch {
	case serviceMode:
		plan.CanUpgrade = false
		plan.Reason = "当前面板就是开机自启的服务进程，不能在运行中替换自己；请解压新版后双击运行，或在新包上执行 -upgrade"
	case plan.NewVersion == "unknown" || plan.NewVersion == "":
		plan.CanUpgrade = false
		plan.Reason = "无法识别新二进制版本，拒绝升级"
	case compareVersions(plan.NewVersion, "0.26.0") < 0:
		plan.CanUpgrade = false
		plan.Reason = "新二进制版本异常，拒绝升级"
	}
	return plan
}

// ---------------------------------------------------------------------------
// 快照 / 回滚
// ---------------------------------------------------------------------------

type upgradeSnapshot struct {
	Plan         UpgradePlan
	Services     []foundService
	Definitions  map[string][]byte // 定义文件原始内容，用于回滚
	BinaryBackup string            // 旧二进制 rename 后的路径
	BinaryExists bool
	SelfRunning  bool
	StartedAt    time.Time
}

func takeSnapshot(plan UpgradePlan, services []foundService) *upgradeSnapshot {
	snap := &upgradeSnapshot{
		Plan:        plan,
		Services:    services,
		Definitions: map[string][]byte{},
		StartedAt:   time.Now(),
	}
	if plan.StablePath != "" {
		if _, err := os.Stat(plan.StablePath); err == nil {
			snap.BinaryExists = true
		}
	}
	for _, s := range services {
		if s.Definition == "" {
			continue
		}
		if data, err := os.ReadFile(s.Definition); err == nil {
			snap.Definitions[s.Definition] = data
		}
	}
	return snap
}

// ---------------------------------------------------------------------------
// 停止 / 卸载 / 替换 / 启动
// ---------------------------------------------------------------------------

func platformStopService(s foundService) {
	name := s.Name
	switch runtime.GOOS {
	case "darwin":
		// bootout 会把仍在跑的 LaunchAgent/LaunchDaemon job 真正摘掉；
		// kardianos 的 Uninstall 只删 plist，不会 unload。
		_ = exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", os.Getuid(), name)).Run()
		if s.Definition != "" {
			_ = exec.Command("launchctl", "unload", "-w", s.Definition).Run()
		}
	case "linux":
		_ = exec.Command("systemctl", "stop", name).Run()
		_ = exec.Command("systemctl", "disable", name).Run()
	case "windows":
		_ = exec.Command("sc.exe", "stop", name).Run()
	}
}

func platformStartService(s foundService) {
	name := s.Name
	switch runtime.GOOS {
	case "darwin":
		if s.Definition != "" {
			_ = exec.Command("launchctl", "load", "-w", s.Definition).Run()
		} else {
			_ = exec.Command("launchctl", "kickstart", "-k", fmt.Sprintf("gui/%d/%s", os.Getuid(), name)).Run()
		}
	case "linux":
		_ = exec.Command("systemctl", "daemon-reload").Run()
		_ = exec.Command("systemctl", "enable", name).Run()
		_ = exec.Command("systemctl", "start", name).Run()
	case "windows":
		_ = exec.Command("sc.exe", "start", name).Run()
	}
}

func stopAndUninstallService(s foundService, emit func(string)) {
	if sk, err := service.New(&npcService{}, serviceConfigFor(s.Name, s.UserLevel)); err == nil {
		if err := sk.Stop(); err != nil {
			logs.Info("停止服务 %s (kardianos): %v，继续用平台命令兜底", s.Name, err)
		}
	}
	platformStopService(s)
	if sk, err := service.New(&npcService{}, serviceConfigFor(s.Name, s.UserLevel)); err == nil {
		if err := sk.Uninstall(); err != nil {
			logs.Info("卸载服务 %s (kardianos): %v", s.Name, err)
		}
	}
	if s.Definition != "" {
		if err := os.Remove(s.Definition); err != nil && !os.IsNotExist(err) {
			emit(fmt.Sprintf("服务定义 %s 未能删除（可能需管理员权限）: %v", s.Definition, err))
		} else {
			emit(fmt.Sprintf("已移除服务定义 %s", s.Definition))
		}
	}
	emit(fmt.Sprintf("已停掉并卸载服务 %s", s.Name))
}

func terminateLegacyProcesses(procs []LegacyInstance, emit func(string)) {
	protected := protectedPIDs()
	for _, item := range procs {
		if protected[item.PID] {
			continue
		}
		p, err := process.NewProcess(item.PID)
		if err != nil {
			continue
		}
		_ = p.Terminate() // Windows 上等价 TerminateProcess，Unix 上是 SIGTERM
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			alive, err := p.IsRunning()
			if err != nil || !alive {
				break
			}
			time.Sleep(150 * time.Millisecond)
		}
		if alive, err := p.IsRunning(); err == nil && alive {
			_ = p.Kill()
			emit(fmt.Sprintf("进程 %d (%s) 未响应，已强制结束", item.PID, item.Name))
		} else {
			emit(fmt.Sprintf("已结束旧进程 %d (%s, %s)", item.PID, item.Name, item.Version))
		}
	}
}

// atomicReplaceBinary 先把新二进制落到同目录临时文件，再把旧文件 rename 成备份，
// 最后 rename 成目标名。O_TRUNC 直接覆盖正在执行的程序在 Linux 会 ETXTBSY、
// Windows 会「文件被占用」，rename 方式三平台都可用。
func atomicReplaceBinary(src, dst string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return "", fmt.Errorf("创建目录 %s 失败: %w", filepath.Dir(dst), err)
	}
	in, err := os.Open(src)
	if err != nil {
		return "", fmt.Errorf("读取新二进制失败: %w", err)
	}
	defer in.Close()

	tmp := fmt.Sprintf("%s.new.%d", dst, os.Getpid())
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return "", fmt.Errorf("创建临时文件失败: %w", err)
	}
	if _, err := out.ReadFrom(in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("写入新二进制失败: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("关闭临时文件失败: %w", err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(tmp, 0755)
	}

	backup := fmt.Sprintf("%s.bak.%s", dst, time.Now().Format("20060102-150405"))
	existed := false
	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, backup); err != nil {
			_ = os.Remove(tmp)
			return "", fmt.Errorf("备份旧二进制失败（旧服务可能仍在运行）: %w", err)
		}
		existed = true
	}
	if err := os.Rename(tmp, dst); err != nil {
		if existed {
			_ = os.Rename(backup, dst)
		}
		_ = os.Remove(tmp)
		return "", fmt.Errorf("替换二进制失败: %w", err)
	}
	if !existed {
		backup = ""
	}
	return backup, nil
}

func installAndStartService(stablePath string, start bool, emit func(string)) error {
	svcConfig := getServiceConfig()
	svcConfig.Executable = stablePath
	s, err := service.New(&npcService{}, svcConfig)
	if err != nil {
		return fmt.Errorf("创建服务实例失败: %w", err)
	}
	if err := s.Install(); err != nil {
		if !strings.Contains(err.Error(), "Init already exists") {
			return fmt.Errorf("安装服务失败: %w", err)
		}
		emit("检测到旧服务定义残留，先卸载再安装")
		if uerr := s.Uninstall(); uerr != nil {
			return fmt.Errorf("卸载旧服务定义失败: %w", uerr)
		}
		if err := s.Install(); err != nil {
			return fmt.Errorf("二次安装服务失败: %w", err)
		}
	}
	emit(fmt.Sprintf("已安装新服务 %s -> %s", currentServiceName, stablePath))
	if !start {
		return nil
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("启动服务失败: %w", err)
	}
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := s.Status(); err == nil && st == service.StatusRunning {
			emit("健康检查通过：新服务已处于运行状态")
			return nil
		}
		time.Sleep(400 * time.Millisecond)
	}
	return fmt.Errorf("新服务启动后 12 秒内未进入 running 状态")
}

// stopSelfClient 升级前先停掉当前面板进程里的手动连接，避免与新服务抢同一个 vkey。
func stopSelfClient() bool {
	mu.Lock()
	if !running {
		mu.Unlock()
		return false
	}
	closing = true
	c := cl
	cl = nil
	mu.Unlock()
	if c != nil {
		c.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		still := running
		mu.Unlock()
		if !still {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return true
}

func rollbackUpgrade(snap *upgradeSnapshot, emit func(string)) {
	emit("升级未完成，开始回滚到旧版本…")
	// 1) 恢复旧二进制
	if snap.BinaryBackup != "" {
		if err := os.Remove(snap.Plan.StablePath); err != nil && !os.IsNotExist(err) {
			emit(fmt.Sprintf("回滚：移除新二进制失败 %v", err))
		}
		if err := os.Rename(snap.BinaryBackup, snap.Plan.StablePath); err != nil {
			emit(fmt.Sprintf("回滚：恢复旧二进制失败 %v", err))
		} else {
			emit("已恢复旧二进制")
		}
	} else if !snap.BinaryExists {
		_ = os.Remove(snap.Plan.StablePath)
	}
	// 2) 恢复服务定义文件
	for path, data := range snap.Definitions {
		_ = os.MkdirAll(filepath.Dir(path), 0755)
		if err := os.WriteFile(path, data, 0644); err != nil {
			emit(fmt.Sprintf("回滚：恢复服务定义 %s 失败 %v", path, err))
		}
	}
	// 3) 恢复原本在跑的服务
	for _, s := range snap.Services {
		if s.Running {
			platformStartService(s)
		}
	}
	if !snap.Plan.ServiceRunning && snap.SelfRunning {
		if err := startClient(loadConfig()); err != nil {
			emit(fmt.Sprintf("回滚：恢复面板连接失败 %v", err))
		} else {
			emit("已恢复面板自身的连接")
		}
	}
	emit("回滚完成，旧版本保持可用")
}

// ---------------------------------------------------------------------------
// 主流程
// ---------------------------------------------------------------------------

func performUpgrade(opts UpgradeOptions, emit func(string)) UpgradeResult {
	if emit == nil {
		emit = func(string) {}
	}
	started := time.Now()
	result := UpgradeResult{Steps: []string{}}
	step := func(s string) {
		logs.Info("[upgrade] %s", s)
		result.Steps = append(result.Steps, s)
		emit(s)
	}
	defer func() { result.DurationMs = time.Since(started).Milliseconds() }()

	plan := buildUpgradePlan(opts)
	result.FromVersion = plan.InstalledVersion
	result.ToVersion = plan.NewVersion
	result.Found = append(result.Found, plan.LegacyServices...)
	result.Found = append(result.Found, plan.LegacyProcesses...)
	if !plan.CanUpgrade {
		result.Error = plan.Reason
		step("拒绝升级：" + plan.Reason)
		return result
	}

	newBin := opts.FromBinary
	if newBin == "" {
		newBin = plan.CurrentPath
	}
	result.NewBinary = newBin
	step(fmt.Sprintf("预检：当前 v%s，已安装 v%s，待升级到 v%s；发现 %d 个旧服务、%d 个旧进程",
		plan.CurrentVersion, plan.InstalledVersion, plan.NewVersion,
		len(plan.LegacyServices), len(plan.LegacyProcesses)))

	// 前置自检：任何问题都在动旧实例之前返回，旧版本完全不受影响。
	verified, err := verifyNewBinary(newBin, "")
	if err != nil {
		result.Error = err.Error()
		step("新二进制自检失败，已取消升级：" + err.Error())
		return result
	}
	if plan.NewVersion != "unknown" && verified != plan.NewVersion {
		result.Error = fmt.Sprintf("自检版本 %s 与包内版本 %s 不一致", verified, plan.NewVersion)
		step("版本不一致，已取消升级")
		return result
	}
	result.ToVersion = verified
	step("新二进制自检通过：" + verified)

	services := discoverServices(loadConfig(), opts.CleanLegacy)
	snap := takeSnapshot(plan, services)
	snap.SelfRunning = stopSelfClient()
	if snap.SelfRunning {
		step("已暂停当前面板的连接，避免与新服务抢同一个 vkey")
	}

	committed := false
	defer func() {
		if !committed {
			rollbackUpgrade(snap, step)
			result.RolledBack = true
			result.ServiceRunning = snap.Plan.ServiceRunning
		}
	}()

	for _, s := range services {
		stopAndUninstallService(s, step)
	}
	if opts.CleanProcesses {
		terminateLegacyProcesses(plan.LegacyProcesses, step)
	} else {
		step("提权上下文：跳过旧进程清理，避免误伤拉起本次安装的 GUI 主进程")
	}

	backup, err := atomicReplaceBinary(newBin, plan.StablePath)
	if err != nil {
		result.Error = err.Error()
		step("替换二进制失败：" + err.Error())
		return result
	}
	snap.BinaryBackup = backup
	result.BackupBinary = backup
	step(fmt.Sprintf("已原子替换为新二进制 %s（旧版备份 %s）", plan.StablePath, backup))

	// 配置沿用：用户配置 /etc/npc 两份都不动，只做一次 best-effort 同步。
	if err := saveSystemConfig(loadConfig()); err != nil {
		logs.Info("同步系统配置跳过（通常需要 root）: %v", err)
	}
	if err := installAndStartService(plan.StablePath, opts.StartService, step); err != nil {
		result.Error = err.Error()
		step("安装/启动新服务失败：" + err.Error())
		return result
	}

	result.ServiceRunning = opts.StartService
	result.OK = true
	committed = true
	step(fmt.Sprintf("升级完成：v%s → v%s，服务%s", plan.InstalledVersion, verified,
		map[bool]string{true: "已启动", false: "已安装（未启动）"}[opts.StartService]))
	if opts.StartService && !plan.SelfIsService {
		result.ServicePortHint = "当前面板仍占用着首选端口，新服务可能自动改用备用端口；关闭本窗口后重启服务即可恢复 9666"
		step(result.ServicePortHint)
	}
	return result
}

// ---------------------------------------------------------------------------
// 供 CLI / 调试使用的 JSON 输出
// ---------------------------------------------------------------------------

func planJSON(p UpgradePlan) string {
	b, _ := json.MarshalIndent(p, "", "  ")
	return string(b)
}

func resultJSON(r UpgradeResult) string {
	b, _ := json.MarshalIndent(r, "", "  ")
	return string(b)
}
