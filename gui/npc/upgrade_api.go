package main

// 升级能力的对外入口：本地面板 HTTP 接口 + 命令行 -upgrade / -update。
// 升级会停止并重启服务，耗时可能超过面板的 30s 写超时，因此统一走后台任务 + 轮询进度。

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type upgradeJob struct {
	mu        sync.Mutex
	running   bool
	kind      string
	startedAt time.Time
	steps     []string
	result    *UpgradeResult
}

var upgJob upgradeJob

type upgradeJobStatus struct {
	Running   bool           `json:"running"`
	Kind      string         `json:"kind,omitempty"`
	StartedAt string         `json:"started_at,omitempty"`
	Steps     []string       `json:"steps"`
	Result    *UpgradeResult `json:"result,omitempty"`
}

func (j *upgradeJob) status() upgradeJobStatus {
	j.mu.Lock()
	defer j.mu.Unlock()
	s := upgradeJobStatus{
		Running: j.running,
		Kind:    j.kind,
		Steps:   append([]string{}, j.steps...),
		Result:  j.result,
	}
	if !j.startedAt.IsZero() {
		s.StartedAt = j.startedAt.Format(time.RFC3339)
	}
	return s
}

// start 返回 false 表示已有任务在跑。
func (j *upgradeJob) start(kind string, fn func(func(string)) UpgradeResult) bool {
	j.mu.Lock()
	if j.running {
		j.mu.Unlock()
		return false
	}
	j.running = true
	j.kind = kind
	j.startedAt = time.Now()
	j.steps = nil
	j.result = nil
	emit := func(msg string) {
		j.mu.Lock()
		j.steps = append(j.steps, msg)
		j.mu.Unlock()
	}
	j.mu.Unlock()

	go func() {
		result := fn(emit)
		j.mu.Lock()
		j.result = &result
		j.running = false
		j.mu.Unlock()
	}()
	return true
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func handleUpgradePlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, buildUpgradePlan(defaultUpgradeOptions()))
}

func handleUpgradeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, upgJob.status())
}

func handleUpgradeApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		FromBinary   string `json:"from_binary"`
		CleanLegacy  *bool  `json:"clean_legacy"`
		StartService *bool  `json:"start_service"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		http.Error(w, "参数解析失败: "+err.Error(), 400)
		return
	}
	opts := defaultUpgradeOptions()
	opts.FromBinary = strings.TrimSpace(req.FromBinary)
	if req.CleanLegacy != nil {
		opts.CleanLegacy = *req.CleanLegacy
	}
	if req.StartService != nil {
		opts.StartService = *req.StartService
	}
	if opts.FromBinary != "" {
		if _, err := os.Stat(opts.FromBinary); err != nil {
			http.Error(w, "新二进制不存在: "+opts.FromBinary, 400)
			return
		}
	}
	if !upgJob.start("local", func(emit func(string)) UpgradeResult {
		return performUpgrade(opts, emit)
	}) {
		http.Error(w, "已有升级任务正在进行", 409)
		return
	}
	writeJSON(w, map[string]bool{"ok": true, "started": true})
}

func handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mu.Lock()
	cfg := curConfig
	mu.Unlock()
	writeJSON(w, checkUpdate(cfg))
}

func handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mu.Lock()
	cfg := curConfig
	mu.Unlock()
	if !upgJob.start("online", func(emit func(string)) UpgradeResult {
		return applyOnlineUpdate(cfg, emit)
	}) {
		http.Error(w, "已有升级任务正在进行", 409)
		return
	}
	writeJSON(w, map[string]bool{"ok": true, "started": true})
}

// ---------------------------------------------------------------------------
// 命令行入口
// ---------------------------------------------------------------------------

// runUpgradeCommands 在 resolveCLI 之后、进入 GUI/服务模式之前执行。
// 返回 handled=true 表示本次启动只做升级命令，main 应立即退出。
func runUpgradeCommands(f *cliFlags) (bool, int) {
	if !*f.upgrade && !*f.upgradePlan && !*f.updateCheck && !*f.updateApply {
		return false, 0
	}
	cfg := loadConfig()
	emit := func(msg string) { fmt.Println("  " + msg) }

	switch {
	case *f.upgradePlan:
		fmt.Println(planJSON(buildUpgradePlan(UpgradeOptions{
			FromBinary:  strings.TrimSpace(*f.upgradeFrom),
			CleanLegacy: true, StartService: true,
		})))
		return true, 0

	case *f.updateCheck:
		res := checkUpdate(cfg)
		fmt.Printf("当前版本: v%s\n最新版本: %s\n%s\n", res.CurrentVersion,
			map[bool]string{true: "v" + res.LatestVersion, false: "无法获取"}[res.OK], res.Message)
		if res.HasUpdate {
			fmt.Printf("可用包: %s\n下载地址: %s\n", res.PackageName, res.PackageURL)
		}
		if !res.OK {
			return true, 1
		}
		return true, 0

	case *f.updateApply:
		if !confirmUpgrade("将检查并在线升级到最新版本（旧服务会被停掉后重启），继续？", *f.upgradeYes) {
			fmt.Println("已取消")
			return true, 0
		}
		res := applyOnlineUpdate(cfg, emit)
		fmt.Println(resultJSON(res))
		if !res.OK {
			return true, 1
		}
		return true, 0

	case *f.upgrade:
		opts := defaultUpgradeOptions()
		opts.FromBinary = strings.TrimSpace(*f.upgradeFrom)
		plan := buildUpgradePlan(opts)
		fmt.Printf("当前 v%s / 已安装 v%s / 待安装 v%s；旧服务 %d 个，旧进程 %d 个\n",
			plan.CurrentVersion, plan.InstalledVersion, plan.NewVersion,
			len(plan.LegacyServices), len(plan.LegacyProcesses))
		if !plan.CanUpgrade {
			fmt.Println("无法升级：" + plan.Reason)
			return true, 1
		}
		if !confirmUpgrade("将停掉旧服务/旧进程并平滑替换为新版本（失败自动回滚），继续？", *f.upgradeYes) {
			fmt.Println("已取消")
			return true, 0
		}
		res := performUpgrade(opts, emit)
		fmt.Println(resultJSON(res))
		if !res.OK {
			return true, 1
		}
		return true, 0
	}
	return false, 0
}

func confirmUpgrade(prompt string, yes bool) bool {
	if yes {
		return true
	}
	fmt.Printf("%s [y/N]: ", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		fmt.Println("\n非交互环境请加 -upgrade-yes 明确确认")
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
