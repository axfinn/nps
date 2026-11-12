package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/astaxie/beego/logs"
)

// 状态栏（macOS 菜单栏 / Windows 系统托盘）用一个平台原生的常驻子进程实现。
//
// 之所以不引入 systray / fyne-tray 这类库：发版脚本是 CGO_ENABLED=0 交叉编译，
// macOS 的 NSStatusItem 必须走 Cocoa，带 cgo 的方案在 CI 上编不出来。
// 这里改用系统自带脚本引擎（macOS 的 osascript JXA / Windows 的 PowerShell），
// 零新依赖、零 cgo，且 CGO_ENABLED=0 下所有平台都能编译。
// 无脚本引擎的平台自动降级为「系统通知 + 面板内显示端口」。

type trayController struct {
	mu         sync.Mutex
	cmd        *exec.Cmd
	cancel     context.CancelFunc
	hbCancel   context.CancelFunc
	scriptPath string
	port       int
	url        string
	running    bool
}

var tray = &trayController{}

// Start 启动（或重启）状态栏。bootNotice=true 表示这是开机自启拉起的进程，
// 额外发一次系统通知，让用户知道本次管理面板的端口。
func (t *trayController) Start(port int, url string, fallback bool, bootNotice bool) {
	t.Stop()

	// 端口文件同时充当主进程心跳：主进程被强杀（SIGKILL）时来不及 Stop()，
	// 托盘靠检测心跳时间戳自行退出，不会在菜单栏留下孤儿图标。
	heartbeatPath := getPortFilePath()
	script, args, err := buildTrayCommand(port, url, heartbeatPath)
	if err != nil {
		logs.Warn("状态栏组件不可用，已降级: %v", err)
	} else {
		path := filepath.Join(os.TempDir(), fmt.Sprintf("npc_tray_%d%s", os.Getpid(), trayScriptExt()))
		if werr := os.WriteFile(path, []byte(script), 0644); werr != nil {
			logs.Warn("写入状态栏脚本失败: %v", werr)
		} else {
			t.startHeartbeat()

			t.mu.Lock()
			t.scriptPath = path
			t.port = port
			t.url = url
			ctx, cancel := context.WithCancel(context.Background())
			t.cancel = cancel
			t.mu.Unlock()

			args = append(args, path)
			go t.keepAlive(ctx, args)
		}
	}

	if bootNotice {
		go bootNotify(port, url, fallback)
	}
}

// keepAlive 维持状态栏进程常驻。开机自启时 Aqua/Explorer 会话可能尚未就绪，
// 首次拉起会失败，这里做有限次退避重试；稳定存活超过 30 秒则重置重试计数。
func (t *trayController) keepAlive(ctx context.Context, args []string) {
	backoff := 2 * time.Second
	attempt := 0
	const maxAttempts = 6

	for attempt < maxAttempts {
		if ctx.Err() != nil {
			return
		}
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdout = nil
		cmd.Stderr = nil

		t.mu.Lock()
		t.cmd = cmd
		t.running = true
		t.mu.Unlock()

		if err := cmd.Start(); err != nil {
			t.mu.Lock()
			t.running = false
			t.mu.Unlock()
			logs.Warn("启动状态栏失败: %v", err)
		} else {
			startedAt := time.Now()
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()

			select {
			case <-ctx.Done():
				_ = cmd.Process.Kill()
				<-done
				t.mu.Lock()
				t.running = false
				t.mu.Unlock()
				return
			case err := <-done:
				if ctx.Err() != nil {
					return
				}
				if time.Since(startedAt) > 30*time.Second {
					attempt = 0 // 已经稳定跑过一段时间，重新给满重试机会
				}
				logs.Warn("状态栏进程退出 (%v)，%v 后重试 (%d/%d)", err, backoff, attempt+1, maxAttempts)
			}
		}

		attempt++
		t.mu.Lock()
		t.running = false
		t.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 10*time.Second {
			backoff *= 2
		}
	}
	logs.Warn("状态栏多次拉起失败，已停止重试；管理面板仍可通过端口文件 %s 访问", getPortFilePath())
}

// startHeartbeat 每 5 秒刷新端口文件的修改时间，作为「主进程还活着」的信号。
func (t *trayController) startHeartbeat() {
	ctx, cancel := context.WithCancel(context.Background())
	t.mu.Lock()
	t.hbCancel = cancel
	t.mu.Unlock()

	path := getPortFilePath()
	go func() {
		touch := func() {
			now := time.Now()
			_ = os.Chtimes(path, now, now)
		}
		touch()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				touch()
			}
		}
	}()
}

// Stop 结束状态栏子进程并清理临时脚本。
func (t *trayController) Stop() {
	t.mu.Lock()
	cancel := t.cancel
	hbCancel := t.hbCancel
	cmd := t.cmd
	path := t.scriptPath
	t.cancel = nil
	t.hbCancel = nil
	t.cmd = nil
	t.scriptPath = ""
	t.running = false
	t.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if hbCancel != nil {
		hbCancel()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if path != "" {
		_ = os.Remove(path)
	}
}

// Running 供 /api/status 展示状态栏是否在线。
func (t *trayController) Running() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running
}

func trayScriptExt() string {
	switch runtime.GOOS {
	case "windows":
		return ".ps1"
	default:
		return ".js"
	}
}

// buildTrayCommand 返回 (脚本内容, 启动参数前缀, error)。调用方把脚本落盘后把路径追加到参数末尾。
func buildTrayCommand(port int, url, heartbeatPath string) (string, []string, error) {
	switch runtime.GOOS {
	case "darwin":
		return darwinTrayScript(port, url, heartbeatPath), []string{"osascript", "-l", "JavaScript"}, nil
	case "windows":
		return windowsTrayScript(port, url, heartbeatPath), []string{
			"powershell", "-NoProfile", "-WindowStyle", "Hidden",
			"-ExecutionPolicy", "Bypass", "-File",
		}, nil
	default:
		return "", nil, fmt.Errorf("%s 暂无原生状态栏实现", runtime.GOOS)
	}
}

// darwinTrayScript 用 JXA + AppKit 创建 NSStatusItem：
// 标题直接显示端口，左键单击即打开管理面板，tooltip 给出完整地址。
func darwinTrayScript(port int, url, heartbeatPath string) string {
	return fmt.Sprintf(`ObjC.import('AppKit');
ObjC.import('Foundation');
var app = $.NSApplication.sharedApplication;
app.setActivationPolicy(1);
var panelURL = %s;
var itemTitle = %s;
var heartbeatPath = %s;
ObjC.registerSubclass({
  name: 'NPCTrayActionTarget',
  superclass: 'NSObject',
  methods: {
    'openPanel:': {
      types: ['void', ['id']],
      implementation: function(sender) {
        $.NSWorkspace.sharedWorkspace.openURL($.NSURL.URLWithString($(panelURL)));
      }
    }
  }
});
// 主进程被强杀时心跳会停止；超过 20 秒未刷新就自行退出，
// 避免菜单栏留下一个指向已失效面板的孤儿图标。
ObjC.registerSubclass({
  name: 'NPCTrayWatchdog',
  superclass: 'NSObject',
  methods: {
    'checkOwner:': {
      types: ['void', ['id']],
      implementation: function(timer) {
        var fm = $.NSFileManager.defaultManager;
        var attrs = fm.attributesOfItemAtPathError($(heartbeatPath), null);
        if (!attrs) { app.terminate(null); return; }
        var d = attrs.objectForKey($('NSFileModificationDate'));
        if (!d || d.timeIntervalSinceNow < -20) { app.terminate(null); }
      }
    }
  }
});
var statusItem = $.NSStatusBar.systemStatusBar.statusItemWithLength(-1);
statusItem.button.title = $(itemTitle);
statusItem.button.toolTip = $('NPC 管理面板 ' + panelURL + '（点击打开）');
var target = $.NPCTrayActionTarget.alloc.init;
statusItem.button.setTarget(target);
statusItem.button.setAction('openPanel:');
var watchdog = $.NPCTrayWatchdog.alloc.init;
$.NSTimer.scheduledTimerWithTimeIntervalTargetSelectorUserInfoRepeats(3, watchdog, 'checkOwner:', null, true);
while (true) {
  $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.distantFuture);
}
`, jxaQuote(url), jxaQuote(fmt.Sprintf("NPC :%d", port)), jxaQuote(heartbeatPath))
}

// jxaQuote 生成 JXA 字符串字面量。url 由 Go 用整数端口拼出，这里仍做一次转义兜底。
func jxaQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}

// psQuote 生成 PowerShell 单引号字符串：反斜杠无需转义，适合 Windows 路径。
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func windowsTrayScript(port int, url, heartbeatPath string) string {
	return fmt.Sprintf(`Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$ni = New-Object System.Windows.Forms.NotifyIcon
$ni.Icon = [System.Drawing.SystemIcons]::Application
$ni.Text = %s
$ni.BalloonTipTitle = 'NPC 管理面板已就绪'
$ni.BalloonTipText = %s
$ni.Visible = $true
$ni.ShowBalloonTip(5000)
$ni.add_Click({ Start-Process %s })
$hb = %s
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 3000
$timer.add_Tick({
  $alive = $false
  if (Test-Path $hb) {
    $alive = (((Get-Date) - (Get-Item $hb).LastWriteTime).TotalSeconds -lt 20)
  }
  if (-not $alive) {
    $timer.Stop()
    $ni.Visible = $false
    [System.Windows.Forms.Application]::Exit()
  }
})
$timer.Start()
[System.Windows.Forms.Application]::Run()
`, psQuote(fmt.Sprintf("NPC :%d", port)), psQuote(url), psQuote(url), psQuote(heartbeatPath))
}

// bootNotify 开机后提醒用户本次的实际端口，尤其是发生端口回退时。
func bootNotify(port int, url string, fallback bool) {
	msg := fmt.Sprintf("管理面板 %s，可在状态栏 NPC :%d 点击打开", url, port)
	title := "NPC 已就绪"
	if fallback {
		title = "NPC 已就绪（端口已自动调整）"
		msg = fmt.Sprintf("默认端口被占用，本次改用 %d：%s（状态栏点击可打开）", port, url)
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf(`display notification %s with title %s`,
			appleScriptQuote(msg), appleScriptQuote(title))
		cmd = exec.Command("osascript", "-e", script)
	case "linux":
		if _, err := exec.LookPath("notify-send"); err != nil {
			logs.Info("开机提醒: %s - %s", title, msg)
			return
		}
		cmd = exec.Command("notify-send", title, msg)
	case "windows":
		// Windows 的提醒由托盘脚本里的 BalloonTip 承担
		logs.Info("开机提醒: %s - %s", title, msg)
		return
	default:
		logs.Info("开机提醒: %s - %s", title, msg)
		return
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		logs.Warn("发送开机提醒失败（不影响使用）: %v, %s", err, string(out))
	}
}

func appleScriptQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
