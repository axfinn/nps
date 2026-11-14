package main

// 在线检查更新：从服务端「客户端下载」目录读取 client-version.json，
// 比对版本后下载对应平台的 GUI 包，校验 sha256/大小、解包自检，再交给
// performUpgrade 完成旧实例清理与平滑替换。
//
// 版本清单由 scripts/gen_client_version.sh 在构建期生成，随镜像一起发布：
//   <下载页 base>/client-version.json
//   <下载页 base>/gui/npc_gui_<os>_<arch>.tar.gz
// 更新源可以显式配置（update_url / -update-url / 编译期 NPC_GUI_UPDATE_URL），
// 未配置时按 server 地址自动探测常见后台端口，探测结果会记住，下次直接用。

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"ehang.io/nps/lib/version"
	"github.com/astaxie/beego/logs"
)

const maxPackageBytes = 120 << 20 // 单个客户端包上限，防止异常响应打满磁盘

type ClientPackage struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Os     string `json:"os,omitempty"`
	Arch   string `json:"arch,omitempty"`
	Sha256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type ClientManifest struct {
	Version     string          `json:"version"`
	Core        string          `json:"core,omitempty"`
	GeneratedAt string          `json:"generated_at,omitempty"`
	Packages    []ClientPackage `json:"packages"`
}

type UpdateCheckResult struct {
	OK             bool     `json:"ok"`
	CurrentVersion string   `json:"current_version"`
	LatestVersion  string   `json:"latest_version"`
	HasUpdate      bool     `json:"has_update"`
	BaseURL        string   `json:"base_url,omitempty"`
	PackageName    string   `json:"package_name,omitempty"`
	PackageURL     string   `json:"package_url,omitempty"`
	Sha256         string   `json:"sha256,omitempty"`
	Size           int64    `json:"size,omitempty"`
	Message        string   `json:"message,omitempty"`
	Candidates     []string `json:"candidates,omitempty"`
}

// normalizeUpdateBase 允许三种写法：
//
//	https://host/static/download
//	https://host/static/download/client-version.json
//	host:8080/static/download
func normalizeUpdateBase(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, "/"+upgradeManifestName)
	return s
}

func hostFromServer(server string) string {
	s := strings.TrimSpace(server)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			return u.Hostname()
		}
	}
	s = strings.SplitN(s, "/", 2)[0]
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return strings.Trim(s, "[]")
}

// candidateUpdateBases 按优先级返回待探测的下载页 base。
func candidateUpdateBases(cfg Config) []string {
	var out []string
	add := func(s string) {
		if v := normalizeUpdateBase(s); v != "" {
			for _, existing := range out {
				if existing == v {
					return
				}
			}
			out = append(out, v)
		}
	}
	if cfg.UpdateUrl != "" {
		add(cfg.UpdateUrl)
	}
	add(buildUpdateURL)
	if host := hostFromServer(cfg.Server); host != "" {
		add(fmt.Sprintf("http://%s:8080/static/download", host))
		add(fmt.Sprintf("http://%s:8081/static/download", host))
		add(fmt.Sprintf("https://%s/static/download", host))
	} else {
		// 连服务器地址都没配时，至少留一个本机后台的常见地址，方便本机调试。
		add("http://127.0.0.1:8080/static/download")
	}
	return out
}

func manifestURL(base string) string { return base + "/" + upgradeManifestName }

func fetchManifest(base string, timeout time.Duration) (ClientManifest, error) {
	var m ClientManifest
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(manifestURL(base))
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return m, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return m, fmt.Errorf("清单不是合法 JSON: %w", err)
	}
	if versionNumbers(m.Version) == nil || len(versionNumbers(m.Version)) == 0 {
		return m, fmt.Errorf("清单缺少 version 字段")
	}
	return m, nil
}

func packageForPlatform(m ClientManifest) (ClientPackage, bool) {
	want := fmt.Sprintf("npc_gui_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	for _, p := range m.Packages {
		if p.Name == want {
			return p, true
		}
	}
	// 兼容清单里显式写了 os/arch 但没有按约定命名的情况
	for _, p := range m.Packages {
		if p.Os == runtime.GOOS && p.Arch == runtime.GOARCH && strings.HasPrefix(p.Name, "npc_gui_") {
			return p, true
		}
	}
	return ClientPackage{}, false
}

func packageURL(base string, p ClientPackage) string {
	if p.Path != "" {
		return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(p.Path, "/")
	}
	return base + "/gui/" + p.Name
}

// checkUpdate 只读操作：探测更新源并比对版本，不改动本机任何文件（除记住可用地址）。
func checkUpdate(cfg Config) UpdateCheckResult {
	res := UpdateCheckResult{CurrentVersion: version.VERSION}
	bases := candidateUpdateBases(cfg)
	res.Candidates = bases
	for _, base := range bases {
		m, err := fetchManifest(base, 4*time.Second)
		if err != nil {
			logs.Info("[update] 探测 %s 失败: %v", manifestURL(base), err)
			continue
		}
		res.BaseURL = base
		res.LatestVersion = m.Version
		res.OK = true
		pkg, ok := packageForPlatform(m)
		if !ok {
			res.Message = fmt.Sprintf("已是 v%s；但清单里没有 %s/%s 的 GUI 包",
				m.Version, runtime.GOOS, runtime.GOARCH)
			return res
		}
		res.PackageName = pkg.Name
		res.PackageURL = packageURL(base, pkg)
		res.Sha256 = pkg.Sha256
		res.Size = pkg.Size
		if compareVersions(m.Version, version.VERSION) > 0 {
			res.HasUpdate = true
			res.Message = fmt.Sprintf("发现新版本 v%s（当前 v%s），可用包 %s",
				m.Version, version.VERSION, pkg.Name)
		} else {
			res.Message = fmt.Sprintf("当前已是最新版本 v%s", version.VERSION)
		}
		// 记住可用的更新源，下次不必逐个端口探测。
		if cfg.UpdateUrl != base {
			cfg.UpdateUrl = base
			mu.Lock()
			curConfig.UpdateUrl = base
			mu.Unlock()
			if err := saveConfig(cfg); err != nil {
				logs.Info("[update] 记住更新源失败（不影响本次检查）: %v", err)
			}
		}
		return res
	}
	res.Message = "未能连接更新源。可在面板「更新源」里填写下载页地址，例如 https://<后台域名>/static/download"
	return res
}

// downloadVerified 下载并按清单校验 sha256 与大小。
func downloadVerified(u, wantSha string, wantSize int64, emit func(string)) (string, error) {
	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Get(u)
	if err != nil {
		return "", fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载失败: HTTP %d", resp.StatusCode)
	}
	name := filepath.Base(strings.Split(u, "?")[0])
	tmp, err := os.CreateTemp("", "npc_gui_update_*.tar.gz")
	if err != nil {
		return "", err
	}
	defer tmp.Close()

	h := sha256.New()
	var written int64
	buf := make([]byte, 64<<10)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			written += int64(n)
			if written > maxPackageBytes {
				_ = os.Remove(tmp.Name())
				return "", fmt.Errorf("包超过 %d MB 上限，已中止", maxPackageBytes>>20)
			}
			if _, err := tmp.Write(buf[:n]); err != nil {
				_ = os.Remove(tmp.Name())
				return "", err
			}
			_, _ = h.Write(buf[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = os.Remove(tmp.Name())
			return "", readErr
		}
	}
	gotSha := hex.EncodeToString(h.Sum(nil))
	if wantSize > 0 && written != wantSize {
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("包大小不符：期望 %d，实际 %d", wantSize, written)
	}
	if wantSha != "" && !strings.EqualFold(gotSha, wantSha) {
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("sha256 校验失败：期望 %s，实际 %s", wantSha, gotSha)
	}
	emit(fmt.Sprintf("已下载 %s（%d 字节，sha256 %s…）", name, written, gotSha[:12]))
	return tmp.Name(), nil
}

// extractGUI binary 从 tar.gz 里只取出客户端主程序，拒绝任何路径穿越与其它文件。
func extractGUIBinary(tarPath string) (string, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("不是有效的 gzip 包: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	want := map[string]bool{"npc_gui": true, "npc_gui.exe": true}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		base := filepath.Base(filepath.Clean(hdr.Name))
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		if !want[base] {
			continue
		}
		if hdr.Size > maxPackageBytes {
			return "", fmt.Errorf("包内二进制过大: %d", hdr.Size)
		}
		dir, err := os.MkdirTemp("", "npc_gui_new_")
		if err != nil {
			return "", err
		}
		outPath := filepath.Join(dir, base)
		out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, io.LimitReader(tr, maxPackageBytes)); err != nil {
			_ = out.Close()
			return "", err
		}
		if err := out.Close(); err != nil {
			return "", err
		}
		if runtime.GOOS != "windows" {
			_ = os.Chmod(outPath, 0755)
		}
		return outPath, nil
	}
	return "", fmt.Errorf("包里没有找到 npc_gui / npc_gui.exe（可能下错了包）")
}

// applyOnlineUpdate 完整在线升级：检查 → 下载校验 → 解包 → 平滑升级。
func applyOnlineUpdate(cfg Config, emit func(string)) UpgradeResult {
	if emit == nil {
		emit = func(string) {}
	}
	fail := func(msg string) UpgradeResult {
		logs.Warn("[update] %s", msg)
		emit(msg)
		return UpgradeResult{Error: msg, Steps: []string{msg}, FromVersion: probeBinaryVersion(mustStablePath()), ToVersion: version.VERSION}
	}
	check := checkUpdate(cfg)
	emit(check.Message)
	if buildServer != "" || buildVkey != "" {
		emit("注意：当前是编译期预置参数的定制包，在线包为通用客户端；已保存的连接配置会保留，预置值不会继承")
	}
	if !check.OK || !check.HasUpdate {
		if !check.OK {
			return fail(check.Message)
		}
		return UpgradeResult{OK: true, FromVersion: version.VERSION, ToVersion: version.VERSION,
			Steps: []string{check.Message}}
	}
	pkgPath, err := downloadVerified(check.PackageURL, check.Sha256, check.Size, emit)
	if err != nil {
		return fail("下载/校验失败：" + err.Error())
	}
	defer os.Remove(pkgPath)

	newBin, err := extractGUIBinary(pkgPath)
	if err != nil {
		_ = os.RemoveAll(filepath.Dir(pkgPath))
		return fail("解包失败：" + err.Error())
	}
	defer os.RemoveAll(filepath.Dir(newBin))

	if _, err := verifyNewBinary(newBin, check.LatestVersion); err != nil {
		return fail("新包自检失败：" + err.Error())
	}
	emit("新包自检通过，开始替换旧实例")
	return performUpgrade(UpgradeOptions{FromBinary: newBin}, emit)
}

func mustStablePath() string {
	p, err := stableBinaryPath()
	if err != nil {
		return ""
	}
	return p
}
