package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestFetchManifest(t *testing.T) {
	wantName := fmt.Sprintf("npc_gui_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	mux := http.NewServeMux()
	mux.HandleFunc("/static/download/client-version.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ClientManifest{
			Version: "99.0.0",
			Packages: []ClientPackage{
				{Name: "npc_gui_other.tar.gz"},
				{Name: wantName, Sha256: "abc", Size: 123, Os: runtime.GOOS, Arch: runtime.GOARCH},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m, err := fetchManifest(srv.URL+"/static/download", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "99.0.0" {
		t.Fatalf("版本不对: %s", m.Version)
	}
	pkg, ok := packageForPlatform(m)
	if !ok || pkg.Name != wantName {
		t.Fatalf("平台包选择错误: %+v, ok=%v", pkg, ok)
	}
	if got := packageURL("https://h/static/download", pkg); got != "https://h/static/download/"+wantName && got != "https://h/static/download/gui/"+wantName {
		t.Fatalf("下载地址拼接错误: %s", got)
	}
}

func TestDownloadVerified(t *testing.T) {
	data := []byte("fake-npc-gui-package")
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()
	emit := func(string) {}

	path, err := downloadVerified(srv.URL, hash, int64(len(data)), emit)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	if got, _ := os.ReadFile(path); string(got) != string(data) {
		t.Fatalf("下载内容不对: %q", got)
	}
	// sha256 不符必须拒绝
	if _, err := downloadVerified(srv.URL, strings.Repeat("0", 64), int64(len(data)), emit); err == nil {
		t.Fatal("sha256 不符时应失败")
	}
	// 大小不符必须拒绝
	if _, err := downloadVerified(srv.URL, hash, int64(len(data))+1, emit); err == nil {
		t.Fatal("大小不符时应失败")
	}
}

func TestCheckUpdateUsesConfiguredSource(t *testing.T) {
	// 隔离 HOME，避免检查更新时把测试用的更新源写进真实用户配置。
	t.Setenv("HOME", t.TempDir())
	wantName := fmt.Sprintf("npc_gui_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/client-version.json") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(ClientManifest{
			Version:  "99.0.0",
			Packages: []ClientPackage{{Name: wantName, Sha256: "abc", Size: 123, Path: "gui/" + wantName}},
		})
	}))
	defer srv.Close()

	cfg := Config{UpdateUrl: srv.URL + "/static/download", Server: "127.0.0.1:8024"}
	res := checkUpdate(cfg)
	if !res.OK || res.LatestVersion != "99.0.0" {
		t.Fatalf("检查更新失败: %+v", res)
	}
	if !res.HasUpdate || res.PackageName != wantName {
		t.Fatalf("应检测到新版本与平台包: %+v", res)
	}
	if res.BaseURL != srv.URL+"/static/download" {
		t.Fatalf("更新源不对: %s", res.BaseURL)
	}
}
