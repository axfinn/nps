package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.26.85", "0.26.84", 1},
		{"0.26.84", "0.26.85", -1},
		{"v0.26.85", "0.26.85", 0},
		{"0.26.85_hotfix", "0.26.85", 0},
		{"0.27.0", "0.26.99", 1},
		{"0.26.85.1", "0.26.85", 1},
		{"unknown", "0.26.85", -1},
		{"", "0.26.85", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q)=%d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestIsNPCClientProcess(t *testing.T) {
	cases := []struct {
		name, exe, cmd string
		want           bool
	}{
		{"npc", "/usr/local/bin/npc", "/usr/local/bin/npc -server=x", true},
		{"npc_gui", "/Users/x/npc_gui", "", true},
		{"npc_gui.exe", `C:\ProgramData\npc\npc_gui.exe`, "", true},
		{"nps", "/usr/local/bin/nps", "", false}, // 服务端不能被误杀
		{"bash", "/bin/bash", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		if got := isNPCClientProcess(c.name, c.exe, c.cmd); got != c.want {
			t.Errorf("isNPCClientProcess(%q,%q,%q)=%v, want %v", c.name, c.exe, c.cmd, got, c.want)
		}
	}
}

func TestIsNPCServiceBase(t *testing.T) {
	cases := map[string]bool{
		"npc-gui.plist":          true,
		"npc-gui.service":        true,
		"Npc.plist":              true, // 老命令行版
		"nps-client-abc.service": true,
		"npc_gui.plist":          true,
		"nps.service":            false,
		"com.example.foo.plist":  false,
	}
	for name, want := range cases {
		if got := isNPCServiceBase(name); got != want {
			t.Errorf("isNPCServiceBase(%q)=%v, want %v", name, got, want)
		}
	}
}

func TestNormalizeUpdateBase(t *testing.T) {
	cases := map[string]string{
		"https://h/static/download/":                    "https://h/static/download",
		"https://h/static/download/client-version.json": "https://h/static/download",
		"h:8080/static/download":                        "http://h:8080/static/download",
		"":                                              "",
		"  https://h/static/download  ":                 "https://h/static/download",
	}
	for in, want := range cases {
		if got := normalizeUpdateBase(in); got != want {
			t.Errorf("normalizeUpdateBase(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestHostFromServer(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:8024":                "1.2.3.4",
		"example.com:8024":            "example.com",
		"https://foo.example.com:443": "foo.example.com",
		"[::1]:8024":                  "::1",
		"":                            "",
	}
	for in, want := range cases {
		if got := hostFromServer(in); got != want {
			t.Errorf("hostFromServer(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestPackageForPlatform(t *testing.T) {
	wantName := fmt.Sprintf("npc_gui_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	m := ClientManifest{Version: "0.26.86", Packages: []ClientPackage{
		{Name: "npc_gui_linux_amd64.tar.gz", Sha256: "aaa", Size: 1},
		{Name: wantName, Sha256: "bbb", Size: 2},
	}}
	pkg, ok := packageForPlatform(m)
	if !ok || pkg.Name != wantName || pkg.Sha256 != "bbb" {
		t.Fatalf("packageForPlatform 选错包: %+v, ok=%v", pkg, ok)
	}
	m.Packages = m.Packages[:1]
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		if _, ok := packageForPlatform(m); ok {
			t.Fatal("不匹配的平台包不应被选中")
		}
	}
}

func TestAtomicReplaceBinary(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "npc_gui")
	src := filepath.Join(dir, "new_binary")
	if err := os.WriteFile(dst, []byte("OLD-BINARY"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("NEW-BINARY"), 0755); err != nil {
		t.Fatal(err)
	}
	backup, err := atomicReplaceBinary(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if backup == "" {
		t.Fatal("旧二进制应被备份")
	}
	if data, _ := os.ReadFile(dst); string(data) != "NEW-BINARY" {
		t.Fatalf("替换后内容不对: %q", data)
	}
	if data, _ := os.ReadFile(backup); string(data) != "OLD-BINARY" {
		t.Fatalf("备份内容不对: %q", data)
	}
	matches, _ := filepath.Glob(dst + ".new.*")
	if len(matches) != 0 {
		t.Fatalf("临时文件未清理: %v", matches)
	}
	// 目标原本不存在时不应产生空备份
	dst2 := filepath.Join(dir, "fresh")
	backup2, err := atomicReplaceBinary(src, dst2)
	if err != nil {
		t.Fatal(err)
	}
	if backup2 != "" {
		t.Fatalf("无旧文件时不应返回备份路径: %s", backup2)
	}
}

func TestExtractGUIBinary(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "npc_gui_test.tar.gz")
	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	// 路径穿越 / 非目标文件必须被忽略
	for _, item := range []struct{ name, body string }{
		{"../../evil.sh", "rm -rf /"},
		{"README.md", "docs"},
		{"./npc_gui", "FAKE-GUI-BINARY"},
	} {
		data := []byte(item.body)
		hdr := &tar.Header{Name: item.name, Mode: 0755, Size: int64(len(data)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	bin, err := extractGUIBinary(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(filepath.Dir(bin))
	if data, _ := os.ReadFile(bin); string(data) != "FAKE-GUI-BINARY" {
		t.Fatalf("解出的二进制内容不对: %q", data)
	}
	if filepath.Base(bin) != "npc_gui" {
		t.Fatalf("解出的文件名不对: %s", bin)
	}
	// 解包只在临时目录里落地，不能写到 tar 里的相对路径
	if _, err := os.Stat(filepath.Join(dir, "evil.sh")); !os.IsNotExist(err) {
		t.Fatal("路径穿越文件被写出了")
	}
}
