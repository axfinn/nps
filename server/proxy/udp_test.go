package proxy

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/file"
)

// TestMain points the lazy file DB at an isolated temp conf dir. IsGlobalBlackIp
// calls file.GetDb(), which panics when conf/clients.json is missing, so seed the
// files it insists on reading ("global.json" may be absent - GetGlobal returns
// nil and the global blacklist is treated as empty).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "nps-proxy-test")
	if err != nil {
		panic(err)
	}
	confDir := filepath.Join(dir, "conf")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		panic(err)
	}
	for _, name := range []string{"clients.json", "tasks.json", "hosts.json"} {
		if err := os.WriteFile(filepath.Join(confDir, name), nil, 0o644); err != nil {
			panic(err)
		}
	}
	common.ConfPath = dir

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// freeUDPPort reserves an ephemeral UDP port and releases it so the server under
// test can bind it.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// TestUdpBlacklistedPacketDoesNotStopService is a regression test for the
// original `break` in the blacklist branch of Start(). A single UDP packet from
// a blacklisted IP used to break out of the accept loop and permanently stop the
// whole UDP tunnel - a one-packet remote DoS. After the fix (`continue`) the
// accept loop keeps running.
//
// The only observable used is whether Start() returns: `break` makes it return
// right after the blocked packet, `continue` keeps it parked in ReadFromUDP.
func TestUdpBlacklistedPacketDoesNotStopService(t *testing.T) {
	port := freeUDPPort(t)
	task := &file.Tunnel{
		Id:       1,
		Mode:     "udp",
		Port:     port,
		ServerIp: "127.0.0.1",
		Target:   &file.Target{TargetStr: "127.0.0.1:9"},
		Client: &file.Client{
			Id:          1,
			BlackIpList: []string{"127.0.0.1"}, // every local packet is blocked
			Cnf:         &file.Config{},
			Flow:        new(file.Flow),
		},
	}

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Close()
	server := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}

	// A nil bridge is safe here: blacklisted packets are dropped before ever
	// reaching bridge.SendLinkInfo.
	s := NewUdpModeServer(nil, task)
	done := make(chan error, 1)
	go func() { done <- s.Start() }()

	// Feed blacklisted packets while the listener may still be binding. With the
	// bug the very first packet read makes Start() return, so done fires.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("accept loop exited on a blacklisted packet (regression: break instead of continue): %v", err)
		default:
		}
		if _, err := client.WriteToUDP([]byte("blocked"), server); err != nil {
			t.Fatalf("send blacklisted packet: %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Give any in-flight packet time to be consumed, then confirm the loop is
	// still parked in ReadFromUDP rather than having returned.
	select {
	case err := <-done:
		t.Fatalf("accept loop exited on a blacklisted packet (regression: break instead of continue): %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	// Intentionally no s.Close(): Start owns the listener and reading s.listener
	// from here would race with Start's assignment. The goroutine stays parked
	// until the test binary exits.
}
