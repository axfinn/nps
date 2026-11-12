package file

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"ehang.io/nps/lib/common"
)

// memPortStore is an in-memory replacement for the JSON tables so the pool
// tests never read or write conf/*.json.
type memPortStore struct {
	users sync.Map
	tasks sync.Map
}

func newMemPortStore() *memPortStore { return &memPortStore{} }

func (m *memPortStore) RangeUsers(f func(*User) bool) {
	m.users.Range(func(_, v interface{}) bool { return f(v.(*User)) })
}

func (m *memPortStore) RangeTasks(f func(*Tunnel) bool) {
	m.tasks.Range(func(_, v interface{}) bool { return f(v.(*Tunnel)) })
}

func (m *memPortStore) GetTask(id int) (*Tunnel, bool) {
	v, ok := m.tasks.Load(id)
	if !ok {
		return nil, false
	}
	return v.(*Tunnel), true
}

func (m *memPortStore) addUser(u *User)   { m.users.Store(u.Id, u) }
func (m *memPortStore) addTask(t *Tunnel) { m.tasks.Store(t.Id, t) }

func testPoolConfig() PortPoolConfig {
	return PortPoolConfig{
		Enabled:     true,
		UserStart:   40000,
		UserEnd:     40999,
		UserQuota:   100,
		SharedStart: 50000,
		SharedEnd:   50009,
	}
}

func newTestAllocator(t *testing.T, cfg PortPoolConfig) (*PortAllocator, *memPortStore) {
	t.Helper()
	a := newPortAllocator()
	store := newMemPortStore()
	a.SetStore(store)
	a.SetPortProbe(func(int, string) bool { return true })
	a.Configure(cfg)
	return a, store
}

// Simulate a reboot: in-flight state is gone, only users.json / tasks.json
// remain. The allocator must rebuild the same picture from those tables.
func simulateReboot(a *PortAllocator) {
	a.mu.Lock()
	a.blocks = make(map[int]time.Time)
	a.leases = make(map[int]*sharedLease)
	a.mu.Unlock()
}

func TestAssignUserBlockConsecutive(t *testing.T) {
	a, store := newTestAllocator(t, testPoolConfig())
	want := []string{"40000-40099", "40100-40199", "40200-40299"}
	for i, w := range want {
		u := &User{Id: i + 1, Username: "user", Role: RoleUser}
		got, err := a.AssignUserBlock(u)
		if err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
		if got != w || u.AllowPorts != w {
			t.Fatalf("block %d: got %q / %q, want %q", i, got, u.AllowPorts, w)
		}
		store.addUser(u)
	}

	admin := &User{Id: 90, Username: "admin", Role: RoleSuperAdmin}
	if got, _ := a.AssignUserBlock(admin); got != "" || admin.AllowPorts != "" {
		t.Fatal("super admin must not receive an exclusive block")
	}
	fixed := &User{Id: 91, Username: "fixed", Role: RoleUser, AllowPorts: "9001-9009"}
	if got, _ := a.AssignUserBlock(fixed); got != "" || fixed.AllowPorts != "9001-9009" {
		t.Fatal("an explicitly configured range must be preserved")
	}
}

func TestAssignUserBlockSurvivesRebootAndSkipsUsedBlock(t *testing.T) {
	a, store := newTestAllocator(t, testPoolConfig())
	u1 := &User{Id: 1, Role: RoleUser}
	_, _ = a.AssignUserBlock(u1)
	store.addUser(u1)
	u2 := &User{Id: 2, Role: RoleUser}
	_, _ = a.AssignUserBlock(u2)
	store.addUser(u2)

	// User 1 is deleted, but one of its tunnels still occupies port 40000.
	store.users.Delete(1)
	store.addTask(&Tunnel{Id: 100, Port: 40000, Status: true})
	simulateReboot(a)

	u3 := &User{Id: 3, Role: RoleUser}
	got, err := a.AssignUserBlock(u3)
	if err != nil {
		t.Fatal(err)
	}
	if got != "40200-40299" {
		t.Fatalf("expected block 2, got %q (block 0 is still used by a tunnel, block 1 by user 2)", got)
	}
}

func TestAssignUserBlockExhausted(t *testing.T) {
	cfg := testPoolConfig()
	cfg.UserEnd = 40199 // exactly two blocks
	a, store := newTestAllocator(t, cfg)
	for i := 1; i <= 2; i++ {
		u := &User{Id: i, Role: RoleUser}
		if _, err := a.AssignUserBlock(u); err != nil {
			t.Fatal(err)
		}
		store.addUser(u)
	}
	if _, err := a.AssignUserBlock(&User{Id: 3, Role: RoleUser}); err == nil {
		t.Fatal("expected the exclusive range to be exhausted")
	}
}

func TestAllocateSharedNoDuplicateAndExhausted(t *testing.T) {
	cfg := testPoolConfig()
	cfg.SharedEnd = 50004 // five ports
	a, store := newTestAllocator(t, cfg)
	seen := make(map[int]bool)
	for id := 1; id <= 5; id++ {
		port, err := a.AllocateShared("tcp", id, 1)
		if err != nil {
			t.Fatalf("allocation %d: %v", id, err)
		}
		if port < 50000 || port > 50004 || seen[port] {
			t.Fatalf("invalid or duplicated port %d", port)
		}
		seen[port] = true
		store.addTask(&Tunnel{Id: id, Port: port, PortPool: PortFromShared, Status: true})
		a.CommitShared(id)
	}
	if _, err := a.AllocateShared("tcp", 6, 1); err == nil {
		t.Fatal("expected the shared pool to be exhausted")
	}
}

func TestSharedPortReturnedWhenTunnelStopped(t *testing.T) {
	cfg := testPoolConfig()
	cfg.SharedEnd = 50000 // a single shared port
	a, store := newTestAllocator(t, cfg)
	port, err := a.AllocateShared("tcp", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	task := &Tunnel{Id: 1, Port: port, PortPool: PortFromShared, Status: true}
	store.addTask(task)
	a.CommitShared(1)

	if _, err := a.AllocateShared("tcp", 2, 2); err == nil {
		t.Fatal("running tunnel must keep its shared port")
	}

	// Stop + explicit recycle (StopServer path).
	task.Status = false
	if got := a.ReleaseShared(1); got != port {
		t.Fatalf("ReleaseShared returned %d, want %d", got, port)
	}
	again, err := a.AllocateShared("tcp", 2, 2)
	if err != nil || again != port {
		t.Fatalf("stopped tunnel did not return its port: got %d, err %v", again, err)
	}
}

func TestSharedPortReturnedWhenTunnelDeleted(t *testing.T) {
	cfg := testPoolConfig()
	cfg.SharedEnd = 50000
	a, store := newTestAllocator(t, cfg)
	port, err := a.AllocateShared("tcp", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	store.addTask(&Tunnel{Id: 1, Port: port, PortPool: PortFromShared, Status: true})
	a.CommitShared(1)

	store.tasks.Delete(1) // DelTask path
	a.ReleaseShared(1)
	again, err := a.AllocateShared("tcp", 2, 2)
	if err != nil || again != port {
		t.Fatalf("deleted tunnel did not return its port: got %d, err %v", again, err)
	}
}

func TestSharedPortRebootReconciliation(t *testing.T) {
	cfg := testPoolConfig()
	cfg.SharedEnd = 50000
	a, store := newTestAllocator(t, cfg)
	port, err := a.AllocateShared("tcp", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	store.addTask(&Tunnel{Id: 1, Port: port, PortPool: PortFromShared, Status: true})
	a.CommitShared(1)

	// Reboot drops all in-memory leases; the tasks.json record alone must
	// still protect the rented port.
	simulateReboot(a)
	if !a.IsSharedLeased(port) {
		t.Fatal("shared lease was not rebuilt from the tasks table")
	}
	if _, err := a.AllocateShared("tcp", 2, 2); err == nil {
		t.Fatal("port was handed out twice after reboot")
	}
}

func TestIsSharedLeasedRejectsManualPorts(t *testing.T) {
	a, store := newTestAllocator(t, testPoolConfig())
	if a.IsSharedLeased(50001) {
		t.Fatal("an unused shared-range port must not be treated as leased")
	}
	// A manually pinned shared port (no PortPool marker) is never leased.
	store.addTask(&Tunnel{Id: 7, Port: 50001, Status: true})
	if a.IsSharedLeased(50001) {
		t.Fatal("a manually pinned port must not bypass the user whitelist")
	}
	port, _ := a.AllocateShared("tcp", 8, 1)
	if !a.IsSharedLeased(port) {
		t.Fatal("in-flight lease must be recognised")
	}
	store.addTask(&Tunnel{Id: 8, Port: port, PortPool: PortFromShared, Status: true})
	a.CommitShared(8)
	if !a.IsSharedLeased(port) {
		t.Fatal("committed shared tunnel must be recognised")
	}
	if !a.IsSharedPortForTask(8) || a.IsSharedPortForTask(7) {
		t.Fatal("IsSharedPortForTask misclassified a tunnel")
	}
}

func TestPickFromAllowedSkipsBusyPorts(t *testing.T) {
	a, store := newTestAllocator(t, testPoolConfig())
	allowed := common.GetPorts("40000-40002")
	store.addTask(&Tunnel{Id: 1, Port: 40000, Status: true})
	for i := 0; i < 20; i++ {
		port, ok := a.PickFromAllowed(allowed, "tcp")
		if !ok {
			t.Fatal("expected a free port in the exclusive block")
		}
		if port == 40000 || port < 40000 || port > 40002 {
			t.Fatalf("picked invalid/busy port %d", port)
		}
	}
}

func TestSystemPortsAreNeverAllocated(t *testing.T) {
	cfg := testPoolConfig()
	cfg.SharedEnd = 50002
	cfg.SystemPorts = []int{50000, 50001}
	a, _ := newTestAllocator(t, cfg)
	for i := 1; i <= 3; i++ {
		port, err := a.AllocateShared("tcp", i, 1)
		if err != nil {
			t.Fatal(err)
		}
		if port != 50002 {
			t.Fatalf("system port was allocated: %d", port)
		}
		a.AbortShared(i)
	}
}

func TestConfigureKeepsRangesDisjoint(t *testing.T) {
	cfg := testPoolConfig()
	cfg.SharedStart = 40500 // deliberately overlapping the user range
	cfg.SharedEnd = 40600
	a, _ := newTestAllocator(t, cfg)
	got := a.Config()
	if got.SharedStart != got.UserEnd+1 {
		t.Fatalf("shared range starts at %d, want %d", got.SharedStart, got.UserEnd+1)
	}
}

func TestConcurrentAllocationNeverDuplicates(t *testing.T) {
	cfg := testPoolConfig()
	cfg.SharedEnd = 50019 // 20 ports, 20 concurrent requests
	a, _ := newTestAllocator(t, cfg)
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[int]bool)
	var failures int
	for id := 1; id <= 20; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			port, err := a.AllocateShared("tcp", id, 1)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures++
				return
			}
			if seen[port] {
				t.Errorf("port %d was allocated twice", port)
			}
			seen[port] = true
		}(id)
	}
	wg.Wait()
	if failures != 0 || len(seen) != 20 {
		t.Fatalf("failures=%d unique=%d, want 0/20", failures, len(seen))
	}
}

func TestLeaseAbortAndStats(t *testing.T) {
	a, store := newTestAllocator(t, testPoolConfig())
	port, _ := a.AllocateShared("tcp", 1, 1)
	a.AbortShared(1) // creation failed
	store.addUser(&User{Id: 1, Role: RoleUser, AllowPorts: "40000-40099"})
	stats := a.Stats()
	if !stats.Enabled || stats.UserBlocksTotal != 10 || stats.UserBlocksUsed != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if stats.SharedTotal != 10 || stats.SharedUsed != 0 {
		t.Fatalf("aborted lease still counted as used: %+v", stats)
	}
	if a.IsSharedLeased(port) {
		t.Fatal("aborted lease must not survive")
	}
}

func TestGlobalAllowPortsIsHardCeiling(t *testing.T) {
	cfg := testPoolConfig()
	cfg.SharedEnd = 50004
	cfg.GlobalPorts = common.GetPorts("50002-50003,9999")
	a, _ := newTestAllocator(t, cfg)
	for id := 1; id <= 2; id++ {
		port, err := a.AllocateShared("tcp", id, 1)
		if err != nil {
			t.Fatal(err)
		}
		if port != 50002 && port != 50003 {
			t.Fatalf("port %d escapes the global allow_ports whitelist", port)
		}
	}
	if _, err := a.AllocateShared("tcp", 3, 1); err == nil {
		t.Fatal("whitelist intersection should be exhausted")
	}
	if a.Stats().SharedTotal != 2 {
		t.Fatal("stats must report the whitelist intersection, not the full range")
	}

	empty := testPoolConfig()
	empty.GlobalPorts = common.GetPorts("9001-9009")
	b, _ := newTestAllocator(t, empty)
	if _, err := b.AllocateShared("tcp", 1, 1); err == nil {
		t.Fatal("a non-overlapping global whitelist must disable shared allocation")
	}
}

func TestHoldSharedProtectsEditRestartWindow(t *testing.T) {
	cfg := testPoolConfig()
	cfg.SharedEnd = 50000 // single shared port
	a, store := newTestAllocator(t, cfg)
	port, _ := a.AllocateShared("tcp", 1, 1)
	task := &Tunnel{Id: 1, Port: port, PortPool: PortFromShared, Status: true}
	store.addTask(task)
	a.CommitShared(1)

	// Editing stops the service (port returns to the pool) and immediately
	// holds it again until the tunnel is running.
	task.Status = false
	a.ReleaseShared(1)
	a.HoldShared(1, port, 1)
	if _, err := a.AllocateShared("tcp", 2, 2); err == nil {
		t.Fatal("a held port must not be handed to another request")
	}

	a.CommitShared(1)
	task.Status = true // tunnel is running again, tasks table owns the port
	if _, err := a.AllocateShared("tcp", 2, 2); err == nil {
		t.Fatal("a running tunnel must keep its shared port")
	}
}

func TestLegacyTaskJsonHasNoPortPool(t *testing.T) {
	var task Tunnel
	if err := json.Unmarshal([]byte(`{"Id":1,"Port":8080,"Status":true,"Mode":"tcp"}`), &task); err != nil {
		t.Fatal(err)
	}
	if task.PortPool != "" {
		t.Fatalf("legacy tasks.json must decode PortPool as empty, got %q", task.PortPool)
	}
}

func TestPinSharedKeepsPortForever(t *testing.T) {
	cfg := testPoolConfig()
	cfg.SharedEnd = 50000 // single shared port makes collisions obvious
	a, store := newTestAllocator(t, cfg)
	port, err := a.AllocateShared("tcp", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	task := &Tunnel{Id: 1, Port: port, PortPool: PortFromShared, Status: true,
		Client: &Client{Id: 7}}
	store.addTask(task)
	a.CommitShared(1)

	if got, err := a.PinShared(1); err != nil || got != port {
		t.Fatalf("PinShared = %d, %v; want %d", got, err, port)
	}
	if task.PortPool != PortFromFixed {
		t.Fatal("PinShared must flip the live tunnel flag so UpdateTask persists it")
	}
	if a.IsSharedPortForTask(1) {
		t.Fatal("a fixed port must never be reallocated on restart")
	}

	// Stopping / client offline sets Status=false. A temporary lease would be
	// returned here; a fixed one must stay reserved for its owner.
	task.Status = false
	if got := a.ReleaseShared(1); got != 0 {
		t.Fatalf("ReleaseShared returned %d for a fixed port, want 0", got)
	}
	if _, err := a.AllocateShared("tcp", 2, 2); err == nil {
		t.Fatal("a stopped fixed tunnel must keep its port out of the shared pool")
	}
	if a.Stats().FixedUsed != 1 {
		t.Fatal("stats must count the pinned port")
	}

	// Reboot: leases are gone, only tasks.json remains. The fixed flag must
	// rebuild the reservation without any extra state file.
	simulateReboot(a)
	if !a.BlockedPorts()[port] {
		t.Fatal("fixed port reservation must survive a reboot")
	}
	task.Status = true
	if _, err := a.AllocateShared("tcp", 3, 3); err == nil {
		t.Fatal("a running fixed tunnel must keep its port after reboot")
	}
}

func TestUnpinSharedReturnsToTemporary(t *testing.T) {
	cfg := testPoolConfig()
	cfg.SharedEnd = 50000
	a, store := newTestAllocator(t, cfg)
	port, _ := a.AllocateShared("tcp", 1, 1)
	task := &Tunnel{Id: 1, Port: port, PortPool: PortFromShared, Status: true}
	store.addTask(task)
	a.CommitShared(1)
	if _, err := a.PinShared(1); err != nil {
		t.Fatal(err)
	}
	if got, err := a.UnpinShared(1); err != nil || got != port {
		t.Fatalf("UnpinShared = %d, %v; want %d", got, err, port)
	}
	if !a.IsSharedPortForTask(1) {
		t.Fatal("unpinning must restore the temporary lease semantics")
	}
	if a.Stats().FixedUsed != 0 {
		t.Fatal("stats must no longer count an unpinned port")
	}
	// A stopped temporary tunnel returns its port immediately.
	task.Status = false
	if got := a.ReleaseShared(1); got != port {
		t.Fatalf("ReleaseShared = %d, want %d", got, port)
	}
	if _, err := a.AllocateShared("tcp", 2, 2); err != nil {
		t.Fatal("an unpinned port must be rentable again:", err)
	}
	if _, err := a.UnpinShared(1); err == nil {
		t.Fatal("unpinning a temporary tunnel must fail")
	}
}

func TestPinSharedRejectsConflicts(t *testing.T) {
	cfg := testPoolConfig()
	cfg.SharedEnd = 50000
	b, store2 := newTestAllocator(t, cfg)
	single, _ := b.AllocateShared("tcp", 1, 1)
	t2 := &Tunnel{Id: 1, Port: single, PortPool: PortFromShared, Status: true}
	store2.addTask(t2)
	b.CommitShared(1)
	// Simulate a stopped tunnel whose number is being rented by somebody else.
	t2.Status = false
	if _, err := b.AllocateShared("tcp", 9, 9); err != nil {
		t.Fatal(err)
	}
	if _, err := b.PinShared(1); err == nil {
		t.Fatal("pinning must be refused while another task rents the same port")
	}

	// A running tunnel on the same number is a hard conflict too.
	c, store3 := newTestAllocator(t, cfg)
	store3.addTask(&Tunnel{Id: 1, Port: 50000, PortPool: PortFromShared, Status: false})
	store3.addTask(&Tunnel{Id: 2, Port: 50000, PortPool: PortFromFixed, Status: true})
	if _, err := c.PinShared(1); err == nil {
		t.Fatal("pinning must be refused when another fixed tunnel owns the port")
	}
}

func TestPinSharedValidationAndIdempotency(t *testing.T) {
	a, store := newTestAllocator(t, testPoolConfig())
	if _, err := a.PinShared(404); err == nil {
		t.Fatal("pinning a missing tunnel must fail")
	}
	store.addTask(&Tunnel{Id: 1, Port: 40001, PortPool: PortFromShared, Status: true})
	if _, err := a.PinShared(1); err == nil {
		t.Fatal("only shared-range ports can be pinned")
	}
	port, _ := a.AllocateShared("tcp", 2, 2)
	store.addTask(&Tunnel{Id: 2, Port: port, PortPool: PortFromShared, Status: true})
	if got, err := a.PinShared(2); err != nil || got != port {
		t.Fatalf("PinShared = %d, %v", got, err)
	}
	if got, err := a.PinShared(2); err != nil || got != port {
		t.Fatalf("PinShared must be idempotent, got %d, %v", got, err)
	}
}

func TestLegacyStoppedTunnelPortNeverReallocated(t *testing.T) {
	cfg := testPoolConfig()
	cfg.SharedEnd = 50000 // a single shared port makes collisions obvious
	a, store := newTestAllocator(t, cfg)

	// All three are legacy records: no PortPool field in tasks.json.
	store.addTask(&Tunnel{Id: 1, Port: 50000, Status: false}) // stopped, in shared range
	store.addTask(&Tunnel{Id: 2, Port: 40022, Status: true})  // running, in user range
	store.addTask(&Tunnel{Id: 3, Port: 40080, Status: false}) // stopped, in user range

	if _, err := a.AllocateShared("tcp", 10, 10); err == nil {
		t.Fatal("a stopped legacy tunnel must keep its port out of the shared pool")
	}
	// A stopped legacy port is protected even if an admin later types the
	// whole block into a user's AllowPorts.
	if port, ok := a.PickFromAllowed([]int{40022, 40080, 40100}, "tcp"); !ok || port != 40100 {
		t.Fatalf("PickFromAllowed = %d, %t; want 40100, true", port, ok)
	}
	// A stopped *temporary* tunnel still returns its port - upgrading must
	// not change the recycling behaviour of the pool itself.
	b, store2 := newTestAllocator(t, testPoolConfig())
	p, err := b.AllocateShared("tcp", 11, 11)
	if err != nil {
		t.Fatal(err)
	}
	store2.addTask(&Tunnel{Id: 11, Port: p, PortPool: PortFromShared, Status: false})
	b.CommitShared(11)
	got, err := b.AllocateShared("tcp", 12, 12, p)
	if err != nil || got == p {
		t.Fatalf("a stopped shared tunnel must still release its port, got %d, %v", got, err)
	}
}

func TestFixedPortClientAndJsonRoundTrip(t *testing.T) {
	a, store := newTestAllocator(t, testPoolConfig())
	task := &Tunnel{Id: 1, Port: 50003, PortPool: PortFromFixed, Status: false,
		Client: &Client{Id: 42}}
	store.addTask(task)
	if cid, ok := a.FixedPortClient(50003); !ok || cid != 42 {
		t.Fatalf("FixedPortClient = %d, %t; want 42, true", cid, ok)
	}
	if _, ok := a.FixedPortClient(50004); ok {
		t.Fatal("an unpinned port must not report an owner")
	}
	if _, ok := a.FixedPortClient(40003); ok {
		t.Fatal("a user-block port is not a pinned shared port")
	}
	b, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Tunnel
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.PortPool != PortFromFixed || decoded.Port != 50003 {
		t.Fatal("fixed flag must round-trip through tasks.json")
	}
}
