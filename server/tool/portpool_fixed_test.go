package tool

import (
	"testing"

	"ehang.io/nps/lib/file"
)

// fixedPortStore is a tiny in-memory tasks table: ownership checks must not
// depend on conf/tasks.json or on any global database state.
type fixedPortStore struct {
	tasks map[int]*file.Tunnel
}

func (s *fixedPortStore) RangeUsers(func(*file.User) bool) {}
func (s *fixedPortStore) RangeTasks(f func(*file.Tunnel) bool) {
	for _, t := range s.tasks {
		if !f(t) {
			return
		}
	}
}
func (s *fixedPortStore) GetTask(id int) (*file.Tunnel, bool) {
	t, ok := s.tasks[id]
	return t, ok
}

func TestIsFixedPortAllowedOwnership(t *testing.T) {
	pool := file.GetPortPool()
	pool.SetStore(&fixedPortStore{tasks: map[int]*file.Tunnel{
		1: {Id: 1, Port: 50003, PortPool: file.PortFromFixed, Status: false,
			Client: &file.Client{Id: 42}},
		2: {Id: 2, Port: 50007, PortPool: file.PortFromShared, Status: true,
			Client: &file.Client{Id: 42}},
	}})
	defer pool.SetStore(nil)

	super := &file.User{Role: file.RoleSuperAdmin}
	owner := &file.User{Id: 5, Role: file.RoleUser, ClientIds: []int{42}, AllowPorts: "40000-40099"}
	stranger := &file.User{Id: 6, Role: file.RoleUser, ClientIds: []int{99}, AllowPorts: "40100-40199"}

	if !IsFixedPortAllowed(50003, super, nil) {
		t.Fatal("a super admin must be allowed to use a pinned port")
	}
	if !IsFixedPortAllowed(50003, owner, nil) {
		t.Fatal("the owner of the pinned tunnel must be allowed to keep its port")
	}
	if IsFixedPortAllowed(50003, stranger, nil) {
		t.Fatal("another user must not be able to type somebody else's pinned port")
	}
	if IsFixedPortAllowed(50007, owner, nil) {
		t.Fatal("a temporary shared port is not a fixed port")
	}
	if IsFixedPortAllowed(50004, owner, nil) {
		t.Fatal("an unallocated shared port must not be whitelisted")
	}
	if IsFixedPortAllowed(40003, owner, nil) {
		t.Fatal("a user-block port is not a pinned shared port")
	}
}

func TestAllowedPortsExcludesSharedRange(t *testing.T) {
	owner := &file.User{Id: 5, Role: file.RoleUser, AllowPorts: "40000-40099"}
	allowed, restricted := AllowedPorts(owner, nil)
	if !restricted || len(allowed) != 100 {
		t.Fatalf("AllowedPorts = %d ports, restricted=%t; want 100, true", len(allowed), restricted)
	}
	// A pinned shared port is outside the exclusive block, which is exactly
	// why TestServerPort needs the ownership-aware fixed-port bypass.
	for _, p := range allowed {
		if p == 50003 {
			t.Fatal("the exclusive block must not contain shared pool ports")
		}
	}
}
