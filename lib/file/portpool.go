package file

import (
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	"ehang.io/nps/lib/common"
	"github.com/astaxie/beego/logs"
)

// PortFromShared marks a tunnel whose server port is rented from the shared
// pool. Such ports are given back automatically when the tunnel is stopped,
// deleted, or its client disconnects.
//
// PortFromFixed marks a shared port that the operator converted into a
// permanent fixed port. It keeps the same number forever: stopping,
// restarting, or taking the client offline never returns it to the pool, and
// the allocator never hands it to another tunnel. UnpinShared turns it back
// into a temporary lease. The flag lives on the tunnel itself, so no extra
// state file is needed and a reboot rebuilds it from tasks.json.
const (
	PortFromShared = "shared"
	PortFromFixed  = "fixed"
)

const (
	userBlockTTL   = 2 * time.Minute
	sharedLeaseTTL = 5 * time.Minute
)

// PortPoolConfig describes the two disjoint port ranges.
//   - [UserStart, UserEnd] is cut into UserQuota-sized blocks, one block per
//     newly created normal user, stored in User.AllowPorts (persistent and
//     exclusive, never recycled while in use).
//   - [SharedStart, SharedEnd] is a shared library: ports are handed out at
//     random and returned as soon as the tunnel stops using them.
type PortPoolConfig struct {
	Enabled     bool
	UserStart   int
	UserEnd     int
	UserQuota   int
	SharedStart int
	SharedEnd   int
	SystemPorts []int // web / bridge / http(s) proxy / p2p / pprof, never allocatable
	// GlobalPorts is the global allow_ports whitelist. When non-empty it stays
	// a hard ceiling: shared ports outside it are never handed out.
	GlobalPorts []int
}

func DefaultPortPoolConfig() PortPoolConfig {
	return PortPoolConfig{
		Enabled:     true,
		UserStart:   40000,
		UserEnd:     49999,
		UserQuota:   100,
		SharedStart: 50000,
		SharedEnd:   60000,
	}
}

func normalizePortPoolConfig(cfg PortPoolConfig) PortPoolConfig {
	d := DefaultPortPoolConfig()
	if cfg.UserQuota <= 0 {
		cfg.UserQuota = d.UserQuota
	}
	if cfg.UserStart < 1024 || cfg.UserStart > 65535 {
		cfg.UserStart = d.UserStart
	}
	if cfg.UserEnd < cfg.UserStart || cfg.UserEnd > 65535 {
		cfg.UserEnd = d.UserEnd
	}
	if cfg.SharedStart < 1024 || cfg.SharedStart > 65535 {
		cfg.SharedStart = d.SharedStart
	}
	if cfg.SharedEnd < cfg.SharedStart || cfg.SharedEnd > 65535 {
		cfg.SharedEnd = d.SharedEnd
	}
	// The two ranges must never overlap, otherwise a user's exclusive block
	// could be handed out as a shared port.
	if cfg.SharedStart <= cfg.UserEnd {
		cfg.SharedStart = cfg.UserEnd + 1
	}
	if cfg.SharedEnd < cfg.SharedStart {
		cfg.SharedEnd = d.SharedEnd
	}
	if cfg.UserEnd < cfg.UserStart {
		cfg.UserStart, cfg.UserEnd, cfg.SharedStart, cfg.SharedEnd = d.UserStart, d.UserEnd, d.SharedStart, d.SharedEnd
	}
	cfg.SystemPorts = append([]int(nil), cfg.SystemPorts...)
	cfg.GlobalPorts = append([]int(nil), cfg.GlobalPorts...)
	return cfg
}

// PortPoolStats is what the web UI shows on the user management page.
type PortPoolStats struct {
	Enabled          bool
	UserStart        int
	UserEnd          int
	UserQuota        int
	UserBlocksTotal  int
	UserBlocksUsed   int
	SharedStart      int
	SharedEnd        int
	SharedTotal      int
	SharedUsed       int
	SharedPortReport string
	FixedUsed        int // shared ports converted into permanent fixed ports
}

type sharedLease struct {
	port    int
	taskId  int
	userId  int
	created time.Time
}

// PortPoolStore keeps the allocator independent from the on-disk database.
// The default implementation reads the live sync.Map tables; tests inject an
// in-memory store so no conf/*.json files are touched.
type PortPoolStore interface {
	RangeUsers(func(*User) bool)
	RangeTasks(func(*Tunnel) bool)
	GetTask(int) (*Tunnel, bool)
}

type dbPortPoolStore struct{}

func (dbPortPoolStore) RangeUsers(f func(*User) bool) {
	GetDb().JsonDb.Users.Range(func(_, v interface{}) bool { return f(v.(*User)) })
}

func (dbPortPoolStore) RangeTasks(f func(*Tunnel) bool) {
	GetDb().JsonDb.Tasks.Range(func(_, v interface{}) bool { return f(v.(*Tunnel)) })
}

func (dbPortPoolStore) GetTask(id int) (*Tunnel, bool) {
	v, ok := GetDb().JsonDb.Tasks.Load(id)
	if !ok {
		return nil, false
	}
	return v.(*Tunnel), true
}

// PortAllocator is the single source of truth for automatic port assignment.
// There is deliberately no extra state file: exclusive blocks live in
// User.AllowPorts and shared leases live in Tunnel.PortPool/Port/Status, both
// already persisted. Rebooting rebuilds the whole picture from those tables,
// so the pool can never drift out of sync with the tunnels.
type PortAllocator struct {
	mu     sync.Mutex
	cfg    PortPoolConfig
	store  PortPoolStore
	probe  func(port int, mode string) bool
	leases map[int]*sharedLease // taskId -> in-flight lease (not yet in Tasks)
	blocks map[int]time.Time    // block index -> time it was handed out
}

var portPool = newPortAllocator()

func newPortAllocator() *PortAllocator {
	return &PortAllocator{
		cfg:    DefaultPortPoolConfig(),
		store:  dbPortPoolStore{},
		probe:  defaultPortProbe,
		leases: make(map[int]*sharedLease),
		blocks: make(map[int]time.Time),
	}
}

func GetPortPool() *PortAllocator { return portPool }

func defaultPortProbe(port int, mode string) bool {
	if mode == "udp" {
		return common.TestUdpPort(port)
	}
	return common.TestTcpPort(port)
}

// SetPortProbe replaces the physical bind probe. Production uses real
// listen-and-close checks; tests inject a deterministic stub.
func (p *PortAllocator) SetPortProbe(fn func(port int, mode string) bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if fn == nil {
		fn = defaultPortProbe
	}
	p.probe = fn
}

// SetStore replaces the backing tables (used by unit tests).
func (p *PortAllocator) SetStore(store PortPoolStore) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if store == nil {
		store = dbPortPoolStore{}
	}
	p.store = store
}

func (p *PortAllocator) Configure(cfg PortPoolConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = normalizePortPoolConfig(cfg)
	logs.Info("[portpool] configured: user=%d-%d block=%d, shared=%d-%d, enabled=%t",
		p.cfg.UserStart, p.cfg.UserEnd, p.cfg.UserQuota, p.cfg.SharedStart, p.cfg.SharedEnd, p.cfg.Enabled)
}

func (p *PortAllocator) Config() PortPoolConfig {
	p.mu.Lock()
	defer p.mu.Unlock()
	cfg := p.cfg
	cfg.SystemPorts = append([]int(nil), p.cfg.SystemPorts...)
	cfg.GlobalPorts = append([]int(nil), p.cfg.GlobalPorts...)
	return cfg
}

func (p *PortAllocator) Enabled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg.Enabled
}

func (p *PortAllocator) InSharedRange(port int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inSharedRangeLocked(port)
}

func (p *PortAllocator) inSharedRangeLocked(port int) bool {
	return port >= p.cfg.SharedStart && port <= p.cfg.SharedEnd
}

func (p *PortAllocator) inUserRangeLocked(port int) bool {
	return port >= p.cfg.UserStart && port <= p.cfg.UserEnd
}

func (p *PortAllocator) userBlockIndexLocked(port int) int {
	return (port - p.cfg.UserStart) / p.cfg.UserQuota
}

func (p *PortAllocator) sweepLocked() {
	now := time.Now()
	for id, l := range p.leases {
		if now.Sub(l.created) > sharedLeaseTTL {
			delete(p.leases, id)
		}
	}
	for idx, t := range p.blocks {
		if now.Sub(t) > userBlockTTL {
			delete(p.blocks, idx)
		}
	}
}

// usedUserBlockSetLocked finds every block that must not be handed out again:
// referenced by an existing user, still used by a tunnel, or just handed to a
// concurrent user creation that has not been persisted yet. Scanning the
// tasks table means deleting a user never recycles a block that is still in
// use by a leftover tunnel.
func (p *PortAllocator) usedUserBlockSetLocked() map[int]bool {
	used := make(map[int]bool)
	for idx, t := range p.blocks {
		if time.Since(t) <= userBlockTTL {
			used[idx] = true
		}
	}
	p.store.RangeUsers(func(u *User) bool {
		if u == nil {
			return true
		}
		for _, port := range common.GetPorts(u.AllowPorts) {
			if p.inUserRangeLocked(port) {
				used[p.userBlockIndexLocked(port)] = true
			}
		}
		return true
	})
	p.store.RangeTasks(func(t *Tunnel) bool {
		if t != nil && p.inUserRangeLocked(t.Port) {
			used[p.userBlockIndexLocked(t.Port)] = true
		}
		return true
	})
	return used
}

// AssignUserBlock gives a new normal user the first completely free block of
// UserQuota consecutive ports and writes it into AllowPorts. Super admins and
// users with an explicitly configured range are left untouched (they keep the
// legacy unrestricted behaviour).
func (p *PortAllocator) AssignUserBlock(u *User) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.cfg.Enabled || u == nil || u.IsSuperAdmin() || strings.TrimSpace(u.AllowPorts) != "" {
		return "", nil
	}
	p.sweepLocked()
	used := p.usedUserBlockSetLocked()
	total := (p.cfg.UserEnd - p.cfg.UserStart + 1) / p.cfg.UserQuota
	for i := 0; i < total; i++ {
		if used[i] {
			continue
		}
		start := p.cfg.UserStart + i*p.cfg.UserQuota
		end := start + p.cfg.UserQuota - 1
		p.blocks[i] = time.Now()
		u.AllowPorts = strconv.Itoa(start) + "-" + strconv.Itoa(end)
		logs.Info("[portpool] user %q got exclusive block %s", u.Username, u.AllowPorts)
		return u.AllowPorts, nil
	}
	return "", errors.New("port pool: no free exclusive port block left")
}

// blockedPortsLocked lists ports that must not be allocated: system listeners,
// ports of every enabled tunnel, permanently pinned ports, all legacy /
// manually configured ports, and in-flight leases.
//
// Only a stopped *temporary* (PortPool == "shared") tunnel is intentionally
// absent - that is exactly how its port returns to the pool. Fixed ports and
// legacy ports keep their reservation while stopped: they predate the pool
// (or were pinned explicitly), so the allocator must never hand their number
// to somebody else, otherwise restarting the old tunnel would collide.
func (p *PortAllocator) blockedPortsLocked() map[int]bool {
	blocked := make(map[int]bool)
	for _, port := range p.cfg.SystemPorts {
		if port > 0 {
			blocked[port] = true
		}
	}
	p.store.RangeTasks(func(t *Tunnel) bool {
		if t == nil || t.Port <= 0 {
			return true
		}
		if t.Status || t.PortPool == PortFromFixed || t.PortPool == "" {
			blocked[t.Port] = true
		}
		return true
	})
	for _, l := range p.leases {
		blocked[l.port] = true
	}
	return blocked
}

// sharedCandidatesLocked is the allocatable part of the shared range: the
// whole range, or its intersection with the global allow_ports whitelist.
func (p *PortAllocator) sharedCandidatesLocked() []int {
	if len(p.cfg.GlobalPorts) > 0 {
		seen := make(map[int]bool, len(p.cfg.GlobalPorts))
		out := make([]int, 0, len(p.cfg.GlobalPorts))
		for _, port := range p.cfg.GlobalPorts {
			if p.inSharedRangeLocked(port) && !seen[port] {
				seen[port] = true
				out = append(out, port)
			}
		}
		return out
	}
	out := make([]int, 0, p.cfg.SharedEnd-p.cfg.SharedStart+1)
	for port := p.cfg.SharedStart; port <= p.cfg.SharedEnd; port++ {
		out = append(out, port)
	}
	return out
}

// AllocateShared rents a random free port from the shared range. The lease is
// in-flight until CommitShared (task persisted) or AbortShared (creation
// failed) is called, which prevents two concurrent requests picking the same
// port before either tunnel is stored.
func (p *PortAllocator) AllocateShared(mode string, taskId, userId int, exclude ...int) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.cfg.Enabled {
		return 0, errors.New("port pool is disabled")
	}
	p.sweepLocked()
	blocked := p.blockedPortsLocked()
	for _, port := range exclude {
		if port > 0 {
			blocked[port] = true
		}
	}
	candidates := p.sharedCandidatesLocked()
	if len(candidates) == 0 {
		return 0, errors.New("port pool: global allow_ports does not overlap the shared range")
	}
	start := rand.Intn(len(candidates))
	for i := 0; i < len(candidates); i++ {
		port := candidates[(start+i)%len(candidates)]
		if blocked[port] {
			continue
		}
		if !p.probe(port, mode) {
			continue
		}
		p.leases[taskId] = &sharedLease{port: port, taskId: taskId, userId: userId, created: time.Now()}
		logs.Info("[portpool] task %d (user %d) rented shared port %d", taskId, userId, port)
		return port, nil
	}
	return 0, errors.New("port pool: shared range exhausted")
}

// HoldShared keeps a shared port reserved while an existing tunnel is being
// edited (its service is stopped and restarted, so the port briefly leaves the
// tasks table's busy set). CommitShared clears the hold once it is running.
func (p *PortAllocator) HoldShared(taskId, port, userId int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.cfg.Enabled || !p.inSharedRangeLocked(port) {
		return
	}
	p.leases[taskId] = &sharedLease{port: port, taskId: taskId, userId: userId, created: time.Now()}
}

// CommitShared moves a lease from "in flight" to "owned by the tasks table".
func (p *PortAllocator) CommitShared(taskId int) {
	p.mu.Lock()
	delete(p.leases, taskId)
	p.mu.Unlock()
}

// AbortShared rolls back a lease whose tunnel was never created.
func (p *PortAllocator) AbortShared(taskId int) {
	p.CommitShared(taskId)
}

// ReleaseShared is the explicit recycling hook called from StopServer /
// DelTask. Temporary leases are handed back; a fixed port is deliberately
// kept - that is the whole point of converting a random port into a fixed one.
func (p *PortAllocator) ReleaseShared(taskId int) int {
	p.mu.Lock()
	l := p.leases[taskId]
	delete(p.leases, taskId)
	store := p.store
	p.mu.Unlock()
	if l != nil {
		logs.Info("[portpool] shared port %d returned (task %d, in-flight)", l.port, taskId)
		return l.port
	}
	if t, ok := store.GetTask(taskId); ok && t != nil {
		switch t.PortPool {
		case PortFromShared:
			logs.Info("[portpool] shared port %d returned (task %d)", t.Port, taskId)
			return t.Port
		case PortFromFixed:
			logs.Info("[portpool] fixed port %d kept for task %d (never expires)", t.Port, taskId)
		}
	}
	return 0
}

// FixedPortClient reports whether a port is a permanently pinned shared port
// and, if so, which client owns the tunnel holding it. The web layer uses it
// to let the owner edit that port manually while refusing other users.
func (p *PortAllocator) FixedPortClient(port int) (int, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.cfg.Enabled || !p.inSharedRangeLocked(port) {
		return 0, false
	}
	var clientId int
	found := false
	p.store.RangeTasks(func(t *Tunnel) bool {
		if t != nil && t.Port == port && t.PortPool == PortFromFixed {
			found = true
			if t.Client != nil {
				clientId = t.Client.Id
			}
			return false
		}
		return true
	})
	return clientId, found
}

// PinShared converts a temporary shared lease into a permanent fixed port.
// The tunnel keeps the very same number, keeps working across stops, restarts
// and client reconnects, and is never recycled. The flag is changed under the
// allocator lock so a concurrent AllocateShared can never take the port in
// between. The caller only has to persist the tunnel (UpdateTask).
func (p *PortAllocator) PinShared(taskId int) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.store.GetTask(taskId)
	if !ok || t == nil {
		return 0, errors.New("port pool: tunnel not found")
	}
	if t.PortPool == PortFromFixed {
		return t.Port, nil // idempotent
	}
	if !p.cfg.Enabled || !p.inSharedRangeLocked(t.Port) {
		return 0, errors.New("port pool: only shared pool ports can be pinned")
	}
	// A lease belonging to this very task is just the creation still in
	// flight. A lease belonging to another task means somebody is about to
	// rent the same number, so pinning must wait.
	for id, l := range p.leases {
		if l.port == t.Port && id != taskId {
			return 0, errors.New("port pool: this port is being rented by another task")
		}
	}
	conflict := false
	p.store.RangeTasks(func(other *Tunnel) bool {
		if other == nil || other.Id == taskId {
			return true
		}
		// Only a stopped temporary tunnel has returned its port. Everything
		// else - running, fixed, or a legacy/manual port - is still owned.
		if other.Port == t.Port && (other.Status || other.PortPool != PortFromShared) {
			conflict = true
			return false
		}
		return true
	})
	if conflict {
		return 0, errors.New("port pool: port is already occupied by another tunnel")
	}
	delete(p.leases, taskId)
	t.PortPool = PortFromFixed
	logs.Info("[portpool] task %d pinned shared port %d (permanent, never expires)", taskId, t.Port)
	return t.Port, nil
}

// UnpinShared turns a fixed port back into a temporary shared lease. A running
// tunnel keeps its current number until it is stopped; a stopped one returns
// its port to the pool immediately and gets a fresh number on restart.
func (p *PortAllocator) UnpinShared(taskId int) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.store.GetTask(taskId)
	if !ok || t == nil {
		return 0, errors.New("port pool: tunnel not found")
	}
	if t.PortPool != PortFromFixed {
		return 0, errors.New("port pool: this tunnel is not pinned")
	}
	t.PortPool = PortFromShared
	logs.Info("[portpool] task %d unpinned shared port %d (temporary again)", taskId, t.Port)
	return t.Port, nil
}

// BlockedPorts returns a snapshot of ports that must not be allocated right
// now (system listeners, enabled tunnels, in-flight leases).
func (p *PortAllocator) BlockedPorts() map[int]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweepLocked()
	return p.blockedPortsLocked()
}

// PickFromAllowed chooses a free port inside an explicit whitelist (normally
// the user's exclusive block). It is the fallback when the shared pool is
// exhausted; unlike shared ports, these are never auto-recycled.
func (p *PortAllocator) PickFromAllowed(allowed []int, mode string) (int, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(allowed) == 0 {
		return 0, false
	}
	p.sweepLocked()
	blocked := p.blockedPortsLocked()
	start := rand.Intn(len(allowed))
	for i := 0; i < len(allowed); i++ {
		port := allowed[(start+i)%len(allowed)]
		if port <= 0 || port > 65535 || blocked[port] {
			continue
		}
		if !p.probe(port, mode) {
			continue
		}
		return port, true
	}
	return 0, false
}

// IsSharedLeased reports whether a port is currently owned by a *temporary*
// shared lease (in-flight or a shared tunnel). TestServerPort uses it to let
// pool-assigned ports through a user's exclusive whitelist, while still
// rejecting manually typed shared-range ports. Fixed ports are intentionally
// excluded: they are cleared by tool.IsFixedPortAllowed, which also checks
// ownership, so another user cannot type somebody else's pinned number.
func (p *PortAllocator) IsSharedLeased(port int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.cfg.Enabled || !p.inSharedRangeLocked(port) {
		return false
	}
	p.sweepLocked()
	for _, l := range p.leases {
		if l.port == port {
			return true
		}
	}
	found := false
	p.store.RangeTasks(func(t *Tunnel) bool {
		// Status is deliberately not checked: a stopped shared tunnel keeps
		// its PortPool marker so that editing / restarting it still passes the
		// whitelist check. The port itself is already free for reuse because
		// blockedPortsLocked only counts Status==true tunnels.
		if t != nil && t.Port == port && t.PortPool == PortFromShared {
			found = true
			return false
		}
		return true
	})
	return found
}

// IsSharedPortForTask is used before restarting a stopped tunnel: a temporary
// shared port may already have been rented to somebody else, so a fresh one is
// picked. Fixed ports deliberately return false - they must never change.
func (p *PortAllocator) IsSharedPortForTask(taskId int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.store.GetTask(taskId)
	return ok && t != nil && t.PortPool == PortFromShared
}

func (p *PortAllocator) Stats() PortPoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweepLocked()
	s := PortPoolStats{
		Enabled:          p.cfg.Enabled,
		UserStart:        p.cfg.UserStart,
		UserEnd:          p.cfg.UserEnd,
		UserQuota:        p.cfg.UserQuota,
		SharedStart:      p.cfg.SharedStart,
		SharedEnd:        p.cfg.SharedEnd,
		SharedPortReport: fmt.Sprintf("%d-%d", p.cfg.SharedStart, p.cfg.SharedEnd),
	}
	s.UserBlocksTotal = (p.cfg.UserEnd - p.cfg.UserStart + 1) / p.cfg.UserQuota
	used := p.usedUserBlockSetLocked()
	for i := 0; i < s.UserBlocksTotal; i++ {
		if used[i] {
			s.UserBlocksUsed++
		}
	}
	p.store.RangeTasks(func(t *Tunnel) bool {
		if t != nil && t.PortPool == PortFromFixed {
			s.FixedUsed++
		}
		return true
	})
	candidates := p.sharedCandidatesLocked()
	s.SharedTotal = len(candidates)
	blocked := p.blockedPortsLocked()
	for _, port := range candidates {
		if blocked[port] {
			s.SharedUsed++
		}
	}
	return s
}
