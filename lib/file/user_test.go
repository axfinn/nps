package file

import (
	"os"
	"path/filepath"
	"testing"
)

func newTestDb(t *testing.T) *DbUtils {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "conf")
	if err := os.MkdirAll(conf, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"clients.json", "tasks.json", "hosts.json"} {
		if err := os.WriteFile(filepath.Join(conf, name), []byte(""), 0600); err != nil {
			t.Fatal(err)
		}
	}
	jsonDb := NewJsonDb(dir)
	jsonDb.LoadClientFromJsonFile()
	jsonDb.LoadUserFromJsonFile()
	return &DbUtils{JsonDb: jsonDb}
}

func TestUserPasswordHash(t *testing.T) {
	u := &User{Username: "alice", Role: RoleUser, Status: true}
	u.SetPassword("s3cret")
	if u.PasswordHash == "s3cret" || u.Salt == "" {
		t.Fatal("password must be stored as a salted hash")
	}
	if !u.CheckPassword("s3cret") || u.CheckPassword("wrong") {
		t.Fatal("password verification failed")
	}
	other := &User{Salt: u.Salt}
	other.SetPassword("s3cret")
	if other.PasswordHash == u.PasswordHash {
		t.Fatal("different salts must produce different hashes")
	}
}

func TestUserOwnership(t *testing.T) {
	db := newTestDb(t)
	a := &User{Username: "a", Role: RoleUser, Status: true, ClientIds: []int{1, 2}}
	a.SetPassword("p")
	if err := db.NewUser(a); err != nil {
		t.Fatal(err)
	}
	b := &User{Username: "b", Role: RoleUser, Status: true, ClientIds: []int{2}}
	b.SetPassword("p")
	if err := db.NewUser(b); err == nil {
		t.Fatal("a client must not be assigned to two normal users")
	}
	dup := &User{Username: "a", Role: RoleUser, Status: true}
	dup.SetPassword("p")
	if err := db.NewUser(dup); err == nil {
		t.Fatal("duplicate username must be rejected")
	}
	if got := db.GetUserByClientId(2); got == nil || got.Username != "a" {
		t.Fatal("client owner lookup failed")
	}
	if got := db.GetUserByClientId(999); got != nil {
		t.Fatal("unassigned client must fall back to super admin scope")
	}
}

func TestInitUsersMigration(t *testing.T) {
	db := newTestDb(t)
	db.JsonDb.Clients.Store(5, &Client{Id: 5, VerifyKey: "vkey5", WebUserName: "alice", WebPassword: "secret", Status: true})
	db.JsonDb.Clients.Store(6, &Client{Id: 6, VerifyKey: "vkey6", WebPassword: "pw6", Status: true})
	db.JsonDb.Clients.Store(7, &Client{Id: 7, VerifyKey: "vkey7", Status: true})
	db.InitUsers("root", "rootpwd")

	admin := db.GetUserByName("root")
	if admin == nil || !admin.IsSuperAdmin() || !admin.CheckPassword("rootpwd") {
		t.Fatal("super admin was not migrated from nps.conf")
	}
	alice := db.GetUserByName("alice")
	if alice == nil || alice.Role != RoleUser || len(alice.ClientIds) != 1 || alice.ClientIds[0] != 5 || !alice.CheckPassword("secret") {
		t.Fatal("legacy client web account was not migrated")
	}
	if u := db.GetUserByName("user_6"); u == nil || !u.CheckPassword("pw6") {
		t.Fatal("legacy account without username should use user_<id> and web password")
	}
	if db.GetUserByName("user_7") != nil {
		t.Fatal("client without web credentials should not create a user")
	}
	db.InitUsers("root", "changed")
	if !db.GetUserByName("root").CheckPassword("rootpwd") {
		t.Fatal("migration must be idempotent and must not overwrite existing users")
	}
}

func TestUserPersistence(t *testing.T) {
	db := newTestDb(t)
	u := &User{Username: "persist", Role: RoleUser, Status: true, ClientIds: []int{3}, AllowPorts: "9001-9005"}
	u.SetPassword("pwd")
	if err := db.NewUser(u); err != nil {
		t.Fatal(err)
	}
	reloaded := NewJsonDb(db.JsonDb.RunPath)
	reloaded.LoadUserFromJsonFile()
	v, err := (&DbUtils{JsonDb: reloaded}).GetUser(u.Id)
	if err != nil || v.Username != "persist" || v.AllowPorts != "9001-9005" || !v.CheckPassword("pwd") {
		t.Fatal("users.json round trip failed", err)
	}
}
