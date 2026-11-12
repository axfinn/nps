package file

import "testing"

func TestUserEmailBinding(t *testing.T) {
	db := newTestDb(t)
	a := &User{Username: "alice", Role: RoleUser, Status: true, Email: "Alice@Example.COM"}
	a.SetPassword("pw")
	if err := db.NewUser(a); err != nil {
		t.Fatal(err)
	}
	if a.Email != "alice@example.com" {
		t.Fatal("email must be normalized before storage")
	}
	if got := db.GetUserByEmail("ALICE@example.com"); got == nil || got.Id != a.Id {
		t.Fatal("case-insensitive email lookup failed")
	}
	if got := db.GetUserByEmail(""); got != nil {
		t.Fatal("empty email must not resolve to a user")
	}

	b := &User{Username: "bob", Role: RoleUser, Status: true, Email: "alice@example.com"}
	b.SetPassword("pw")
	if err := db.NewUser(b); err == nil {
		t.Fatal("an email address must not be bound to two users")
	}
	if b.Email != "alice@example.com" {
		t.Fatal("rejected value should remain untouched on the input object")
	}

	c := &User{Username: "carol", Role: RoleUser, Status: true}
	c.SetPassword("pw")
	if err := db.NewUser(c); err != nil {
		t.Fatal(err)
	}
	if err := db.SetUserEmail(c.Id, "carol@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetUserEmail(c.Id, "not-an-email"); err == nil {
		t.Fatal("invalid email must be rejected")
	}
	if c.Email != "carol@example.com" {
		t.Fatal("a rejected bind must not overwrite the existing address")
	}
	if err := db.SetUserEmail(c.Id, "alice@example.com"); err == nil {
		t.Fatal("duplicate email must be rejected")
	}
	if db.GetUserByEmail("alice@example.com").Id != a.Id {
		t.Fatal("a rejected bind must not create a phantom binding on carol")
	}
	if err := db.SetUserEmail(c.Id, ""); err != nil {
		t.Fatal(err)
	}
	if c.Email != "" || db.GetUserByEmail("carol@example.com") != nil {
		t.Fatal("unbind failed")
	}
}

func TestUserEmailPersistence(t *testing.T) {
	db := newTestDb(t)
	u := &User{Username: "dave", Role: RoleUser, Status: true, Email: "dave@example.com"}
	u.SetPassword("pw")
	if err := db.NewUser(u); err != nil {
		t.Fatal(err)
	}
	reloaded := NewJsonDb(db.JsonDb.RunPath)
	reloaded.LoadUserFromJsonFile()
	got := (&DbUtils{JsonDb: reloaded}).GetUserByEmail("DAVE@example.com")
	if got == nil || got.Id != u.Id || got.Email != "dave@example.com" {
		t.Fatal("email did not survive the users.json round trip")
	}
}

func TestClientAssignment(t *testing.T) {
	db := newTestDb(t)
	u := &User{Username: "owner", Role: RoleUser, Status: true, ClientIds: []int{-1}}
	u.SetPassword("pw")
	if err := db.NewUser(u); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignClientToUser(u.Id, 42); err == nil {
		t.Fatal("cannot assign a client that does not exist")
	}
	db.JsonDb.Clients.Store(42, &Client{Id: 42, VerifyKey: "vkey42"})
	if err := db.AssignClientToUser(u.Id, 42); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignClientToUser(u.Id, 42); err != nil {
		t.Fatal(err)
	}
	if len(u.ClientIds) != 1 || u.ClientIds[0] != 42 {
		t.Fatal("assignment must be idempotent", u.ClientIds)
	}
	if got := db.GetUserByClientId(42); got == nil || got.Id != u.Id {
		t.Fatal("self-created client is not owned by its creator")
	}
	db.UnassignClient(42)
	if len(u.ClientIds) != 0 || db.GetUserByClientId(42) != nil {
		t.Fatal("deleting a client must clear its ownership")
	}
}
