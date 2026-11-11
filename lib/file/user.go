package file

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"ehang.io/nps/lib/crypt"
)

// User roles. A super admin manages the whole server, a normal user only
// manages the clients explicitly assigned to it.
const (
	RoleSuperAdmin = "super_admin"
	RoleUser       = "user"
)

// User is stored in conf/users.json. Passwords are never persisted in plain
// text: PasswordHash is a salted, iterated SHA-256 digest.
type User struct {
	Id           int
	Username     string
	PasswordHash string
	Salt         string
	Role         string
	Status       bool
	ClientIds    []int
	AllowPorts   string
	Remark       string
	CreateTime   string
}

// HashUserPassword derives a password digest. Iterated SHA-256 with a random
// per-user salt is used to avoid adding a new module dependency.
func HashUserPassword(pwd, salt string) string {
	b := []byte(pwd + ":" + salt)
	for i := 0; i < 20000; i++ {
		sum := sha256.Sum256(b)
		b = sum[:]
	}
	return hex.EncodeToString(b)
}

func (u *User) SetPassword(pwd string) {
	u.Salt = crypt.GetRandomString(16)
	u.PasswordHash = HashUserPassword(pwd, u.Salt)
}

func (u *User) CheckPassword(pwd string) bool {
	if u == nil || u.PasswordHash == "" || !u.Status {
		return false
	}
	got := HashUserPassword(pwd, u.Salt)
	return subtle.ConstantTimeCompare([]byte(got), []byte(u.PasswordHash)) == 1
}

func (u *User) IsSuperAdmin() bool {
	return u != nil && u.Role == RoleSuperAdmin
}

func (u *User) HasClient(id int) bool {
	if u == nil {
		return false
	}
	for _, v := range u.ClientIds {
		if v == id {
			return true
		}
	}
	return false
}

// Public returns a copy safe to serialize to the web UI (no hash / salt).
func (u *User) Public() *User {
	if u == nil {
		return nil
	}
	ids := append([]int(nil), u.ClientIds...)
	return &User{
		Id:         u.Id,
		Username:   u.Username,
		Role:       u.Role,
		Status:     u.Status,
		ClientIds:  ids,
		AllowPorts: u.AllowPorts,
		Remark:     u.Remark,
		CreateTime: u.CreateTime,
	}
}

func (s *DbUtils) HasUsers() bool {
	var has bool
	s.JsonDb.Users.Range(func(key, value interface{}) bool {
		has = true
		return false
	})
	return has
}

func (s *DbUtils) GetUser(id int) (*User, error) {
	if v, ok := s.JsonDb.Users.Load(id); ok {
		return v.(*User), nil
	}
	return nil, errors.New("user not found")
}

func (s *DbUtils) GetUserByName(username string) *User {
	var found *User
	s.JsonDb.Users.Range(func(key, value interface{}) bool {
		v := value.(*User)
		if v.Username == username {
			found = v
			return false
		}
		return true
	})
	return found
}

// GetUserByClientId resolves which normal user owns a client. A client that
// is not assigned to any user is considered managed by the super admin.
func (s *DbUtils) GetUserByClientId(clientId int) *User {
	var found *User
	s.JsonDb.Users.Range(func(key, value interface{}) bool {
		v := value.(*User)
		if v.Role == RoleUser && v.HasClient(clientId) {
			found = v
			return false
		}
		return true
	})
	return found
}

func (s *DbUtils) GetUserList(start, length int, search string) ([]*User, int) {
	list := make([]*User, 0)
	var cnt int
	ids := make([]int, 0)
	s.JsonDb.Users.Range(func(key, value interface{}) bool {
		ids = append(ids, key.(int))
		return true
	})
	sort.Ints(ids)
	for _, id := range ids {
		v, ok := s.JsonDb.Users.Load(id)
		if !ok {
			continue
		}
		u := v.(*User)
		if search != "" && !strings.Contains(u.Username, search) && !strings.Contains(u.Remark, search) {
			continue
		}
		cnt++
		if start--; start < 0 {
			if length--; length >= 0 {
				list = append(list, u.Public())
			}
		}
	}
	return list, cnt
}

// VerifyUserUsername reports whether username is available for the given user id.
func (s *DbUtils) VerifyUserUsername(username string, id int) bool {
	var ok = true
	s.JsonDb.Users.Range(func(key, value interface{}) bool {
		v := value.(*User)
		if v.Username == username && v.Id != id {
			ok = false
			return false
		}
		return true
	})
	return ok
}

// ValidateClientOwnership makes sure a client is assigned to at most one user.
func (s *DbUtils) ValidateClientOwnership(u *User) error {
	var conflict int
	s.JsonDb.Users.Range(func(key, value interface{}) bool {
		v := value.(*User)
		if v.Id == u.Id || v.Role == RoleSuperAdmin {
			return true
		}
		for _, id := range u.ClientIds {
			if v.HasClient(id) {
				conflict = id
				return false
			}
		}
		return true
	})
	if conflict != 0 {
		return errors.New("client " + strconv.Itoa(conflict) + " is already assigned to another user")
	}
	return nil
}

func (s *DbUtils) NewUser(u *User) error {
	if strings.TrimSpace(u.Username) == "" {
		return errors.New("username is required")
	}
	if !s.VerifyUserUsername(u.Username, u.Id) {
		return errors.New("username already exists")
	}
	if err := s.ValidateClientOwnership(u); err != nil {
		return err
	}
	if u.Role != RoleSuperAdmin {
		u.Role = RoleUser
	}
	if u.Id == 0 {
		u.Id = int(s.JsonDb.GetUserId())
	}
	if u.CreateTime == "" {
		u.CreateTime = time.Now().Format("2006-01-02 15:04:05")
	}
	s.JsonDb.Users.Store(u.Id, u)
	s.JsonDb.StoreUsersToJsonFile()
	return nil
}

func (s *DbUtils) UpdateUser(u *User) error {
	if _, err := s.GetUser(u.Id); err != nil {
		return err
	}
	if !s.VerifyUserUsername(u.Username, u.Id) {
		return errors.New("username already exists")
	}
	if err := s.ValidateClientOwnership(u); err != nil {
		return err
	}
	if u.Role != RoleSuperAdmin {
		u.Role = RoleUser
	}
	s.JsonDb.Users.Store(u.Id, u)
	s.JsonDb.StoreUsersToJsonFile()
	return nil
}

func (s *DbUtils) DelUser(id int) error {
	u, err := s.GetUser(id)
	if err != nil {
		return err
	}
	if u.IsSuperAdmin() && s.CountSuperAdmins() <= 1 {
		return errors.New("cannot delete the last super admin")
	}
	s.JsonDb.Users.Delete(id)
	s.JsonDb.StoreUsersToJsonFile()
	return nil
}

func (s *DbUtils) CountSuperAdmins() (n int) {
	s.JsonDb.Users.Range(func(key, value interface{}) bool {
		if value.(*User).IsSuperAdmin() {
			n++
		}
		return true
	})
	return
}

// InitUsers bootstraps the user store on first start. The legacy admin from
// nps.conf becomes a super admin and every legacy client web account becomes
// a normal user owning exactly that client. Existing installs keep working.
func (s *DbUtils) InitUsers(adminName, adminPwd string) {
	if s.HasUsers() {
		return
	}
	if strings.TrimSpace(adminName) == "" {
		adminName = "admin"
	}
	admin := &User{
		Username:   adminName,
		Role:       RoleSuperAdmin,
		Status:     true,
		Remark:     "由 nps.conf 初始化",
		CreateTime: time.Now().Format("2006-01-02 15:04:05"),
	}
	admin.SetPassword(adminPwd)
	_ = s.NewUser(admin)

	s.JsonDb.Clients.Range(func(key, value interface{}) bool {
		c := value.(*Client)
		if c.NoDisplay || (c.WebUserName == "" && c.WebPassword == "") {
			return true
		}
		name := c.WebUserName
		if name == "" {
			name = "user_" + strconv.Itoa(c.Id)
		}
		if !s.VerifyUserUsername(name, 0) {
			return true
		}
		pwd := c.WebPassword
		if pwd == "" {
			pwd = c.VerifyKey
		}
		u := &User{
			Username:   name,
			Role:       RoleUser,
			Status:     c.Status,
			ClientIds:  []int{c.Id},
			Remark:     "由客户端 " + strconv.Itoa(c.Id) + " 迁移",
			CreateTime: time.Now().Format("2006-01-02 15:04:05"),
		}
		u.SetPassword(pwd)
		_ = s.NewUser(u)
		return true
	})
}
