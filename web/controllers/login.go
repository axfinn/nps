package controllers

import (
	"math/rand"
	"net"
	"sync"
	"time"

	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/file"
	"ehang.io/nps/server"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/cache"
	"github.com/astaxie/beego/utils/captcha"
)

type LoginController struct {
	beego.Controller
}

var ipRecord sync.Map
var cpt *captcha.Captcha

type record struct {
	hasLoginFailTimes int
	lastLoginTime     time.Time
}

func init() {
	// use beego cache system store the captcha data
	store := cache.NewMemoryCache()
	cpt = captcha.NewWithFilter("/captcha/", store)
}

func (self *LoginController) Index() {
	// Try login implicitly, will succeed if it's configured as no-auth(empty username&password).
	webBaseUrl := beego.AppConfig.String("web_base_url")
	if self.doLogin("", "", false) {
		self.Redirect(webBaseUrl+"/index/index", 302)
	}
	self.Data["web_base_url"] = webBaseUrl
	self.Data["register_allow"], _ = beego.AppConfig.Bool("allow_user_register")
	self.Data["captcha_open"], _ = beego.AppConfig.Bool("open_captcha")
	self.TplName = "login/index.html"
}

func (self *LoginController) Verify() {
	username := self.GetString("username")
	password := self.GetString("password")
	captchaOpen, _ := beego.AppConfig.Bool("open_captcha")
	if captchaOpen {
		if !cpt.VerifyReq(self.Ctx.Request) {
			self.Data["json"] = map[string]interface{}{"status": 0, "msg": "the verification code is wrong, please get it again and try again"}
			self.ServeJSON()
		}
	}
	if self.doLogin(username, password, true) {
		self.Data["json"] = map[string]interface{}{"status": 1, "msg": "login success"}
	} else {
		self.Data["json"] = map[string]interface{}{"status": 0, "msg": "username or password incorrect"}
	}
	self.ServeJSON()
}

func (self *LoginController) setSuperAdminSession() {
	self.SetSession("isAdmin", true)
	self.SetSession("role", file.RoleSuperAdmin)
	self.DelSession("userId")
	self.DelSession("clientIds")
	self.DelSession("clientId")
	self.DelSession("username")
	server.Bridge.Register.Store(common.GetIpByAddr(self.Ctx.Input.IP()), time.Now().Add(time.Hour*2))
}

func (self *LoginController) doLogin(username, password string, explicit bool) bool {
	clearIprecord()
	ip, _, _ := net.SplitHostPort(self.Ctx.Request.RemoteAddr)
	if v, ok := ipRecord.Load(ip); ok {
		vv := v.(*record)
		if (time.Now().Unix() - vv.lastLoginTime.Unix()) >= 60 {
			vv.hasLoginFailTimes = 0
		}
		if vv.hasLoginFailTimes >= 10 {
			return false
		}
	}
	var auth bool

	// 1. Independent user store (super_admin / user).
	if beego.AppConfig.DefaultBool("user_auth_enable", true) {
		if u := file.GetDb().GetUserByName(username); u != nil && u.CheckPassword(password) {
			auth = true
			self.SetSession("isAdmin", u.IsSuperAdmin())
			self.SetSession("role", u.Role)
			self.SetSession("userId", u.Id)
			self.SetSession("username", u.Username)
			self.SetSession("clientIds", u.ClientIds)
			if u.IsSuperAdmin() {
				self.DelSession("clientId")
				server.Bridge.Register.Store(common.GetIpByAddr(self.Ctx.Input.IP()), time.Now().Add(time.Hour*2))
			} else if len(u.ClientIds) > 0 {
				self.SetSession("clientId", u.ClientIds[0])
			} else {
				self.SetSession("clientId", 0)
			}
		}
	}

	// 2. Legacy admin from nps.conf, kept as a recovery path.
	if !auth && password == beego.AppConfig.String("web_password") && username == beego.AppConfig.String("web_username") {
		self.setSuperAdminSession()
		auth = true
	}

	// 3. Legacy per-client web login (user + vkey), kept for compatibility.
	if !auth {
		b, err := beego.AppConfig.Bool("allow_user_login")
		if err == nil && b {
			file.GetDb().JsonDb.Clients.Range(func(key, value interface{}) bool {
				v := value.(*file.Client)
				if !v.Status || v.NoDisplay {
					return true
				}
				matched := false
				if v.WebUserName == "" && v.WebPassword == "" {
					matched = username == "user" && v.VerifyKey == password
				} else {
					matched = v.WebPassword == password && v.WebUserName == username
				}
				if !matched {
					return true
				}
				auth = true
				self.SetSession("isAdmin", false)
				self.SetSession("role", file.RoleUser)
				self.DelSession("userId")
				self.SetSession("clientId", v.Id)
				self.SetSession("clientIds", []int{v.Id})
				self.SetSession("username", v.WebUserName)
				return false
			})
		}
	}

	if auth {
		self.SetSession("auth", true)
		ipRecord.Delete(ip)
		return true
	}
	if v, load := ipRecord.LoadOrStore(ip, &record{hasLoginFailTimes: 1, lastLoginTime: time.Now()}); load && explicit {
		vv := v.(*record)
		vv.lastLoginTime = time.Now()
		vv.hasLoginFailTimes += 1
		ipRecord.Store(ip, vv)
	}
	return false
}

func (self *LoginController) Register() {
	if self.Ctx.Request.Method == "GET" {
		self.Data["web_base_url"] = beego.AppConfig.String("web_base_url")
		self.TplName = "login/register.html"
		return
	}
	if b, err := beego.AppConfig.Bool("allow_user_register"); err != nil || !b {
		self.Data["json"] = map[string]interface{}{"status": 0, "msg": "register is not allow"}
		self.ServeJSON()
		return
	}
	username := self.GetString("username")
	password := self.GetString("password")
	if username == "" || password == "" || username == beego.AppConfig.String("web_username") {
		self.Data["json"] = map[string]interface{}{"status": 0, "msg": "please check your input"}
		self.ServeJSON()
		return
	}
	if beego.AppConfig.DefaultBool("user_auth_enable", true) {
		if file.GetDb().GetUserByName(username) != nil {
			self.Data["json"] = map[string]interface{}{"status": 0, "msg": "username already exists"}
			self.ServeJSON()
			return
		}
		c := &file.Client{
			Status:          true,
			Cnf:             &file.Config{},
			Flow:            &file.Flow{},
			ConfigConnAllow: true,
			Remark:          "注册用户 " + username,
			CreateTime:      time.Now().Format("2006-01-02 15:04:05"),
		}
		if err := file.GetDb().NewClient(c); err != nil {
			self.Data["json"] = map[string]interface{}{"status": 0, "msg": err.Error()}
			self.ServeJSON()
			return
		}
		u := &file.User{
			Username:   username,
			Role:       file.RoleUser,
			Status:     true,
			ClientIds:  []int{c.Id},
			Remark:     "自助注册",
			CreateTime: time.Now().Format("2006-01-02 15:04:05"),
		}
		u.SetPassword(password)
		if err := file.GetDb().NewUser(u); err != nil {
			_ = file.GetDb().DelClient(c.Id)
			self.Data["json"] = map[string]interface{}{"status": 0, "msg": err.Error()}
			self.ServeJSON()
			return
		}
		self.Data["json"] = map[string]interface{}{"status": 1, "msg": "register success"}
		self.ServeJSON()
		return
	}
	// Legacy registration: a client with a web login attached.
	t := &file.Client{
		Id:          int(file.GetDb().JsonDb.GetClientId()),
		Status:      true,
		Cnf:         &file.Config{},
		WebUserName: username,
		WebPassword: password,
		Flow:        &file.Flow{},
	}
	if err := file.GetDb().NewClient(t); err != nil {
		self.Data["json"] = map[string]interface{}{"status": 0, "msg": err.Error()}
	} else {
		self.Data["json"] = map[string]interface{}{"status": 1, "msg": "register success"}
	}
	self.ServeJSON()
}

func (self *LoginController) Out() {
	self.DelSession("auth")
	self.DelSession("isAdmin")
	self.DelSession("role")
	self.DelSession("userId")
	self.DelSession("clientId")
	self.DelSession("clientIds")
	self.DelSession("username")
	self.Redirect(beego.AppConfig.String("web_base_url")+"/login/index", 302)
}

func clearIprecord() {
	rand.Seed(time.Now().UnixNano())
	x := rand.Intn(100)
	if x == 1 {
		ipRecord.Range(func(key, value interface{}) bool {
			v := value.(*record)
			if time.Now().Unix()-v.lastLoginTime.Unix() >= 60 {
				ipRecord.Delete(key)
			}
			return true
		})
	}
}
