package controllers

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/file"
	"ehang.io/nps/lib/mail"
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
	self.Data["email_login_enable"] = emailLoginEnabled()
	self.Data["email_code_resend_seconds"] = beego.AppConfig.DefaultInt("email_code_resend_seconds", 60)
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
			return
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

// applyUserSession is the single place where a user-table login writes its
// session. Both password and email-code login go through it, so permissions
// can never drift between the two paths.
func (self *LoginController) applyUserSession(u *file.User) {
	self.SetSession("isAdmin", u.IsSuperAdmin())
	self.SetSession("role", u.Role)
	self.SetSession("userId", u.Id)
	self.SetSession("username", u.Username)
	ids := append([]int(nil), u.ClientIds...)
	// An empty scope means "all clients" in the list helpers. A normal user
	// with no clients must therefore carry an impossible id as a sentinel,
	// otherwise it would be treated as an unrestricted viewer.
	if !u.IsSuperAdmin() && len(ids) == 0 {
		ids = []int{-1}
	}
	self.SetSession("clientIds", ids)
	if u.IsSuperAdmin() {
		self.DelSession("clientId")
		server.Bridge.Register.Store(common.GetIpByAddr(self.Ctx.Input.IP()), time.Now().Add(time.Hour*2))
	} else if len(u.ClientIds) > 0 {
		self.SetSession("clientId", u.ClientIds[0])
	} else {
		self.SetSession("clientId", 0)
	}
	self.SetSession("auth", true)
}

func (self *LoginController) clientIP() string {
	if ip, _, err := net.SplitHostPort(self.Ctx.Request.RemoteAddr); err == nil {
		return ip
	}
	return self.Ctx.Input.IP()
}

func (self *LoginController) ajaxStatus(status int, msg string) {
	self.Data["json"] = map[string]interface{}{"status": status, "msg": msg}
	self.ServeJSON()
}

// SendCode issues a login code (unauthenticated, only for bound addresses) or
// a bind-email code (requires a logged-in session).
func (self *LoginController) SendCode() {
	if !emailLoginEnabled() {
		self.ajaxStatus(0, "邮箱验证码登录未启用，请先在 nps.conf 中配置 SMTP")
		return
	}
	purpose := mail.Purpose(strings.TrimSpace(self.GetString("purpose")))
	if !mail.ValidPurpose(purpose) {
		self.ajaxStatus(0, "验证码用途无效")
		return
	}
	email := mail.NormalizeEmail(self.GetString("email"))
	if !mail.ValidEmail(email) {
		self.ajaxStatus(0, "邮箱格式不正确")
		return
	}
	if purpose == mail.PurposeLogin {
		u := file.GetDb().GetUserByEmail(email)
		if u == nil || !u.Status {
			self.ajaxStatus(0, "该邮箱未绑定任何启用中的账号")
			return
		}
	} else {
		if self.GetSession("auth") != true {
			self.ajaxStatus(0, "请先登录后再绑定邮箱")
			return
		}
		if bound := file.GetDb().GetUserByEmail(email); bound != nil {
			if id, ok := self.GetSession("userId").(int); ok && id == bound.Id {
				self.ajaxStatus(0, "该邮箱已是当前账号的绑定邮箱")
			} else {
				self.ajaxStatus(0, "该邮箱已被其他账号绑定")
			}
			return
		}
	}

	code, err := emailCodeStore().Issue(email, purpose, self.clientIP())
	if err != nil {
		switch {
		case errors.Is(err, mail.ErrTooFrequent):
			self.ajaxStatus(0, "发送过于频繁，请稍后再试")
		case errors.Is(err, mail.ErrIPRateLimit):
			self.ajaxStatus(0, "请求次数过多，请一小时后再试")
		default:
			self.ajaxStatus(0, err.Error())
		}
		return
	}

	subject, action := "登录验证码", "登录"
	if purpose == mail.PurposeBind {
		subject, action = "邮箱绑定验证码", "绑定邮箱"
	}
	minutes := beego.AppConfig.DefaultInt("email_code_ttl_minutes", 10)
	body := fmt.Sprintf("你正在%s，验证码是 %s，%d 分钟内有效。\r\n若非本人操作请忽略此邮件，切勿把验证码告诉他人。", action, code, minutes)
	if err := mail.Send(smtpConfig(), email, subject, body); err != nil {
		emailCodeStore().Revoke(email, purpose)
		log.Printf("nps: send email code to %s failed: %v", email, err)
		self.ajaxStatus(0, "验证码邮件发送失败，请检查 SMTP 配置或稍后重试")
		return
	}
	self.ajaxStatus(1, "验证码已发送，请查收邮件")
}

// EmailLogin redeems a login code and opens the same session as a password
// login. Codes are single use and bound to the address they were issued for.
func (self *LoginController) EmailLogin() {
	if !emailLoginEnabled() {
		self.ajaxStatus(0, "邮箱验证码登录未启用")
		return
	}
	email := mail.NormalizeEmail(self.GetString("email"))
	code := strings.TrimSpace(self.GetString("code"))
	if !mail.ValidEmail(email) || code == "" {
		self.ajaxStatus(0, "请输入邮箱和验证码")
		return
	}
	u := file.GetDb().GetUserByEmail(email)
	if u == nil || !u.Status {
		self.ajaxStatus(0, "该邮箱未绑定任何启用中的账号")
		return
	}
	if !emailCodeStore().Consume(email, mail.PurposeLogin, code) {
		self.ajaxStatus(0, "验证码错误或已过期，请重新获取")
		return
	}
	self.applyUserSession(u)
	ipRecord.Delete(self.clientIP())
	self.ajaxStatus(1, "login success")
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
			self.applyUserSession(u)
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
