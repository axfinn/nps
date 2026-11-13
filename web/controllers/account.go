package controllers

import (
	"ehang.io/nps/lib/file"
	"ehang.io/nps/lib/mail"

	"github.com/astaxie/beego"
)

// AccountController exposes the per-user self-service settings. It is
// deliberately separate from UserController: that controller is super-admin
// only, while every logged-in user must be able to bind their own email.
type AccountController struct {
	BaseController
}

func (s *AccountController) Profile() {
	u := s.SessionUser()
	s.Data["menu"] = "account"
	s.Data["email_login_enable"] = emailLoginEnabled()
	s.Data["mail_service_configured"] = mailServiceConfig().Configured()
	s.Data["code_ttl_minutes"] = beego.AppConfig.DefaultInt("email_code_ttl_minutes", 10)
	s.Data["resend_seconds"] = beego.AppConfig.DefaultInt("email_code_resend_seconds", 60)
	s.Data["username"] = s.GetSession("username")
	s.Data["email"] = ""
	s.Data["user_id"] = 0
	if u != nil {
		s.Data["username"] = u.Username
		s.Data["email"] = u.Email
		s.Data["user_id"] = u.Id
	}
	s.SetInfo("account")
	s.display("account/profile")
}

// BindEmail consumes a bind-purpose code and stores the address. A code is
// tied to the exact address it was mailed to, so this doubles as ownership
// verification of the mailbox.
func (s *AccountController) BindEmail() {
	if !emailLoginEnabled() {
		s.AjaxErr("邮箱验证码登录未启用，请先配置中心邮件服务（NPS_MAIL_CLIENT_ID / NPS_MAIL_CLIENT_SECRET）")
		return
	}
	u := s.SessionUser()
	if u == nil {
		s.AjaxErr("当前登录账号不在用户表中，无法自助绑定邮箱，请联系超级管理员")
		return
	}
	email := mail.NormalizeEmail(s.GetString("email"))
	if !mail.ValidEmail(email) {
		s.AjaxErr("邮箱格式不正确")
		return
	}
	if other := file.GetDb().GetUserByEmail(email); other != nil && other.Id != u.Id {
		s.AjaxErr("该邮箱已被其他账号绑定")
		return
	}
	if !emailCodeStore().Consume(email, mail.PurposeBind, s.GetString("code")) {
		s.AjaxErr("验证码错误或已过期，请重新获取")
		return
	}
	if err := file.GetDb().SetUserEmail(u.Id, email); err != nil {
		s.AjaxErr(err.Error())
		return
	}
	s.AjaxOk("邮箱绑定成功，之后可用邮箱验证码登录")
}

// UnbindEmail removes the address. It requires a logged-in session, but no
// code: the user is already authenticated and is only reducing their own
// login surface.
func (s *AccountController) UnbindEmail() {
	u := s.SessionUser()
	if u == nil {
		s.AjaxErr("当前登录账号不在用户表中，无法解绑邮箱")
		return
	}
	if err := file.GetDb().SetUserEmail(u.Id, ""); err != nil {
		s.AjaxErr(err.Error())
		return
	}
	s.AjaxOk("邮箱已解绑")
}
