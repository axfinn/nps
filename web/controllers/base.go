package controllers

import (
	"html"
	"math"
	"strconv"
	"strings"
	"time"

	"ehang.io/nps/bridge"
	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/crypt"
	"ehang.io/nps/lib/file"
	"ehang.io/nps/server"
	"github.com/astaxie/beego"
)

type BaseController struct {
	beego.Controller
	controllerName string
	actionName     string
}

// 初始化参数
func (s *BaseController) Prepare() {
	s.Data["web_base_url"] = beego.AppConfig.String("web_base_url")
	controllerName, actionName := s.GetControllerAndAction()
	s.controllerName = strings.ToLower(controllerName[0 : len(controllerName)-10])
	s.actionName = strings.ToLower(actionName)
	// web api verify
	// param 1 is md5(authKey+Current timestamp)
	// param 2 is timestamp (It's limited to 20 seconds.)
	md5Key := s.getEscapeString("auth_key")
	timestamp := s.GetIntNoErr("timestamp")
	configKey := beego.AppConfig.String("auth_key")
	if configKey == "" {
		configKey = crypt.GetRandomString(64)
	}
	timeNowUnix := time.Now().Unix()
	if !(md5Key != "" && (math.Abs(float64(timeNowUnix-int64(timestamp))) <= 20) && (crypt.Md5(configKey+strconv.Itoa(timestamp)) == md5Key)) {
		if s.GetSession("auth") != true {
			s.Redirect(beego.AppConfig.String("web_base_url")+"/login/index", 302)
		}
	} else {
		s.SetSession("isAdmin", true)
		s.SetSession("role", file.RoleSuperAdmin)
		s.DelSession("userId")
		s.DelSession("clientIds")
		s.Data["isAdmin"] = true
	}
	if s.IsSuperAdmin() {
		s.Data["isAdmin"] = true
		if s.GetSession("role") == nil {
			s.SetSession("role", file.RoleSuperAdmin)
		}
	} else {
		s.Data["isAdmin"] = false
		s.Data["username"] = s.GetSession("username")
		s.CheckUserAuth()
	}
	s.Data["role"] = s.GetSession("role")
	s.Data["user_auth_enable"] = beego.AppConfig.DefaultBool("user_auth_enable", true)
	s.Data["https_just_proxy"], _ = beego.AppConfig.Bool("https_just_proxy")
	s.Data["allow_user_login"], _ = beego.AppConfig.Bool("allow_user_login")
	s.Data["allow_flow_limit"], _ = beego.AppConfig.Bool("allow_flow_limit")
	s.Data["allow_rate_limit"], _ = beego.AppConfig.Bool("allow_rate_limit")
	s.Data["allow_connection_num_limit"], _ = beego.AppConfig.Bool("allow_connection_num_limit")
	s.Data["allow_multi_ip"], _ = beego.AppConfig.Bool("allow_multi_ip")
	s.Data["system_info_display"], _ = beego.AppConfig.Bool("system_info_display")
	s.Data["allow_tunnel_num_limit"], _ = beego.AppConfig.Bool("allow_tunnel_num_limit")
	s.Data["allow_local_proxy"], _ = beego.AppConfig.Bool("allow_local_proxy")
	s.Data["allow_user_change_username"], _ = beego.AppConfig.Bool("allow_user_change_username")
}

func toIntSlice(v interface{}) []int {
	switch x := v.(type) {
	case []int:
		return x
	case []interface{}:
		out := make([]int, 0, len(x))
		for _, it := range x {
			switch n := it.(type) {
			case int:
				out = append(out, n)
			case int64:
				out = append(out, int(n))
			case float64:
				out = append(out, int(n))
			}
		}
		return out
	}
	return nil
}

// VisibleClientIds returns the client scope of the current session. An empty
// slice means the whole server (super admin).
func (s *BaseController) VisibleClientIds() []int {
	return toIntSlice(s.GetSession("clientIds"))
}

func (s *BaseController) IsSuperAdmin() bool {
	v := s.GetSession("isAdmin")
	if v == nil {
		return true
	}
	b, _ := v.(bool)
	return b
}

// CurrentUser resolves the logged-in user. Super admins get a sentinel with
// RoleSuperAdmin so callers can bypass per-user restrictions. Legacy logins
// that never created a user record return nil and fall back to client-owner
// resolution.
func (s *BaseController) CurrentUser() *file.User {
	if s.IsSuperAdmin() {
		return &file.User{Role: file.RoleSuperAdmin}
	}
	if v := s.GetSession("userId"); v != nil {
		if id, ok := v.(int); ok {
			if u, err := file.GetDb().GetUser(id); err == nil {
				return u
			}
		}
	}
	return nil
}

func (s *BaseController) RequireSuperAdmin() bool {
	if !s.IsSuperAdmin() {
		s.AjaxErr("super admin permission required")
		return false
	}
	return true
}

// RequestClientIds narrows the scope when the request explicitly carries a
// client_id. Illegal client ids are rejected by CheckUserAuth; this returns
// a guaranteed-empty scope as a second line of defence.
func (s *BaseController) RequestClientIds() []int {
	visible := s.VisibleClientIds()
	if id := s.GetIntNoErr("client_id"); id != 0 {
		if file.MatchClientId(id, visible) {
			return []int{id}
		}
		return []int{-1}
	}
	return visible
}

// CheckUserAuth enforces the normal-user boundary. Super admins pass through.
func (s *BaseController) CheckUserAuth() {
	if s.IsSuperAdmin() {
		return
	}
	allowed := func(id int) bool { return file.MatchClientId(id, s.VisibleClientIds()) }

	// User management and global settings are super-admin only.
	if s.controllerName == "user" || s.controllerName == "global" {
		s.StopRun()
		return
	}
	// Creating / deleting / disabling clients is super-admin only.
	if s.controllerName == "client" {
		switch s.actionName {
		case "add", "del", "changestatus":
			s.StopRun()
			return
		}
		if id := s.GetIntNoErr("id"); id != 0 && !allowed(id) {
			s.StopRun()
			return
		}
	}
	if cid := s.GetIntNoErr("client_id"); cid != 0 && !allowed(cid) {
		s.StopRun()
		return
	}
	if s.controllerName == "index" {
		if id := s.GetIntNoErr("id"); id != 0 {
			belong := false
			if v, ok := file.GetDb().JsonDb.Hosts.Load(id); ok && allowed(v.(*file.Host).Client.Id) {
				belong = true
			}
			if !belong {
				if v, ok := file.GetDb().JsonDb.Tasks.Load(id); ok && allowed(v.(*file.Tunnel).Client.Id) {
					belong = true
				}
			}
			if !belong {
				s.StopRun()
			}
		}
	}
}

// 加载模板
func (s *BaseController) display(tpl ...string) {
	s.Data["web_base_url"] = beego.AppConfig.String("web_base_url")
	var tplname string
	if s.Data["menu"] == nil {
		s.Data["menu"] = s.actionName
	}
	if len(tpl) > 0 {
		tplname = strings.Join([]string{tpl[0], "html"}, ".")
	} else {
		tplname = s.controllerName + "/" + s.actionName + ".html"
	}
	ip := s.Ctx.Request.Host
	s.Data["ip"] = common.GetIpByAddr(ip)
	s.Data["bridgeType"] = beego.AppConfig.String("bridge_type")
	if common.IsWindows() {
		s.Data["win"] = ".exe"
	}

	s.Data["p"] = strconv.Itoa(server.Bridge.TunnelPort)

	if bridge.ServerTlsEnable {
		tlsPort := strconv.Itoa(beego.AppConfig.DefaultInt("tls_bridge_port", 8025))
		s.Data["tls_p"] = tlsPort
		s.Data["p1"] = strconv.Itoa(server.Bridge.TunnelPort) + " / " + tlsPort
	} else {
		s.Data["p1"] = strconv.Itoa(server.Bridge.TunnelPort)
	}

	s.Data["proxyPort"] = beego.AppConfig.String("hostPort")
	s.Layout = "public/layout.html"
	s.TplName = tplname
}

// 错误
func (s *BaseController) error() {
	s.Data["web_base_url"] = beego.AppConfig.String("web_base_url")
	s.Layout = "public/layout.html"
	s.TplName = "public/error.html"
}

// getEscapeString
func (s *BaseController) getEscapeString(key string) string {
	return html.EscapeString(s.GetString(key))
}

// 去掉没有err返回值的int
func (s *BaseController) GetIntNoErr(key string, def ...int) int {
	strv := s.Ctx.Input.Query(key)
	if len(strv) == 0 && len(def) > 0 {
		return def[0]
	}
	val, _ := strconv.Atoi(strv)
	return val
}

// 获取去掉错误的bool值
func (s *BaseController) GetBoolNoErr(key string, def ...bool) bool {
	strv := s.Ctx.Input.Query(key)
	if len(strv) == 0 && len(def) > 0 {
		return def[0]
	}
	val, _ := strconv.ParseBool(strv)
	return val
}

// ajax正确返回
func (s *BaseController) AjaxOk(str string) {
	s.Data["json"] = ajax(str, 1)
	s.ServeJSON()
	s.StopRun()
}

// ajax正确返回
func (s *BaseController) AjaxOkWithId(str string, id int) {
	s.Data["json"] = ajaxWithId(str, 1, id)
	s.ServeJSON()
	s.StopRun()
}

// ajax错误返回
func (s *BaseController) AjaxErr(str string) {
	s.Data["json"] = ajax(str, 0)
	s.ServeJSON()
	s.StopRun()
}

// 组装ajax
func ajax(str string, status int) map[string]interface{} {
	json := make(map[string]interface{})
	json["status"] = status
	json["msg"] = str
	return json
}

// 组装ajax
func ajaxWithId(str string, status int, id int) map[string]interface{} {
	json := make(map[string]interface{})
	json["status"] = status
	json["msg"] = str
	json["id"] = id
	return json
}

// ajax table返回
func (s *BaseController) AjaxTable(list interface{}, cnt int, recordsTotal int, kwargs map[string]interface{}) {
	json := make(map[string]interface{})
	json["rows"] = list
	json["total"] = recordsTotal
	if kwargs != nil {
		for k, v := range kwargs {
			if v != nil {
				json[k] = v
			}
		}
	}
	s.Data["json"] = json
	s.ServeJSON()
	s.StopRun()
}

// ajax table参数
func (s *BaseController) GetAjaxParams() (start, limit int) {
	return s.GetIntNoErr("offset"), s.GetIntNoErr("limit")
}

func (s *BaseController) SetInfo(name string) {
	s.Data["name"] = name
}

func (s *BaseController) SetType(name string) {
	s.Data["type"] = name
}
