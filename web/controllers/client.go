package controllers

import (
	"strings"
	"time"

	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/file"
	"ehang.io/nps/lib/rate"
	"ehang.io/nps/server"
	"github.com/astaxie/beego"
)

type ClientController struct {
	BaseController
}

func (s *ClientController) List() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "client"
		s.SetInfo("client")
		s.display("client/list")
		return
	}
	start, length := s.GetAjaxParams()
	clientIds := s.RequestClientIds()
	list, cnt := server.GetClientList(start, length, s.getEscapeString("search"), s.getEscapeString("sort"), s.getEscapeString("order"), clientIds)
	cmd := make(map[string]interface{})
	ip := s.Ctx.Request.Host
	cmd["ip"] = common.GetIpByAddr(ip)
	cmd["bridgeType"] = beego.AppConfig.String("bridge_type")
	cmd["bridgePort"] = server.Bridge.TunnelPort
	s.AjaxTable(list, cnt, cnt, cmd)
}

// updateClientScope keeps the session in sync when a normal user adds or
// deletes one of their own clients, so the new permission is visible without
// logging in again. An empty scope always degrades to the -1 sentinel.
func (s *ClientController) updateClientScope(add, remove int) {
	if s.IsSuperAdmin() {
		return
	}
	ids := make([]int, 0)
	for _, id := range s.VisibleClientIds() {
		if id == -1 || (remove > 0 && id == remove) {
			continue
		}
		ids = append(ids, id)
	}
	if add > 0 {
		ids = append(ids, add)
	}
	if len(ids) == 0 {
		ids = []int{-1}
	}
	s.SetSession("clientIds", ids)
}

// 添加客户端。超级管理员可为任意用户创建；普通用户只能创建自己的客户端，
// 创建后立刻写入 users.json 归属，且无法设置配额与旧版 Web 登录凭据。
func (s *ClientController) Add() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "client"
		s.SetInfo("add client")
		s.display()
		return
	}
	var owner *file.User
	if !s.IsSuperAdmin() {
		if !beego.AppConfig.DefaultBool("user_auth_enable", true) {
			s.AjaxErr("当前登录模式不支持用户自助创建客户端")
			return
		}
		owner = s.SessionUser()
		if owner == nil || !owner.Status {
			s.AjaxErr("当前账号不能创建客户端，请联系超级管理员")
			return
		}
	}
	id := int(file.GetDb().JsonDb.GetClientId())
	t := &file.Client{
		VerifyKey: s.getEscapeString("vkey"),
		Id:        id,
		Status:    true,
		Remark:    s.getEscapeString("remark"),
		Cnf: &file.Config{
			U:        s.getEscapeString("u"),
			P:        s.getEscapeString("p"),
			Compress: common.GetBoolByStr(s.getEscapeString("compress")),
			Crypt:    s.GetBoolNoErr("crypt"),
		},
		ConfigConnAllow: s.GetBoolNoErr("config_conn_allow"),
		RateLimit:       s.GetIntNoErr("rate_limit"),
		MaxConn:         s.GetIntNoErr("max_conn"),
		WebUserName:     s.getEscapeString("web_username"),
		WebPassword:     s.getEscapeString("web_password"),
		MaxTunnelNum:    s.GetIntNoErr("max_tunnel"),
		Flow: &file.Flow{
			ExportFlow: 0,
			InletFlow:  0,
			FlowLimit:  int64(s.GetIntNoErr("flow_limit")),
		},
		BlackIpList: RemoveRepeatedElement(strings.Split(s.getEscapeString("blackiplist"), "\r\n")),
		IpWhite:     s.GetBoolNoErr("ipwhite"),
		IpWhitePass: s.getEscapeString("ipwhitepass"),
		IpWhiteList: RemoveRepeatedElement(strings.Split(s.getEscapeString("ipwhitelist"), "\r\n")),
		CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
	}
	if owner != nil {
		// Quotas and legacy web credentials stay under super-admin control.
		t.WebUserName = ""
		t.WebPassword = ""
		t.Flow.FlowLimit = 0
		t.RateLimit = 0
		t.MaxConn = 0
		t.MaxTunnelNum = 0
	}
	if err := file.GetDb().NewClient(t); err != nil {
		s.AjaxErr(err.Error())
		return
	}
	if owner != nil {
		if err := file.GetDb().AssignClientToUser(owner.Id, id); err != nil {
			_ = file.GetDb().DelClient(id)
			s.AjaxErr(err.Error())
			return
		}
		s.updateClientScope(id, 0)
	}
	s.AjaxOkWithId("add success", id)
}

func (s *ClientController) GetClient() {
	if s.Ctx.Request.Method == "POST" {
		id := s.GetIntNoErr("id")
		data := make(map[string]interface{})
		// This endpoint exposes the vkey, so ownership must be checked here
		// as well as in Prepare.
		if c, err := file.GetDb().GetClient(id); err != nil || !s.CanManageClient(id) {
			data["code"] = 0
		} else {
			data["code"] = 1
			data["data"] = c
		}
		s.Data["json"] = data
		s.ServeJSON()
	}
}

// 修改客户端
func (s *ClientController) Edit() {
	id := s.GetIntNoErr("id")
	if !s.CanManageClient(id) {
		s.AjaxErr("无权修改该客户端")
		return
	}
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "client"
		if c, err := file.GetDb().GetClient(id); err != nil {
			s.error()
		} else {
			s.Data["c"] = c
			s.Data["BlackIpList"] = strings.Join(c.BlackIpList, "\r\n")
			s.Data["IpWhiteList"] = strings.Join(c.IpWhiteList, "\r\n")
		}
		s.SetInfo("edit client")
		s.display()
	} else {
		if c, err := file.GetDb().GetClient(id); err != nil {
			s.error()
			s.AjaxErr("client ID not found")
			return
		} else {
			if s.IsSuperAdmin() {
				if s.getEscapeString("web_username") != "" {
					if s.getEscapeString("web_username") == beego.AppConfig.String("web_username") || !file.GetDb().VerifyUserName(s.getEscapeString("web_username"), c.Id) {
						s.AjaxErr("web login username duplicate, please reset")
						return
					}
				}
				if !file.GetDb().VerifyVkey(s.getEscapeString("vkey"), c.Id) {
					s.AjaxErr("Vkey duplicate, please reset")
					return
				}
				c.VerifyKey = s.getEscapeString("vkey")
				c.Flow.FlowLimit = int64(s.GetIntNoErr("flow_limit"))
				c.RateLimit = s.GetIntNoErr("rate_limit")
				c.MaxConn = s.GetIntNoErr("max_conn")
				c.MaxTunnelNum = s.GetIntNoErr("max_tunnel")
				c.WebUserName = s.getEscapeString("web_username")
				c.WebPassword = s.getEscapeString("web_password")
			}
			c.Remark = s.getEscapeString("remark")
			c.Cnf.U = s.getEscapeString("u")
			c.Cnf.P = s.getEscapeString("p")
			c.Cnf.Compress = common.GetBoolByStr(s.getEscapeString("compress"))
			c.Cnf.Crypt = s.GetBoolNoErr("crypt")
			// Normal users may tune their own connection settings, but never
			// the legacy web credentials or the quotas set by a super admin.
			c.ConfigConnAllow = s.GetBoolNoErr("config_conn_allow")
			c.IpWhite = s.GetBoolNoErr("ipwhite")
			c.IpWhitePass = s.getEscapeString("ipwhitepass")
			c.IpWhiteList = RemoveRepeatedElement(strings.Split(s.getEscapeString("ipwhitelist"), "\r\n"))
			if c.Rate != nil {
				c.Rate.Stop()
			}
			if c.RateLimit > 0 {
				c.Rate = rate.NewRate(int64(c.RateLimit * 1024))
				c.Rate.Start()
			} else {
				c.Rate = rate.NewRate(int64(2 << 23))
				c.Rate.Start()
			}

			c.BlackIpList = RemoveRepeatedElement(strings.Split(s.getEscapeString("blackiplist"), "\r\n"))
			file.GetDb().JsonDb.StoreClientsToJsonFile()
		}
		s.AjaxOk("save success")
	}
}

func RemoveRepeatedElement(arr []string) (newArr []string) {
	newArr = make([]string, 0)
	for i := 0; i < len(arr); i++ {
		// 过滤空IP
		if strings.TrimSpace(arr[i]) == "" {
			continue
		}
		repeat := false
		for j := i + 1; j < len(arr); j++ {
			if arr[i] == arr[j] {
				repeat = true
				break
			}
		}
		if !repeat {
			newArr = append(newArr, arr[i])
		}
	}
	return
}

// 更改状态
func (s *ClientController) ChangeStatus() {
	id := s.GetIntNoErr("id")
	if !s.CanManageClient(id) {
		s.AjaxErr("无权修改该客户端状态")
		return
	}
	if client, err := file.GetDb().GetClient(id); err == nil {
		client.Status = s.GetBoolNoErr("status")
		if client.Status == false {
			server.DelClientConnect(client.Id)
		}
		s.AjaxOk("modified success")
	}
	s.AjaxErr("modified fail")
}

// 删除客户端
func (s *ClientController) Del() {
	id := s.GetIntNoErr("id")
	if !s.CanManageClient(id) {
		s.AjaxErr("无权删除该客户端")
		return
	}
	if err := file.GetDb().DelClient(id); err != nil {
		s.AjaxErr("delete error")
		return
	}
	file.GetDb().UnassignClient(id)
	server.DelTunnelAndHostByClientId(id, false)
	server.DelClientConnect(id)
	s.updateClientScope(0, id)
	s.AjaxOk("delete success")
}
