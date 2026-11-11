package controllers

import (
	"strconv"
	"strings"
	"time"

	"ehang.io/nps/lib/file"
)

type UserController struct {
	BaseController
}

func allClientsForUser() []*file.Client {
	list, _ := file.GetDb().GetClientList(0, 10000, "", "", "", nil)
	return list
}

func parseClientIds(s *UserController) []int {
	_ = s.Ctx.Request.ParseForm()
	raw := s.Ctx.Request.Form["client_ids"]
	ids := make([]int, 0)
	seen := make(map[int]bool)
	for _, item := range raw {
		for _, part := range strings.Split(item, ",") {
			id, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil || id <= 0 || seen[id] {
				continue
			}
			if _, err := file.GetDb().GetClient(id); err != nil {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

func (s *UserController) List() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "user"
		s.SetInfo("user")
		s.display("user/list")
		return
	}
	if !s.RequireSuperAdmin() {
		return
	}
	start, length := s.GetAjaxParams()
	list, cnt := file.GetDb().GetUserList(start, length, s.getEscapeString("search"))
	s.AjaxTable(list, cnt, cnt, nil)
}

func (s *UserController) Add() {
	if !s.RequireSuperAdmin() {
		return
	}
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "user"
		s.Data["clients"] = allClientsForUser()
		s.Data["selected"] = map[int]bool{}
		s.SetInfo("add user")
		s.display()
		return
	}
	username := strings.TrimSpace(s.getEscapeString("username"))
	password := s.getEscapeString("password")
	if username == "" || password == "" {
		s.AjaxErr("username and password are required")
		return
	}
	u := &file.User{
		Username:   username,
		Role:       s.getEscapeString("role"),
		Status:     s.GetBoolNoErr("status", true),
		ClientIds:  parseClientIds(s),
		AllowPorts: strings.TrimSpace(s.getEscapeString("allow_ports")),
		Remark:     s.getEscapeString("remark"),
		CreateTime: time.Now().Format("2006-01-02 15:04:05"),
	}
	u.SetPassword(password)
	if err := file.GetDb().NewUser(u); err != nil {
		s.AjaxErr(err.Error())
		return
	}
	s.AjaxOk("add success")
}

func (s *UserController) Edit() {
	if !s.RequireSuperAdmin() {
		return
	}
	id := s.GetIntNoErr("id")
	u, err := file.GetDb().GetUser(id)
	if err != nil {
		s.AjaxErr(err.Error())
		return
	}
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "user"
		s.Data["u"] = u.Public()
		s.Data["clients"] = allClientsForUser()
		selected := make(map[int]bool)
		for _, cid := range u.ClientIds {
			selected[cid] = true
		}
		s.Data["selected"] = selected
		s.SetInfo("edit user")
		s.display()
		return
	}
	username := strings.TrimSpace(s.getEscapeString("username"))
	if username == "" {
		s.AjaxErr("username is required")
		return
	}
	role := s.getEscapeString("role")
	status := s.GetBoolNoErr("status", true)
	if u.IsSuperAdmin() && (role != file.RoleSuperAdmin || !status) && file.GetDb().CountSuperAdmins() <= 1 {
		s.AjaxErr("cannot demote or disable the last super admin")
		return
	}
	u.Username = username
	u.Role = role
	u.Status = status
	u.ClientIds = parseClientIds(s)
	u.AllowPorts = strings.TrimSpace(s.getEscapeString("allow_ports"))
	u.Remark = s.getEscapeString("remark")
	if pwd := s.getEscapeString("password"); pwd != "" {
		u.SetPassword(pwd)
	}
	if err := file.GetDb().UpdateUser(u); err != nil {
		s.AjaxErr(err.Error())
		return
	}
	s.AjaxOk("save success")
}

func (s *UserController) Del() {
	if !s.RequireSuperAdmin() {
		return
	}
	id := s.GetIntNoErr("id")
	if v := s.GetSession("userId"); v != nil {
		if current, ok := v.(int); ok && current == id {
			s.AjaxErr("cannot delete the current login user")
			return
		}
	}
	if err := file.GetDb().DelUser(id); err != nil {
		s.AjaxErr(err.Error())
		return
	}
	s.AjaxOk("delete success")
}

func (s *UserController) ChangeStatus() {
	if !s.RequireSuperAdmin() {
		return
	}
	id := s.GetIntNoErr("id")
	u, err := file.GetDb().GetUser(id)
	if err != nil {
		s.AjaxErr(err.Error())
		return
	}
	status := s.GetBoolNoErr("status")
	if u.IsSuperAdmin() && !status && file.GetDb().CountSuperAdmins() <= 1 {
		s.AjaxErr("cannot disable the last super admin")
		return
	}
	u.Status = status
	if err := file.GetDb().UpdateUser(u); err != nil {
		s.AjaxErr(err.Error())
		return
	}
	s.AjaxOk("modified success")
}
