package controllers

import (
	"fmt"

	"ehang.io/nps/lib/file"
	"ehang.io/nps/server"
	"ehang.io/nps/server/tool"

	"github.com/astaxie/beego"
)

type IndexController struct {
	BaseController
}

func (s *IndexController) Index() {
	s.Data["web_base_url"] = beego.AppConfig.String("web_base_url")
	s.Data["data"] = server.GetDashboardData()
	s.SetInfo("dashboard")
	s.display("index/index")
}
func (s *IndexController) Help() {
	s.SetInfo("about")
	s.display("index/help")
}

func (s *IndexController) Download() {
	s.SetInfo("download")
	s.Data["download_base_url"] = beego.AppConfig.String("web_base_url") + "/static/download"
	s.display("index/download")
}

func (s *IndexController) Tcp() {
	s.SetInfo("tcp")
	s.SetType("tcp")
	s.display("index/list")
}

func (s *IndexController) Udp() {
	s.SetInfo("udp")
	s.SetType("udp")
	s.display("index/list")
}

func (s *IndexController) Socks5() {
	s.SetInfo("socks5")
	s.SetType("socks5")
	s.display("index/list")
}

func (s *IndexController) Http() {
	s.SetInfo("http proxy")
	s.SetType("httpProxy")
	s.display("index/list")
}
func (s *IndexController) File() {
	s.SetInfo("file server")
	s.SetType("file")
	s.display("index/list")
}

func (s *IndexController) Secret() {
	s.SetInfo("secret")
	s.SetType("secret")
	s.display("index/list")
}
func (s *IndexController) P2p() {
	s.SetInfo("p2p")
	s.SetType("p2p")
	s.display("index/list")
}

func (s *IndexController) Host() {
	s.SetInfo("host")
	s.SetType("hostServer")
	s.display("index/list")
}

func (s *IndexController) All() {
	s.Data["menu"] = "client"
	clientId := s.getEscapeString("client_id")
	s.Data["client_id"] = clientId
	s.SetInfo("client id:" + clientId)
	s.display("index/list")
}

func (s *IndexController) GetTunnel() {
	start, length := s.GetAjaxParams()
	taskType := s.getEscapeString("type")
	clientIds := s.RequestClientIds()
	list, cnt := server.GetTunnel(start, length, taskType, clientIds, s.getEscapeString("search"), s.getEscapeString("sort"), s.getEscapeString("order"))
	s.AjaxTable(list, cnt, cnt, nil)
}

func (s *IndexController) Add() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["type"] = s.getEscapeString("type")
		s.Data["client_id"] = s.getEscapeString("client_id")
		s.SetInfo("add tunnel")
		s.display()
	} else {
		id := int(file.GetDb().JsonDb.GetTaskId())
		t := &file.Tunnel{
			Port:         s.GetIntNoErr("port"),
			ServerIp:     s.getEscapeString("server_ip"),
			Mode:         s.getEscapeString("type"),
			Target:       &file.Target{TargetStr: s.getEscapeString("target"), LocalProxy: s.GetBoolNoErr("local_proxy")},
			Id:           id,
			Status:       true,
			Remark:       s.getEscapeString("remark"),
			Password:     s.getEscapeString("password"),
			LocalPath:    s.getEscapeString("local_path"),
			StripPre:     s.getEscapeString("strip_pre"),
			ProtoVersion: s.getEscapeString("proto_version"),
			Flow:         &file.Flow{},
		}

		var err error
		if t.Client, err = file.GetDb().GetClient(s.GetIntNoErr("client_id")); err != nil {
			s.AjaxErr(err.Error())
			return
		}

		pool := file.GetPortPool()
		if t.Port <= 0 {
			// Blank port: rent a random port from the shared pool, or fall
			// back to this user's exclusive block when the pool is exhausted.
			port, fromPool := tool.GenerateServerPort(t.Mode, s.CurrentUser(), t.Client, id)
			if port <= 0 {
				s.AjaxErr("No available port: the shared pool and your exclusive block are both full.")
				return
			}
			t.Port = port
			if fromPool {
				// A newly rented port can be pinned right away: it then keeps
				// this exact number forever instead of being recycled.
				if s.GetBoolNoErr("pin_port") {
					t.PortPool = file.PortFromFixed
				} else {
					t.PortPool = file.PortFromShared
				}
			}
		} else if pool.Enabled() && pool.InSharedRange(t.Port) {
			s.AjaxErr("Ports in the shared range are assigned automatically; leave the port blank or use your own exclusive block.")
			return
		}
		if !tool.TestServerPort(t.Port, t.Mode, s.CurrentUser(), t.Client) {
			pool.AbortShared(id)
			s.AjaxErr("The port cannot be opened because it may has been occupied or is no longer allowed.")
			return
		}
		if t.Client.MaxTunnelNum != 0 && t.Client.GetTunnelNum() >= t.Client.MaxTunnelNum {
			pool.AbortShared(id)
			s.AjaxErr("The number of tunnels exceeds the limit")
			return
		}
		if err := file.GetDb().NewTask(t); err != nil {
			pool.AbortShared(id)
			s.AjaxErr(err.Error())
			return
		}
		if err := server.AddTask(t, s.CurrentUser()); err != nil {
			pool.AbortShared(id)
			// Roll back the half-created task so it cannot keep a pool port busy.
			_ = file.GetDb().DelTask(id)
			s.AjaxErr(err.Error())
			return
		}
		pool.CommitShared(id)
		s.AjaxOkWithId("add success", id)
	}
}

func (s *IndexController) Copy() {
	oldId := s.GetIntNoErr("id")
	if oldTask, err := file.GetDb().GetTask(oldId); err != nil {
		s.error()
		return
	} else {
		if client, err := file.GetDb().GetClient(oldTask.Client.Id); err != nil {
			s.AjaxErr("modified error,the client is not exist")
			return
		} else {
			oldTask.Client = client
		}

		id := int(file.GetDb().JsonDb.GetTaskId())
		pool := file.GetPortPool()
		copyPort, fromPool := tool.GenerateServerPort(oldTask.Mode, s.CurrentUser(), oldTask.Client, id)
		if copyPort <= 0 {
			s.AjaxErr("No available port: the shared pool and your exclusive block are both full.")
			return
		}
		newTask := &file.Tunnel{
			Client:       oldTask.Client,
			Port:         copyPort,
			ServerIp:     oldTask.ServerIp,
			Mode:         oldTask.Mode,
			Target:       oldTask.Target,
			Id:           id,
			Status:       true,
			Remark:       oldTask.Remark,
			Password:     oldTask.Password,
			LocalPath:    oldTask.LocalPath,
			StripPre:     oldTask.StripPre,
			ProtoVersion: oldTask.ProtoVersion,
			Flow:         &file.Flow{},
		}
		if fromPool {
			newTask.PortPool = file.PortFromShared
		}
		if !tool.TestServerPort(newTask.Port, newTask.Mode, s.CurrentUser(), newTask.Client) {
			pool.AbortShared(id)
			s.AjaxErr("The port cannot be opened because it may has been occupied or is no longer allowed.")
			return
		}

		if newTask.Client.MaxTunnelNum != 0 && newTask.Client.GetTunnelNum() >= newTask.Client.MaxTunnelNum {
			pool.AbortShared(id)
			s.AjaxErr("The number of tunnels exceeds the limit")
			return
		}
		if err := file.GetDb().NewTask(newTask); err != nil {
			pool.AbortShared(id)
			s.AjaxErr(err.Error())
			return
		}
		if err := server.AddTask(newTask, s.CurrentUser()); err != nil {
			pool.AbortShared(id)
			_ = file.GetDb().DelTask(id)
			s.AjaxErr(err.Error())
			return
		}
		pool.CommitShared(id)
		s.AjaxOkWithId("add success", id)
	}
}

func (s *IndexController) GetOneTunnel() {
	id := s.GetIntNoErr("id")
	data := make(map[string]interface{})
	if t, err := file.GetDb().GetTask(id); err != nil {
		data["code"] = 0
	} else {
		data["code"] = 1
		data["data"] = t
	}
	s.Data["json"] = data
	s.ServeJSON()
}
func (s *IndexController) Edit() {
	id := s.GetIntNoErr("id")
	if s.Ctx.Request.Method == "GET" {
		if t, err := file.GetDb().GetTask(id); err != nil {
			s.error()
			return
		} else {
			s.Data["t"] = t
		}
		s.SetInfo("edit tunnel")
		s.display()
	} else {
		if t, err := file.GetDb().GetTask(id); err != nil {
			s.error()
			return
		} else {
			if client, err := file.GetDb().GetClient(s.GetIntNoErr("client_id")); err != nil {
				s.AjaxErr("modified error,the client is not exist")
				return
			} else {
				t.Client = client
			}
			pool := file.GetPortPool()
			requestedPort := s.GetIntNoErr("port")
			if requestedPort != t.Port {
				if requestedPort <= 0 {
					port, fromPool := tool.GenerateServerPort(t.Mode, s.CurrentUser(), t.Client, id)
					if port <= 0 {
						s.AjaxErr("No available port: the shared pool and your exclusive block are both full.")
						return
					}
					t.Port = port
					if fromPool {
						t.PortPool = file.PortFromShared
					} else {
						t.PortPool = ""
					}
				} else {
					if pool.Enabled() && pool.InSharedRange(requestedPort) && requestedPort != t.Port {
						s.AjaxErr("Ports in the shared range are assigned automatically; leave the port blank or use your own exclusive block.")
						return
					}
					t.Port = requestedPort
					t.PortPool = ""
				}

				if !tool.TestServerPort(t.Port, t.Mode, s.CurrentUser(), t.Client) {
					pool.AbortShared(id)
					s.AjaxErr("The port cannot be opened because it may has been occupied or is no longer allowed.")
					return
				}
			}
			// Converting a random shared port into a permanent fixed port is
			// allowed both from the edit form and the list button. PinShared
			// checks for conflicts and flips the flag on the live tunnel.
			if s.GetBoolNoErr("pin_port") && t.PortPool == file.PortFromShared {
				if _, err := pool.PinShared(id); err != nil {
					s.AjaxErr(err.Error())
					return
				}
			}
			t.ServerIp = s.getEscapeString("server_ip")
			t.Mode = s.getEscapeString("type")
			t.Target = &file.Target{TargetStr: s.getEscapeString("target")}
			t.Password = s.getEscapeString("password")
			t.Id = id
			t.LocalPath = s.getEscapeString("local_path")
			t.ProtoVersion = s.getEscapeString("proto_version")
			t.StripPre = s.getEscapeString("strip_pre")
			t.Remark = s.getEscapeString("remark")
			t.Target.LocalProxy = s.GetBoolNoErr("local_proxy")
			file.GetDb().UpdateTask(t)
			server.StopServer(t.Id)
			// StopServer returns the shared port to the pool. Hold it again
			// during the restart so a concurrent request cannot grab it.
			if t.PortPool == file.PortFromShared {
				userId := 0
				if u := s.CurrentUser(); u != nil {
					userId = u.Id
				}
				pool.HoldShared(id, t.Port, userId)
			}
			server.StartTask(t.Id, s.CurrentUser(), false)
			pool.CommitShared(id)
		}
		s.AjaxOk("modified success")
	}
}

func (s *IndexController) Stop() {
	id := s.GetIntNoErr("id")
	if err := server.StopServer(id); err != nil {
		s.AjaxErr("stop error")
		return
	}
	s.AjaxOk("stop success")
}

func (s *IndexController) Del() {
	id := s.GetIntNoErr("id")
	if err := server.DelTask(id); err != nil {
		s.AjaxErr("delete error")
	}
	s.AjaxOk("delete success")
}

func (s *IndexController) Start() {
	id := s.GetIntNoErr("id")
	if err := server.StartTask(id, s.CurrentUser(), true); err != nil {
		s.AjaxErr("start error")
	}
	s.AjaxOk("start success")
}

// PinPort converts a randomly rented shared port into a permanent fixed port
// (action=pin), or turns it back into a temporary lease (action=unpin).
// The port number itself never changes and the service does not need a
// restart: the flag is persisted on the tunnel and the allocator immediately
// starts treating it as permanently reserved.
func (s *IndexController) PinPort() {
	if s.Ctx.Request.Method != "POST" {
		s.AjaxErr("invalid request")
		return
	}
	id := s.GetIntNoErr("id")
	t, err := file.GetDb().GetTask(id)
	if err != nil || t == nil {
		s.AjaxErr("tunnel not found")
		return
	}
	if t.Client == nil || !s.CanManageClient(t.Client.Id) {
		s.AjaxErr("permission denied")
		return
	}
	pool := file.GetPortPool()
	action := s.getEscapeString("action")
	var port int
	if action == "unpin" {
		port, err = pool.UnpinShared(id)
	} else {
		port, err = pool.PinShared(id)
	}
	if err != nil {
		s.AjaxErr(err.Error())
		return
	}
	if err := file.GetDb().UpdateTask(t); err != nil {
		s.AjaxErr(err.Error())
		return
	}
	if action == "unpin" {
		s.AjaxOk(fmt.Sprintf("port %d is temporary again", port))
		return
	}
	s.AjaxOk(fmt.Sprintf("port %d is now fixed and never expires", port))
}

func (s *IndexController) HostList() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["client_id"] = s.getEscapeString("client_id")
		s.Data["menu"] = "host"
		s.SetInfo("host list")
		s.display("index/hlist")
	} else {
		start, length := s.GetAjaxParams()
		clientIds := s.RequestClientIds()
		list, cnt := file.GetDb().GetHost(start, length, clientIds, s.getEscapeString("search"))
		s.AjaxTable(list, cnt, cnt, nil)
	}
}

func (s *IndexController) GetHost() {
	if s.Ctx.Request.Method == "POST" {
		data := make(map[string]interface{})
		if h, err := file.GetDb().GetHostById(s.GetIntNoErr("id")); err != nil {
			data["code"] = 0
		} else {
			data["data"] = h
			data["code"] = 1
		}
		s.Data["json"] = data
		s.ServeJSON()
	}
}

func (s *IndexController) DelHost() {
	id := s.GetIntNoErr("id")
	if err := file.GetDb().DelHost(id); err != nil {
		s.AjaxErr("delete error")
	}
	s.AjaxOk("delete success")
}

func (s *IndexController) AddHost() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["client_id"] = s.getEscapeString("client_id")
		s.Data["menu"] = "host"
		s.SetInfo("add host")
		s.display("index/hadd")
	} else {
		id := int(file.GetDb().JsonDb.GetHostId())
		h := &file.Host{
			Id:           id,
			Host:         s.getEscapeString("host"),
			Target:       &file.Target{TargetStr: s.getEscapeString("target"), LocalProxy: s.GetBoolNoErr("local_proxy")},
			HeaderChange: s.getEscapeString("header"),
			HostChange:   s.getEscapeString("hostchange"),
			Remark:       s.getEscapeString("remark"),
			Location:     s.getEscapeString("location"),
			Flow:         &file.Flow{},
			Scheme:       s.getEscapeString("scheme"),
			KeyFilePath:  s.getEscapeString("key_file_path"),
			CertFilePath: s.getEscapeString("cert_file_path"),
			AutoHttps:    s.GetBoolNoErr("AutoHttps"),
		}

		if h.Scheme == "http" {
			h.AutoHttps = false
		}

		var err error
		if h.Client, err = file.GetDb().GetClient(s.GetIntNoErr("client_id")); err != nil {
			s.AjaxErr("add error the client can not be found")
		}
		if h.Client.MaxTunnelNum != 0 && h.Client.GetTunnelNum() >= h.Client.MaxTunnelNum {
			s.AjaxErr("The number of tunnels exceeds the limit")
		}

		if err := file.GetDb().NewHost(h); err != nil {
			s.AjaxErr("add fail" + err.Error())
		}
		s.AjaxOkWithId("add success", id)
	}
}

func (s *IndexController) EditHost() {
	id := s.GetIntNoErr("id")
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "host"
		if h, err := file.GetDb().GetHostById(id); err != nil {
			s.error()
		} else {
			s.Data["h"] = h
		}
		s.SetInfo("edit")
		s.display("index/hedit")
	} else {
		if h, err := file.GetDb().GetHostById(id); err != nil {
			s.error()
		} else {
			if h.Host != s.getEscapeString("host") {
				tmpHost := new(file.Host)
				tmpHost.Host = s.getEscapeString("host")
				tmpHost.Location = s.getEscapeString("location")
				tmpHost.Scheme = s.getEscapeString("scheme")
				if file.GetDb().IsHostExist(tmpHost) {
					s.AjaxErr("host has exist")
					return
				}
			}
			if client, err := file.GetDb().GetClient(s.GetIntNoErr("client_id")); err != nil {
				s.AjaxErr("modified error,the client is not exist")
			} else {
				h.Client = client
			}
			h.Host = s.getEscapeString("host")
			h.Target = &file.Target{TargetStr: s.getEscapeString("target")}
			h.HeaderChange = s.getEscapeString("header")
			h.HostChange = s.getEscapeString("hostchange")
			h.Remark = s.getEscapeString("remark")
			h.Location = s.getEscapeString("location")
			h.Scheme = s.getEscapeString("scheme")
			h.KeyFilePath = s.getEscapeString("key_file_path")
			h.CertFilePath = s.getEscapeString("cert_file_path")
			h.Target.LocalProxy = s.GetBoolNoErr("local_proxy")
			h.AutoHttps = s.GetBoolNoErr("AutoHttps")

			if h.Scheme == "http" {
				h.AutoHttps = false
			}

			file.GetDb().JsonDb.StoreHostToJsonFile()
		}
		s.AjaxOk("modified success")
	}
}
