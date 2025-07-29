package bridge

import (
	"crypto/tls"
	_ "crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"ehang.io/nps/lib/nps_mux"

	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/conn"
	"ehang.io/nps/lib/crypt"
	"ehang.io/nps/lib/file"
	"ehang.io/nps/lib/version"
	"ehang.io/nps/server/connection"
	"ehang.io/nps/server/tool"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
)

var ServerTlsEnable bool = false

type Client struct {
	tunnel    *nps_mux.Mux
	signal    *conn.Conn
	file      *nps_mux.Mux
	Version   string
	retryTime int // it will be add 1 when ping not ok until to 3 will close the client
}

func NewClient(t, f *nps_mux.Mux, s *conn.Conn, vs string) *Client {
	return &Client{
		signal:  s,
		tunnel:  t,
		file:    f,
		Version: vs,
	}
}

type Bridge struct {
	TunnelPort     int //通信隧道端口
	Client         sync.Map
	Register       sync.Map
	tunnelType     string //bridge type kcp or tcp
	OpenTask       chan *file.Tunnel
	CloseTask      chan *file.Tunnel
	CloseClient    chan int
	SecretChan     chan *conn.Secret
	ipVerify       bool
	runList        sync.Map //map[int]interface{}
	disconnectTime int
}

func NewTunnel(tunnelPort int, tunnelType string, ipVerify bool, runList sync.Map, disconnectTime int) *Bridge {
	return &Bridge{
		TunnelPort:     tunnelPort,
		tunnelType:     tunnelType,
		OpenTask:       make(chan *file.Tunnel),
		CloseTask:      make(chan *file.Tunnel),
		CloseClient:    make(chan int),
		SecretChan:     make(chan *conn.Secret),
		ipVerify:       ipVerify,
		runList:        runList,
		disconnectTime: disconnectTime,
	}
}

func (s *Bridge) StartTunnel() error {
	go s.ping()
	if s.tunnelType == "kcp" {
		logs.Info("server start, the bridge type is %s, the bridge port is %d", s.tunnelType, s.TunnelPort)
		return conn.NewKcpListenerAndProcess(beego.AppConfig.String("bridge_ip")+":"+beego.AppConfig.String("bridge_port"), func(c net.Conn) {
			s.cliProcess(conn.NewConn(c))
		})
	} else {

		go func() {
			listener, err := connection.GetBridgeListener(s.tunnelType)
			if err != nil {
				logs.Error(err)
				os.Exit(0)
				return
			}
			conn.Accept(listener, func(c net.Conn) {
				s.cliProcess(conn.NewConn(c))
			})
		}()

		// tls
		if ServerTlsEnable {
			go func() {
				// 监听TLS 端口
				tlsBridgePort := beego.AppConfig.DefaultInt("tls_bridge_port", 8025)

				logs.Info("tls server start, the bridge type is %s, the tls bridge port is %d", "tcp", tlsBridgePort)
				tlsListener, tlsErr := net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP(beego.AppConfig.String("bridge_ip")), tlsBridgePort, ""})
				if tlsErr != nil {
					logs.Error(tlsErr)
					os.Exit(0)
					return
				}
				conn.Accept(tlsListener, func(c net.Conn) {
					s.cliProcess(conn.NewConn(tls.Server(c, &tls.Config{Certificates: []tls.Certificate{crypt.GetCert()}})))
				})
			}()
		}
	}
	return nil
}

// get health information form client
func (s *Bridge) GetHealthFromClient(id int, c *conn.Conn) {
	for {
		if info, status, err := c.GetHealthInfo(); err != nil {
			break
		} else if !status { //the status is true , return target to the targetArr
			file.GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
				v := value.(*file.Tunnel)
				if v.Client.Id == id && v.Mode == "tcp" && strings.Contains(v.Target.TargetStr, info) {
					v.Lock()
					if v.Target.TargetArr == nil || (len(v.Target.TargetArr) == 0 && len(v.HealthRemoveArr) == 0) {
						v.Target.TargetArr = common.TrimArr(strings.Split(v.Target.TargetStr, "\n"))
					}
					v.Target.TargetArr = common.RemoveArrVal(v.Target.TargetArr, info)
					if v.HealthRemoveArr == nil {
						v.HealthRemoveArr = make([]string, 0)
					}
					v.HealthRemoveArr = append(v.HealthRemoveArr, info)
					v.Unlock()
				}
				return true
			})
			file.GetDb().JsonDb.Hosts.Range(func(key, value interface{}) bool {
				v := value.(*file.Host)
				if v.Client.Id == id && strings.Contains(v.Target.TargetStr, info) {
					v.Lock()
					if v.Target.TargetArr == nil || (len(v.Target.TargetArr) == 0 && len(v.HealthRemoveArr) == 0) {
						v.Target.TargetArr = common.TrimArr(strings.Split(v.Target.TargetStr, "\n"))
					}
					v.Target.TargetArr = common.RemoveArrVal(v.Target.TargetArr, info)
					if v.HealthRemoveArr == nil {
						v.HealthRemoveArr = make([]string, 0)
					}
					v.HealthRemoveArr = append(v.HealthRemoveArr, info)
					v.Unlock()
				}
				return true
			})
		} else { //the status is false,remove target from the targetArr
			file.GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
				v := value.(*file.Tunnel)
				if v.Client.Id == id && v.Mode == "tcp" && common.IsArrContains(v.HealthRemoveArr, info) && !common.IsArrContains(v.Target.TargetArr, info) {
					v.Lock()
					v.Target.TargetArr = append(v.Target.TargetArr, info)
					v.HealthRemoveArr = common.RemoveArrVal(v.HealthRemoveArr, info)
					v.Unlock()
				}
				return true
			})

			file.GetDb().JsonDb.Hosts.Range(func(key, value interface{}) bool {
				v := value.(*file.Host)
				if v.Client.Id == id && common.IsArrContains(v.HealthRemoveArr, info) && !common.IsArrContains(v.Target.TargetArr, info) {
					v.Lock()
					v.Target.TargetArr = append(v.Target.TargetArr, info)
					v.HealthRemoveArr = common.RemoveArrVal(v.HealthRemoveArr, info)
					v.Unlock()
				}
				return true
			})
		}
	}
	s.DelClient(id)
}

// 验证失败，返回错误验证flag，并且关闭连接
func (s *Bridge) verifyError(c *conn.Conn) {
	c.Write([]byte(common.VERIFY_EER))
}

func (s *Bridge) verifySuccess(c *conn.Conn) {
	c.Write([]byte(common.VERIFY_SUCCESS))
	// 尝试刷新连接确保数据发送
	if flusher, ok := c.Conn.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			logs.Warn("=== SERVER: Failed to flush connection after sending verification success: %s", err.Error())
		} else {
			logs.Info("=== SERVER: Successfully flushed connection after sending verification success")
		}
	}
}

func (s *Bridge) cliProcess(c *conn.Conn) {
	// 设置读取超时，避免长时间阻塞，增加超时时间到15秒
	c.SetReadDeadlineBySecond(15)
	logs.Info("=== SERVER: Starting cliProcess for client: %s ===", c.Conn.RemoteAddr().String())

	//read test flag
	buf := make([]byte, 3)
	logs.Info("=== SERVER: Step 1 - Reading CONN_TEST flag from client: %s", c.Conn.RemoteAddr().String())
	if _, err := c.Read(buf); err != nil {
		logs.Info("=== SERVER: The client %s connect error: failed to read test flag - %s", c.Conn.RemoteAddr(), err.Error())
		c.Close()
		return
	} else if string(buf) != common.CONN_TEST {
		logs.Info("=== SERVER: The client %s connect error: test flag not match, got %s, expected %s", c.Conn.RemoteAddr(), string(buf), common.CONN_TEST)
		c.Close()
		return
	}
	logs.Info("=== SERVER: Successfully read CONN_TEST flag from client: %s", c.Conn.RemoteAddr().String())

	// 重置读取超时，增加超时时间到15秒
	c.SetReadDeadlineBySecond(15)

	//version check
	logs.Info("=== SERVER: Step 2 - Reading client version from client: %s", c.Conn.RemoteAddr().String())
	logs.Info("=== SERVER: Connection state before reading client version - Local: %s, Remote: %s", c.Conn.LocalAddr().String(), c.Conn.RemoteAddr().String())
	
	// 使用更直接的方式读取客户端版本，避免使用GetShortLenContent方法
	// 先读取长度（4字节小端序）
	lenBuf := make([]byte, 4)
	if _, err := c.Read(lenBuf); err != nil {
		logs.Info("=== SERVER: Failed to read client version length from client %s: %s", c.Conn.RemoteAddr(), err.Error())
		c.Close()
		return
	}
	
	versionLen := binary.LittleEndian.Uint32(lenBuf)
	logs.Info("=== SERVER: Client version length: %d", versionLen)
	
	// 再读取版本内容
	if versionLen > 32<<10 {
		logs.Info("=== SERVER: Client version length too large: %d", versionLen)
		c.Close()
		return
	}
	
	versionBuf := make([]byte, versionLen)
	if _, err := c.Read(versionBuf); err != nil {
		logs.Info("=== SERVER: Failed to read client version content from client %s: %s", c.Conn.RemoteAddr(), err.Error())
		c.Close()
		return
	}
	
	b := versionBuf
	clientVersion := string(b)
	logs.Info("=== SERVER: Client %s reported version: %s, server version: %s", c.Conn.RemoteAddr(), clientVersion, version.GetVersion())
	
	if clientVersion != version.GetVersion() {
		// Check if client version is compatible (equal or greater than minimum required version)
		minRequiredVersion := version.GetVersion()
		if !s.isVersionCompatible(clientVersion, minRequiredVersion) {
			logs.Info("=== SERVER: The client %s version %s is not compatible. Minimum required version is %s",
				c.Conn.RemoteAddr(), clientVersion, minRequiredVersion)
			c.Close()
			return
		}
		logs.Info("=== SERVER: The client %s version %s is compatible with server", c.Conn.RemoteAddr(), clientVersion)
	}

	// 重置读取超时
	c.SetReadDeadlineBySecond(10)

	//version get
	logs.Info("=== SERVER: Step 3 - Reading client detailed version from client: %s", c.Conn.RemoteAddr().String())
	
	// 使用更直接的方式读取客户端详细版本，避免使用GetShortLenContent方法
	// 先读取长度（4字节小端序）
	var lenBuf2 []byte
	lenBuf2 = make([]byte, 4)
	if _, err := c.Read(lenBuf2); err != nil {
		logs.Info("=== SERVER: Failed to read client detailed version length from client %s: %s", c.Conn.RemoteAddr(), err.Error())
		c.Close()
		return
	}
	
	detailedVersionLen := binary.LittleEndian.Uint32(lenBuf2)
	logs.Info("=== SERVER: Client detailed version length: %d", detailedVersionLen)
	
	// 再读取版本内容
	if detailedVersionLen > 32<<10 {
		logs.Info("=== SERVER: Client detailed version length too large: %d", detailedVersionLen)
		c.Close()
		return
	}
	
	detailedVersionBuf := make([]byte, detailedVersionLen)
	if _, err := c.Read(detailedVersionBuf); err != nil {
		logs.Info("=== SERVER: Failed to read client detailed version content from client %s: %s", c.Conn.RemoteAddr(), err.Error())
		c.Close()
		return
	}
	
	vs := detailedVersionBuf
	logs.Info("=== SERVER: Client %s detailed version: %s", c.Conn.RemoteAddr(), string(vs))

	//write server version to client
	serverVersion := version.GetVersion()
	versionHash := crypt.Md5(serverVersion)
	logs.Info("=== SERVER: Step 4 - Preparing to send server version hash to client %s. Server version: %s, Hash: %s, Hash length: %d", 
		c.Conn.RemoteAddr(), serverVersion, versionHash, len(versionHash))
	
	// 确保我们发送的是32字节的哈希值
	hashBytes := []byte(versionHash)
	logs.Info("=== SERVER: Hash bytes length: %d, Hash bytes: %v", len(hashBytes), hashBytes)
	
	logs.Info("=== SERVER: Sending server version hash to client: %s", c.Conn.RemoteAddr().String())
	if _, err := c.Write(hashBytes); err != nil {
		logs.Info("=== SERVER: Failed to write server version hash to client %s: %s", c.Conn.RemoteAddr(), err.Error())
		c.Close()
		return
	}
	
	// 尝试刷新连接确保数据发送
	if flusher, ok := c.Conn.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			logs.Warn("=== SERVER: Failed to flush connection to client %s: %s", c.Conn.RemoteAddr(), err.Error())
		} else {
			logs.Info("=== SERVER: Successfully flushed connection to client %s", c.Conn.RemoteAddr())
		}
	}
	
	logs.Info("=== SERVER: Successfully sent server version hash to client: %s", c.Conn.RemoteAddr().String())

	// 重置读取超时，避免影响后续读取操作
	c.SetReadDeadlineBySecond(15) // 增加超时时间到15秒

	//get vKey from client
	logs.Info("=== SERVER: Step 5 - Reading vKey from client: %s", c.Conn.RemoteAddr().String())
	
	// 直接读取32字节的vKey，而不是使用GetShortContent方法
	bufContent := make([]byte, 32)
	if _, err2 := c.Read(bufContent); err2 != nil {
		logs.Info("=== SERVER: Failed to read vKey from client %s: %s", c.Conn.RemoteAddr(), err2.Error())
		c.Close()
		return
	}
	logs.Info("=== SERVER: Successfully read vKey from client: %s, vKey: %.10s...", c.Conn.RemoteAddr(), string(bufContent)) // 只记录前10个字符以保护隐私

	//verify
	logs.Info("=== SERVER: Step 6 - Verifying client: %s", c.Conn.RemoteAddr().String())
	id, err := file.GetDb().GetIdByVerifyKey(string(bufContent), c.Conn.RemoteAddr().String())
	if err != nil {
		logs.Info("=== SERVER: Current client connection validation error, close this client: %s, vkey: %.10s..., error: %s", 
			c.Conn.RemoteAddr(), string(bufContent), err.Error())
		logs.Info("=== SERVER: Sending verification error response to client: %s", c.Conn.RemoteAddr().String())
		s.verifyError(c)
		logs.Info("=== SERVER: Successfully sent verification error response to client: %s", c.Conn.RemoteAddr().String())
		return
	} else {
		logs.Info("=== SERVER: Client verification successful for client: %s, clientId: %d", c.Conn.RemoteAddr(), id)
		logs.Info("=== SERVER: Sending verification success response to client: %s", c.Conn.RemoteAddr().String())
		s.verifySuccess(c)
		logs.Info("=== SERVER: Successfully sent verification success response to client: %s", c.Conn.RemoteAddr().String())
		
		// 添加短暂延迟，确保客户端有足够时间接收响应
		time.Sleep(100 * time.Millisecond)
		
		// 尝试刷新连接确保数据发送
		if flusher, ok := c.Conn.(interface{ Flush() error }); ok {
			if err := flusher.Flush(); err != nil {
				logs.Warn("=== SERVER: Failed to flush connection after sending verification success: %s", err.Error())
			} else {
				logs.Info("=== SERVER: Successfully flushed connection after sending verification success")
			}
		}

	// 设置读取超时
	c.SetReadDeadlineBySecond(15) // 增加超时时间到15秒

	logs.Info("=== SERVER: Step 7 - Reading connection flag from client: %s", c.Conn.RemoteAddr().String())
	// 直接读取4字节的连接标志，而不是使用ReadFlag方法
	buf := make([]byte, 4)
	if _, err := c.Read(buf); err != nil {
		logs.Warn("=== SERVER: Failed to read flag from client %s: %s", c.Conn.RemoteAddr(), err.Error())
		// 添加更多调试信息
		logs.Info("=== SERVER: Connection state - Local: %s, Remote: %s", c.Conn.LocalAddr().String(), c.Conn.RemoteAddr().String())
		c.Close()
		return
	}
	
	flag := string(buf)
	logs.Info("=== SERVER: Received connection flag from client %s: %s", c.Conn.RemoteAddr(), flag)
	s.typeDeal(flag, c, id, string(vs))
	logs.Info("=== SERVER: Finished cliProcess for client: %s", c.Conn.RemoteAddr().String())
	return
	}
	
	// 添加更多调试信息
	logs.Info("=== SERVER: Connection state - Local: %s, Remote: %s", c.Conn.LocalAddr().String(), c.Conn.RemoteAddr().String())
	c.Close()
	return
}

// isVersionCompatible checks if the client version is compatible with the server
// For now, we simply check if client version is equal or greater than minimum required version
func (s *Bridge) isVersionCompatible(clientVersion, minRequiredVersion string) bool {
	// Allow all 0.26.x versions to connect
	if strings.HasPrefix(clientVersion, "0.26.") {
		return true
	}

	// Parse versions
	clientParts := parseVersion(clientVersion)
	serverParts := parseVersion(minRequiredVersion)

	// Compare version parts
	for i := 0; i < len(clientParts) && i < len(serverParts); i++ {
		if clientParts[i] > serverParts[i] {
			return true
		}
		if clientParts[i] < serverParts[i] {
			return false
		}
	}

	// If all compared parts are equal, the versions are compatible
	return true
}

// isDataAvailable checks if there is data available to read from the connection
// This helps prevent EOF errors when the client disconnects unexpectedly
func (s *Bridge) isDataAvailable(c *conn.Conn) bool {
	// For now, we'll always return true to allow the connection to proceed
	// In the future, we could implement a more sophisticated check if needed
	return true
}

// parseVersion parses a version string into integer components
func parseVersion(version string) []int {
	parts := strings.Split(version, ".")
	result := make([]int, len(parts))

	for i, part := range parts {
		if num, err := strconv.Atoi(part); err == nil {
			result[i] = num
		} else {
			// In case of non-numeric parts, truncate the version
			result = result[:i]
			break
		}
	}

	return result
}

func (s *Bridge) DelClient(id int) {
	if v, ok := s.Client.Load(id); ok {
		if v.(*Client).signal != nil {
			v.(*Client).signal.Close()
		}
		s.Client.Delete(id)
		if file.GetDb().IsPubClient(id) {
			return
		}
		if c, err := file.GetDb().GetClient(id); err == nil {
			s.CloseClient <- c.Id
		}
	}
}

// use different
func (s *Bridge) typeDeal(typeVal string, c *conn.Conn, id int, vs string) {
	isPub := file.GetDb().IsPubClient(id)
	switch typeVal {
	case common.WORK_MAIN:
		if isPub {
			c.Close()
			return
		}
		tcpConn, ok := c.Conn.(*net.TCPConn)
		if ok {
			// add tcp keep alive option for signal connection
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(5 * time.Second)
		}
		//the vKey connect by another ,close the client of before
		if v, ok := s.Client.LoadOrStore(id, NewClient(nil, nil, c, vs)); ok {
			if v.(*Client).signal != nil {
				v.(*Client).signal.WriteClose()
			}
			v.(*Client).signal = c
			v.(*Client).Version = vs
		}
		go s.GetHealthFromClient(id, c)
		logs.Info("clientId %d connection succeeded, address:%s ", id, c.Conn.RemoteAddr())
	case common.WORK_CHAN:
		muxConn := nps_mux.NewMux(c.Conn, s.tunnelType, s.disconnectTime)
		if v, ok := s.Client.LoadOrStore(id, NewClient(muxConn, nil, nil, vs)); ok {
			v.(*Client).tunnel = muxConn
		}
	case common.WORK_CONFIG:
		client, err := file.GetDb().GetClient(id)
		if err != nil || (!isPub && !client.ConfigConnAllow) {
			c.Close()
			return
		}
		binary.Write(c, binary.LittleEndian, isPub)
		go s.getConfig(c, isPub, client)
	case common.WORK_REGISTER:
		go s.register(c)
	case common.WORK_SECRET:
		if b, err := c.GetShortContent(32); err == nil {
			s.SecretChan <- conn.NewSecret(string(b), c)
		} else {
			logs.Error("secret error, failed to match the key successfully")
		}
	case common.WORK_FILE:
		muxConn := nps_mux.NewMux(c.Conn, s.tunnelType, s.disconnectTime)
		if v, ok := s.Client.LoadOrStore(id, NewClient(nil, muxConn, nil, vs)); ok {
			v.(*Client).file = muxConn
		}
	case common.WORK_P2P:
		//read md5 secret
		if b, err := c.GetShortContent(32); err != nil {
			logs.Error("p2p error,", err.Error())
		} else if t := file.GetDb().GetTaskByMd5Password(string(b)); t == nil {
			logs.Error("p2p error, failed to match the key successfully")
		} else {
			if v, ok := s.Client.Load(t.Client.Id); !ok {
				return
			} else {
				//向密钥对应的客户端发送与服务端udp建立连接信息，地址，密钥
				v.(*Client).signal.Write([]byte(common.NEW_UDP_CONN))
				svrAddr := beego.AppConfig.String("p2p_ip") + ":" + beego.AppConfig.String("p2p_port")
				if err != nil {
					logs.Warn("get local udp addr error")
					return
				}
				v.(*Client).signal.WriteLenContent([]byte(svrAddr))
				v.(*Client).signal.WriteLenContent(b)
				//向该请求者发送建立连接请求,服务器地址
				c.WriteLenContent([]byte(svrAddr))
			}
		}
	}
	c.SetAlive(s.tunnelType)
	return
}

// register ip
func (s *Bridge) register(c *conn.Conn) {
	var hour int32
	if err := binary.Read(c, binary.LittleEndian, &hour); err == nil {
		s.Register.Store(common.GetIpByAddr(c.Conn.RemoteAddr().String()), time.Now().Add(time.Hour*time.Duration(hour)))
	}
}

func (s *Bridge) SendLinkInfo(clientId int, link *conn.Link, t *file.Tunnel) (target net.Conn, err error) {
	// 如果是本地代理类型，直接连接目标地址
	if link.LocalProxy {
		return net.Dial("tcp", link.Host)
	}

	// 查找客户端
	client, ok := s.Client.Load(clientId)
	if !ok {
		return nil, errors.New("client not found")
	}
	c := client.(*Client)

	// IP验证
	if s.ipVerify {
		ip := common.GetIpByAddr(link.RemoteAddr)
		expiryTime, ok := s.Register.Load(ip)
		if !ok {
			return nil, fmt.Errorf("the ip %s is not in the validation list", ip)
		}
		if !expiryTime.(time.Time).After(time.Now()) {
			return nil, fmt.Errorf("the validity of the ip %s has expired", ip)
		}
	}

	// 获取隧道
	var tunnel *nps_mux.Mux
	if t != nil && t.Mode == "file" {
		tunnel = c.file
	} else {
		tunnel = c.tunnel
	}

	if tunnel == nil {
		return nil, errors.New("the client connect error")
	}

	// 创建新连接
	target, err = tunnel.NewConn()
	if err != nil {
		return nil, err
	}

	// 如果是文件模式，不需要加密和压缩
	if t != nil && t.Mode == "file" {
		link.Crypt = false
		link.Compress = false
		return target, nil
	}

	// 发送连接信息
	connWrapper := conn.NewConn(target)
	if _, err := connWrapper.SendInfo(link, ""); err != nil {
		target.Close()
		return nil, fmt.Errorf("failed to send info: %v", err)
	}

	return target, nil
}

func (s *Bridge) ping() {
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			arr := make([]int, 0)
			s.Client.Range(func(key, value interface{}) bool {
				v := value.(*Client)
				if v.tunnel == nil || v.signal == nil {
					v.retryTime += 1
					if v.retryTime >= 3 {
						arr = append(arr, key.(int))
					}
					return true
				}
				if v.tunnel.IsClose {
					arr = append(arr, key.(int))
				}
				return true
			})
			for _, v := range arr {
				logs.Info("the client %d closed", v)
				s.DelClient(v)
			}
		}
	}
}

// get config and add task from client config
func (s *Bridge) getConfig(c *conn.Conn, isPub bool, client *file.Client) {
	var fail bool
loop:
	for {
		flag, err := c.ReadFlag()
		if err != nil {
			break
		}
		switch flag {
		case common.WORK_STATUS:
			if b, err := c.GetShortContent(32); err != nil {
				break loop
			} else {
				var str string
				id, err := file.GetDb().GetClientIdByVkey(string(b))
				if err != nil {
					break loop
				}
				file.GetDb().JsonDb.Hosts.Range(func(key, value interface{}) bool {
					v := value.(*file.Host)
					if v.Client.Id == id {
						str += v.Remark + common.CONN_DATA_SEQ
					}
					return true
				})
				file.GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
					v := value.(*file.Tunnel)
					//if _, ok := s.runList[v.Id]; ok && v.Client.Id == id {
					if _, ok := s.runList.Load(v.Id); ok && v.Client.Id == id {
						str += v.Remark + common.CONN_DATA_SEQ
					}
					return true
				})
				binary.Write(c, binary.LittleEndian, int32(len([]byte(str))))
				binary.Write(c, binary.LittleEndian, []byte(str))
			}
		case common.NEW_CONF:
			var err error
			if client, err = c.GetConfigInfo(); err != nil {
				fail = true
				c.WriteAddFail()
				break loop
			} else {
				if err = file.GetDb().NewClient(client); err != nil {
					fail = true
					c.WriteAddFail()
					break loop
				}
				c.WriteAddOk()
				c.Write([]byte(client.VerifyKey))
				s.Client.Store(client.Id, NewClient(nil, nil, nil, ""))
			}
		case common.NEW_HOST:
			h, err := c.GetHostInfo()
			if err != nil {
				fail = true
				c.WriteAddFail()
				break loop
			}
			h.Client = client
			if h.Location == "" {
				h.Location = "/"
			}
			if !client.HasHost(h) {
				if file.GetDb().IsHostExist(h) {
					fail = true
					c.WriteAddFail()
					break loop
				} else {
					file.GetDb().NewHost(h)
					c.WriteAddOk()
				}
			} else {
				c.WriteAddOk()
			}
		case common.NEW_TASK:
			if t, err := c.GetTaskInfo(); err != nil {
				fail = true
				c.WriteAddFail()
				break loop
			} else {
				ports := common.GetPorts(t.Ports)
				targets := common.GetPorts(t.Target.TargetStr)
				if len(ports) > 1 && (t.Mode == "tcp" || t.Mode == "udp") && (len(ports) != len(targets)) {
					fail = true
					c.WriteAddFail()
					break loop
				} else if t.Mode == "secret" || t.Mode == "p2p" {
					ports = append(ports, 0)
				}
				if len(ports) == 0 {
					fail = true
					c.WriteAddFail()
					break loop
				}
				for i := 0; i < len(ports); i++ {
					tl := new(file.Tunnel)
					tl.Mode = t.Mode
					tl.Port = ports[i]
					tl.ServerIp = t.ServerIp
					if len(ports) == 1 {
						tl.Target = t.Target
						tl.Remark = t.Remark
					} else {
						tl.Remark = t.Remark + "_" + strconv.Itoa(tl.Port)
						tl.Target = new(file.Target)
						if t.TargetAddr != "" {
							tl.Target.TargetStr = t.TargetAddr + ":" + strconv.Itoa(targets[i])
						} else {
							tl.Target.TargetStr = strconv.Itoa(targets[i])
						}
					}
					tl.Id = int(file.GetDb().JsonDb.GetTaskId())
					tl.Status = true
					tl.Flow = new(file.Flow)
					tl.NoStore = true
					tl.Client = client
					tl.Password = t.Password
					tl.LocalPath = t.LocalPath
					tl.StripPre = t.StripPre
					tl.MultiAccount = t.MultiAccount
					if !client.HasTunnel(tl) {
						if err := file.GetDb().NewTask(tl); err != nil {
							logs.Notice("Add task error ", err.Error())
							fail = true
							c.WriteAddFail()
							break loop
						}
						if b := tool.TestServerPort(tl.Port, tl.Mode); !b && t.Mode != "secret" && t.Mode != "p2p" {
							fail = true
							c.WriteAddFail()
							break loop
						} else {
							s.OpenTask <- tl
						}
					}
					c.WriteAddOk()
				}
			}
		}
	}
	if fail && client != nil {
		s.DelClient(client.Id)
	}
	c.Close()
}
