package client

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/config"
	"ehang.io/nps/lib/conn"
	"ehang.io/nps/lib/crypt"
	"ehang.io/nps/lib/version"
	"github.com/astaxie/beego/logs"
	"github.com/xtaci/kcp-go"
	"golang.org/x/net/proxy"
)

var tlsEnable1 = false

func SetTlsEnable(tlsEnable11 bool) {
	tlsEnable1 = tlsEnable11
}

func GetTlsEnable() bool {
	return tlsEnable1
}

func GetTaskStatus(path string) {
	cnf, err := config.NewConfig(path)
	if err != nil {
		log.Fatalln(err)
	}
	c, err := NewConn(cnf.CommonConfig.Tp, cnf.CommonConfig.VKey, cnf.CommonConfig.Server, common.WORK_CONFIG, cnf.CommonConfig.ProxyUrl)
	if err != nil {
		log.Fatalln(err)
	}
	if _, err := c.Write([]byte(common.WORK_STATUS)); err != nil {
		log.Fatalln(err)
	}
	//read now vKey and write to server
	if f, err := common.ReadAllFromFile(filepath.Join(common.GetTmpPath(), "npc_vkey.txt")); err != nil {
		log.Fatalln(err)
	} else if _, err := c.Write([]byte(crypt.Md5(string(f)))); err != nil {
		log.Fatalln(err)
	}
	var isPub bool
	binary.Read(c, binary.LittleEndian, &isPub)
	if l, err := c.GetLen(); err != nil {
		log.Fatalln(err)
	} else if b, err := c.GetShortContent(l); err != nil {
		log.Fatalln(err)
	} else {
		arr := strings.Split(string(b), common.CONN_DATA_SEQ)
		for _, v := range cnf.Hosts {
			if common.InStrArr(arr, v.Remark) {
				log.Println(v.Remark, "ok")
			} else {
				log.Println(v.Remark, "not running")
			}
		}
		for _, v := range cnf.Tasks {
			ports := common.GetPorts(v.Ports)
			if v.Mode == "secret" {
				ports = append(ports, 0)
			}
			for _, vv := range ports {
				var remark string
				if len(ports) > 1 {
					remark = v.Remark + "_" + strconv.Itoa(vv)
				} else {
					remark = v.Remark
				}
				if common.InStrArr(arr, remark) {
					log.Println(remark, "ok")
				} else {
					log.Println(remark, "not running")
				}
			}
		}
	}
	os.Exit(0)
}

var errAdd = errors.New("The server returned an error, which port or host may have been occupied or not allowed to open.")

func StartFromFile(path string) {
	first := true
	cnf, err := config.NewConfig(path)
	if err != nil || cnf.CommonConfig == nil {
		logs.Error("Config file %s loading error %s", path, err.Error())
		os.Exit(0)
	}
	logs.Info("Loading configuration file %s successfully", path)

	SetTlsEnable(cnf.CommonConfig.TlsEnable)
	logs.Info("the version of client is %s, the core version of client is %s,tls enable is %t", version.VERSION, version.GetVersion(), GetTlsEnable())
re:
	if first || cnf.CommonConfig.AutoReconnection {
		if !first {
			logs.Info("Reconnecting...")
			time.Sleep(time.Second * 5)
		}
	} else {
		return
	}
	first = false
	c, err := NewConn(cnf.CommonConfig.Tp, cnf.CommonConfig.VKey, cnf.CommonConfig.Server, common.WORK_CONFIG, cnf.CommonConfig.ProxyUrl)
	if err != nil {
		logs.Error(err)
		goto re
	}
	var isPub bool
	binary.Read(c, binary.LittleEndian, &isPub)

	// get tmp password
	var b []byte
	vkey := cnf.CommonConfig.VKey
	if isPub {
		// send global configuration to server and get status of config setting
		if _, err := c.SendInfo(cnf.CommonConfig.Client, common.NEW_CONF); err != nil {
			logs.Error(err)
			goto re
		}
		if !c.GetAddStatus() {
			logs.Error("the web_user may have been occupied!")
			goto re
		}

		if b, err = c.GetShortContent(16); err != nil {
			logs.Error(err)
			goto re
		}
		vkey = string(b)
	}
	ioutil.WriteFile(filepath.Join(common.GetTmpPath(), "npc_vkey.txt"), []byte(vkey), 0600)

	//send hosts to server
	for _, v := range cnf.Hosts {
		if _, err := c.SendInfo(v, common.NEW_HOST); err != nil {
			logs.Error(err)
			goto re
		}
		if !c.GetAddStatus() {
			logs.Error(errAdd, v.Host)
			goto re
		}
	}

	//send  task to server
	for _, v := range cnf.Tasks {
		if _, err := c.SendInfo(v, common.NEW_TASK); err != nil {
			logs.Error(err)
			goto re
		}
		if !c.GetAddStatus() {
			logs.Error(errAdd, v.Ports, v.Remark)
			goto re
		}
		if v.Mode == "file" {
			//start local file server
			go startLocalFileServer(cnf.CommonConfig, v, vkey)
		}
	}

	//create local server secret or p2p
	for _, v := range cnf.LocalServer {
		go StartLocalServer(v, cnf.CommonConfig)
	}

	c.Close()
	if cnf.CommonConfig.Client.WebUserName == "" || cnf.CommonConfig.Client.WebPassword == "" {
		logs.Notice("web access login username:user password:%s", vkey)
	} else {
		logs.Notice("web access login username:%s password:%s", cnf.CommonConfig.Client.WebUserName, cnf.CommonConfig.Client.WebPassword)
	}
	NewRPClient(cnf.CommonConfig.Server, vkey, cnf.CommonConfig.Tp, cnf.CommonConfig.ProxyUrl, cnf, cnf.CommonConfig.DisconnectTime).Start()
	CloseLocalServer()
	goto re
}

// Create a new connection with the server and verify it
func NewConn(tp string, vkey string, server string, connType string, proxyUrl string) (*conn.Conn, error) {
	var err error
	var connection net.Conn
	var sess *kcp.UDPSession
	
	if tp == "tcp" {
		if proxyUrl != "" {
			u, er := url.Parse(proxyUrl)
			if er != nil {
				return nil, er
			}
			switch u.Scheme {
			case "socks5":
				n, er := proxy.FromURL(u, nil)
				if er != nil {
					return nil, er
				}
				connection, err = n.Dial("tcp", server)
			default:
				connection, err = NewHttpProxyConn(u, server)
			}
		} else {
			if GetTlsEnable() {
				//tls 流量加密
				conf := &tls.Config{
					InsecureSkipVerify: true,
				}
				connection, err = tls.Dial("tcp", server, conf)
			} else {
				connection, err = net.DialTimeout("tcp", server, time.Second*10)
			}
		}
	} else {
		sess, err = kcp.DialWithOptions(server, nil, 10, 3)
		if err == nil {
			conn.SetUdpSession(sess)
			connection = sess
		}
	}
	if err != nil {
		return nil, err
	}
	
	// 设置连接超时
	connection.SetDeadline(time.Now().Add(time.Second * 10))
	defer connection.SetDeadline(time.Time{})
	
	c := conn.NewConn(connection)
	logs.Info("=== CLIENT: Starting handshake process with server: %s ===", server)
	
	// 重置写入超时
	connection.SetDeadline(time.Now().Add(time.Second * 10))
	logs.Info("=== CLIENT: Step 1 - Sending CONN_TEST flag to server: %s", common.CONN_TEST)
	if _, err := c.Write([]byte(common.CONN_TEST)); err != nil {
		logs.Error("=== CLIENT: Failed to send CONN_TEST flag to server: %s", err.Error())
		connection.Close()
		return nil, err
	}
	logs.Info("=== CLIENT: Successfully sent CONN_TEST flag to server")
	logs.Info("=== CLIENT: Step 2 - Sending client version: %s", version.GetVersion())
	clientVersionBytes := []byte(version.GetVersion())
	logs.Info("=== CLIENT: Client version bytes length: %d, content: %s", len(clientVersionBytes), string(clientVersionBytes))
	
	// 使用更直接的方式发送版本信息，避免使用WriteLenContent方法
	// 先发送长度（4字节小端序）
	versionLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionLen, uint32(len(clientVersionBytes)))
	if _, err := c.Write(versionLen); err != nil {
		logs.Error("=== CLIENT: Failed to send client version length to server: %s", err.Error())
		connection.Close()
		return nil, err
	}
	
	// 再发送版本内容
	if _, err := c.Write(clientVersionBytes); err != nil {
		logs.Error("=== CLIENT: Failed to send client version to server: %s", err.Error())
		connection.Close()
		return nil, err
	}
	logs.Info("=== CLIENT: Successfully sent client version to server")
	
	// 重置写入超时
	connection.SetDeadline(time.Now().Add(time.Second * 15)) // 增加超时时间到15秒
	logs.Info("=== CLIENT: Step 3 - Sending server version: %s", version.VERSION)
	serverVersionBytes := []byte(version.VERSION)
	logs.Info("=== CLIENT: Server version bytes length: %d, content: %s", len(serverVersionBytes), string(serverVersionBytes))
	
	// 使用更直接的方式发送服务端版本信息，避免使用WriteLenContent方法
	// 先发送长度（4字节小端序）
	serverVersionLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(serverVersionLen, uint32(len(serverVersionBytes)))
	if _, err := c.Write(serverVersionLen); err != nil {
		logs.Error("=== CLIENT: Failed to send server version length to server: %s", err.Error())
		connection.Close()
		return nil, err
	}
	
	// 再发送版本内容
	if _, err := c.Write(serverVersionBytes); err != nil {
		logs.Error("=== CLIENT: Failed to send server version to server: %s", err.Error())
		connection.Close()
		return nil, err
	}
	logs.Info("=== CLIENT: Successfully sent server version to server")
	
	// 重置读取超时
	connection.SetDeadline(time.Now().Add(time.Second * 10))
	logs.Info("=== CLIENT: Step 4 - Waiting for server version hash response")
	// b, err := c.GetShortContent(32)
	// 修复：直接读取32个字节，而不是使用GetShortContent方法
	b := make([]byte, 32)
	logs.Info("=== CLIENT: Attempting to read 32 bytes for server version hash")
	n, err := c.Read(b)
	logs.Info("=== CLIENT: Read operation completed. Bytes read: %d, Error: %v", n, err)
	if err != nil {
		logs.Error("=== CLIENT: Failed to read server response: %s", err.Error())
		connection.Close()
		return nil, err
	}
	logs.Info("=== CLIENT: Successfully received server version hash: %s", string(b))
	
	if crypt.Md5(version.GetVersion()) != string(b) {
		logs.Warn("=== CLIENT: Server version hash mismatch for client %s, expected: %s, got: %s", server, crypt.Md5(version.GetVersion()), string(b))
	}
	
	// 重置写入超时
	connection.SetDeadline(time.Now().Add(time.Second * 15)) // 增加超时时间到15秒
	logs.Info("=== CLIENT: Step 5 - Sending verification key")
	vkeyBytes := []byte(common.Getverifyval(vkey))
	logs.Info("=== CLIENT: Verification key bytes length: %d", len(vkeyBytes))
	
	// 在发送前记录连接状态
	logs.Info("=== CLIENT: Connection state before sending verification key - Local: %s, Remote: %s", connection.LocalAddr().String(), connection.RemoteAddr().String())
	if _, err := c.Write(vkeyBytes); err != nil {
		logs.Error("=== CLIENT: Failed to send verification key to server: %s", err.Error())
		connection.Close()
		return nil, err
	}
	logs.Info("=== CLIENT: Successfully sent verification key to server")
	
	// 增加短暂延迟，确保服务端有足够时间处理并发送响应
	time.Sleep(100 * time.Millisecond)
	
	// 重置读取超时
	connection.SetDeadline(time.Now().Add(time.Second * 15)) // 增加超时时间到15秒
	logs.Info("=== CLIENT: Step 6 - Waiting for server verification response")
	
	// 记录连接状态
	logs.Info("=== CLIENT: Connection state before reading verification response - Local: %s, Remote: %s", connection.LocalAddr().String(), connection.RemoteAddr().String())
	
	// 直接读取4字节的响应标志，而不是使用ReadFlag方法
	buf := make([]byte, 4)
	if _, err := c.Read(buf); err != nil {
		logs.Error("=== CLIENT: Failed to read server verification response: %s", err.Error())
		connection.Close()
		return nil, err
	}
	
	s := string(buf)
	if s == common.VERIFY_EER {
		err := errors.New(fmt.Sprintf("Validation key %s incorrect", vkey))
		logs.Error("=== CLIENT: Server verification failed: %s", err.Error())
		connection.Close()
		return nil, err
	}
	logs.Info("=== CLIENT: Server verification successful")
	
	// 立即重置写入超时，确保能及时发送连接类型标志
	connection.SetDeadline(time.Now().Add(time.Second * 15)) // 增加超时时间到15秒
	logs.Info("=== CLIENT: Step 7 - Sending connection type: %s", connType)
	
	// 在发送前记录连接状态
	logs.Info("=== CLIENT: Connection state before sending connection type - Local: %s, Remote: %s", connection.LocalAddr().String(), connection.RemoteAddr().String())
	if _, err := c.Write([]byte(connType)); err != nil {
		logs.Error("=== CLIENT: Failed to send connection type to server: %s", err.Error())
		connection.Close()
		return nil, err
	}
	logs.Info("=== CLIENT: Successfully sent connection type to server")
	logs.Info("=== CLIENT: Connection state after sending connection type - Local: %s, Remote: %s", connection.LocalAddr().String(), connection.RemoteAddr().String())
	
	c.SetAlive(tp)
	
	logs.Info("=== CLIENT: Handshake completed successfully")
	return c, nil
}

// http proxy connection
func NewHttpProxyConn(url *url.URL, remoteAddr string) (net.Conn, error) {
	req, err := http.NewRequest("CONNECT", "http://"+remoteAddr, nil)
	if err != nil {
		return nil, err
	}
	password, _ := url.User.Password()
	req.Header.Set("Authorization", "Basic "+basicAuth(strings.Trim(url.User.Username(), " "), password))
	// we make a http proxy request
	proxyConn, err := net.Dial("tcp", url.Host)
	if err != nil {
		return nil, err
	}
	if err := req.Write(proxyConn); err != nil {
		return nil, err
	}
	res, err := http.ReadResponse(bufio.NewReader(proxyConn), req)
	if err != nil {
		return nil, err
	}
	_ = res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errors.New("Proxy error " + res.Status)
	}
	return proxyConn, nil
}

// get a basic auth string
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func getRemoteAddressFromServer(rAddr string, localConn *net.UDPConn, md5Password, role string, add int) error {
	rAddr, err := getNextAddr(rAddr, add)
	if err != nil {
		logs.Error(err)
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", rAddr)
	if err != nil {
		return err
	}
	if _, err := localConn.WriteTo(common.GetWriteStr(md5Password, role), addr); err != nil {
		return err
	}
	return nil
}

func handleP2PUdp(localAddr, rAddr, md5Password, role string) (remoteAddress string, c net.PacketConn, err error) {
	localConn, err := newUdpConnByAddr(localAddr)
	if err != nil {
		return
	}
	err = getRemoteAddressFromServer(rAddr, localConn, md5Password, role, 0)
	if err != nil {
		logs.Error(err)
		return
	}
	err = getRemoteAddressFromServer(rAddr, localConn, md5Password, role, 1)
	if err != nil {
		logs.Error(err)
		return
	}
	err = getRemoteAddressFromServer(rAddr, localConn, md5Password, role, 2)
	if err != nil {
		logs.Error(err)
		return
	}
	var remoteAddr1, remoteAddr2, remoteAddr3 string
	for {
		buf := common.BufPool.Get().([]byte)
		defer common.BufPool.Put(buf)
		if n, addr, er := localConn.ReadFromUDP(buf); er != nil {
			err = er
			return
		} else {
			rAddr2, _ := getNextAddr(rAddr, 1)
			rAddr3, _ := getNextAddr(rAddr, 2)
			switch addr.String() {
			case rAddr:
				remoteAddr1 = string(buf[:n])
			case rAddr2:
				remoteAddr2 = string(buf[:n])
			case rAddr3:
				remoteAddr3 = string(buf[:n])
			}
		}
		if remoteAddr1 != "" && remoteAddr2 != "" && remoteAddr3 != "" {
			break
		}
	}
	if remoteAddress, err = sendP2PTestMsg(localConn, remoteAddr1, remoteAddr2, remoteAddr3); err != nil {
		return
	}
	c, err = newUdpConnByAddr(localAddr)
	return
}

func sendP2PTestMsg(localConn *net.UDPConn, remoteAddr1, remoteAddr2, remoteAddr3 string) (string, error) {
	logs.Trace(remoteAddr3, remoteAddr2, remoteAddr1)
	defer localConn.Close()
	isClose := false
	defer func() { isClose = true }()
	interval, err := getAddrInterval(remoteAddr1, remoteAddr2, remoteAddr3)
	if err != nil {
		return "", err
	}
	go func() {
		addr, err := getNextAddr(remoteAddr3, interval)
		if err != nil {
			return
		}
		remoteUdpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return
		}
		logs.Trace("try send test packet to target %s", addr)
		ticker := time.NewTicker(time.Millisecond * 500)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if isClose {
					return
				}
				if _, err := localConn.WriteTo([]byte(common.WORK_P2P_CONNECT), remoteUdpAddr); err != nil {
					return
				}
			}
		}
	}()
	if interval != 0 {
		ip := common.GetIpByAddr(remoteAddr2)
		go func() {
			ports := getRandomPortArr(common.GetPortByAddr(remoteAddr3), common.GetPortByAddr(remoteAddr3)+interval*50)
			for i := 0; i <= 50; i++ {
				go func(port int) {
					trueAddress := ip + ":" + strconv.Itoa(port)
					logs.Trace("try send test packet to target %s", trueAddress)
					remoteUdpAddr, err := net.ResolveUDPAddr("udp", trueAddress)
					if err != nil {
						return
					}
					ticker := time.NewTicker(time.Second * 2)
					defer ticker.Stop()
					for {
						select {
						case <-ticker.C:
							if isClose {
								return
							}
							if _, err := localConn.WriteTo([]byte(common.WORK_P2P_CONNECT), remoteUdpAddr); err != nil {
								return
							}
						}
					}
				}(ports[i])
				time.Sleep(time.Millisecond * 10)
			}
		}()

	}

	buf := common.BufPoolCopy.Get().([]byte)
	defer common.BufPoolCopy.Put(buf)
	for {
		localConn.SetReadDeadline(time.Now().Add(time.Second * 10))
		n, addr, err := localConn.ReadFromUDP(buf)
		localConn.SetReadDeadline(time.Time{})
		if err != nil {
			break
		}
		switch string(buf[:n]) {
		case common.WORK_P2P_SUCCESS:
			for i := 20; i > 0; i-- {
				if _, err = localConn.WriteTo([]byte(common.WORK_P2P_END), addr); err != nil {
					return "", err
				}
			}
			return addr.String(), nil
		case common.WORK_P2P_END:
			logs.Trace("Remotely Address %s Reply Packet Successfully Received", addr.String())
			return addr.String(), nil
		case common.WORK_P2P_CONNECT:
			go func() {
				for i := 20; i > 0; i-- {
					logs.Trace("try send receive success packet to target %s", addr.String())
					if _, err = localConn.WriteTo([]byte(common.WORK_P2P_SUCCESS), addr); err != nil {
						return
					}
					time.Sleep(time.Second)
				}
			}()
		default:
			continue
		}
	}
	return "", errors.New("connect to the target failed, maybe the nat type is not support p2p")
}

func newUdpConnByAddr(addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	return udpConn, nil
}

func getNextAddr(addr string, n int) (string, error) {
	arr := strings.Split(addr, ":")
	if len(arr) != 2 {
		return "", errors.New(fmt.Sprintf("the format of %s incorrect", addr))
	}
	if p, err := strconv.Atoi(arr[1]); err != nil {
		return "", err
	} else {
		return arr[0] + ":" + strconv.Itoa(p+n), nil
	}
}

func getAddrInterval(addr1, addr2, addr3 string) (int, error) {
	arr1 := strings.Split(addr1, ":")
	if len(arr1) != 2 {
		return 0, errors.New(fmt.Sprintf("the format of %s incorrect", addr1))
	}
	arr2 := strings.Split(addr2, ":")
	if len(arr2) != 2 {
		return 0, errors.New(fmt.Sprintf("the format of %s incorrect", addr2))
	}
	arr3 := strings.Split(addr3, ":")
	if len(arr3) != 2 {
		return 0, errors.New(fmt.Sprintf("the format of %s incorrect", addr3))
	}
	p1, err := strconv.Atoi(arr1[1])
	if err != nil {
		return 0, err
	}
	p2, err := strconv.Atoi(arr2[1])
	if err != nil {
		return 0, err
	}
	p3, err := strconv.Atoi(arr3[1])
	if err != nil {
		return 0, err
	}
	interVal := int(math.Floor(math.Min(math.Abs(float64(p3-p2)), math.Abs(float64(p2-p1)))))
	if p3-p1 < 0 {
		return -interVal, nil
	}
	return interVal, nil
}

func getRandomPortArr(min, max int) []int {
	if min > max {
		min, max = max, min
	}
	addrAddr := make([]int, max-min+1)
	for i := min; i <= max; i++ {
		addrAddr[max-i] = i
	}
	rand.Seed(time.Now().UnixNano())
	var r, temp int
	for i := max - min; i > 0; i-- {
		r = rand.Int() % i
		temp = addrAddr[i]
		addrAddr[i] = addrAddr[r]
		addrAddr[r] = temp
	}
	return addrAddr
}
