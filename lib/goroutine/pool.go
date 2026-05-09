package goroutine

import (
	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/file"
	"errors"
	"fmt"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
	"github.com/panjf2000/ants/v2"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

var errAuthRequired = errors.New("auth required")

type connGroup struct {
	src io.ReadWriteCloser
	dst io.ReadWriteCloser
	wg  *sync.WaitGroup
	n   *int64
	opt *copyOptions
}

type copyOptions struct {
	flow             *file.Flow
	task             *file.Tunnel
	remote           string
	authResponse     []byte
	checkFlowLimit   bool
	flowLimitBytes   int64
	flowFlushBytes   int64
	flowFlushPackets int
}

//func newConnGroup(dst, src io.ReadWriteCloser, wg *sync.WaitGroup, n *int64) connGroup {
//	return connGroup{
//		src: src,
//		dst: dst,
//		wg:  wg,
//		n:   n,
//	}
//}

func newConnGroup(dst, src io.ReadWriteCloser, wg *sync.WaitGroup, n *int64, flow *file.Flow, task *file.Tunnel, remote string) connGroup {
	return newConnGroupWithOptions(dst, src, wg, n, newCopyOptions(flow, task, remote))
}

func newConnGroupWithOptions(dst, src io.ReadWriteCloser, wg *sync.WaitGroup, n *int64, opt *copyOptions) connGroup {
	return connGroup{
		src: src,
		dst: dst,
		wg:  wg,
		n:   n,
		opt: opt,
	}
}

func CopyBuffer(dst io.Writer, src io.Reader, flow *file.Flow, task *file.Tunnel, remote string) (err error) {
	return copyBuffer(dst, src, newCopyOptions(flow, task, remote))
}

func newCopyOptions(flow *file.Flow, task *file.Tunnel, remote string) *copyOptions {
	opt := &copyOptions{
		flow:             flow,
		task:             task,
		remote:           remote,
		flowFlushBytes:   1 << 20,
		flowFlushPackets: 32,
	}
	if flow != nil && flow.FlowLimit > 0 {
		opt.checkFlowLimit = true
		opt.flowLimitBytes = flow.FlowLimit << 20
	}
	if task != nil && task.Client != nil && task.Client.IpWhite && task.Client.IpWhitePass != "" &&
		common.IsAuthIp(remote, task.Client.VerifyKey, task.Client.IpWhiteList) {
		errorContent, _ := common.ReadAllFromFile(filepath.Join(common.GetRunPath(), "web", "static", "page", "auth.html"))
		authHtml := string(errorContent)
		authHtml = strings.ReplaceAll(authHtml, "${ip}", common.GetIpByAddr(remote))
		authHtml = strings.ReplaceAll(authHtml, "${vkey}", task.Client.VerifyKey)
		authHtml = strings.ReplaceAll(authHtml, "${port}", beego.AppConfig.String("web_port"))
		opt.authResponse = []byte(fmt.Sprintf("HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(authHtml), authHtml))
	}
	return opt
}

func copyBuffer(dst io.Writer, src io.Reader, opt *copyOptions) (err error) {
	if opt.authResponse != nil {
		_, _ = dst.Write(opt.authResponse)
		return errAuthRequired
	}
	buf := common.CopyBuff.Get()
	defer common.CopyBuff.Put(buf)
	var pending int64
	var packets int
	defer func() {
		if pending > 0 && opt.flow != nil {
			opt.flow.Add(pending, pending)
		}
	}()
	for {
		if len(buf) <= 0 {
			break
		}
		nr, er := src.Read(buf)

		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				//written += int64(nw)
				if opt.flow != nil {
					pending += int64(nw)
					packets++
					if pending >= opt.flowFlushBytes || packets >= opt.flowFlushPackets {
						opt.flow.Add(pending, pending)
						pending = 0
						packets = 0
					}
					// <<20 = 1024 * 1024
					if opt.checkFlowLimit && opt.flowLimitBytes < opt.flow.Total()+pending*2 {
						logs.Info("流量已经超出.........")
						break
					}
				}

			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			err = er
			break
		}
	}
	//return written, err
	return err
}

func copyConnGroup(group interface{}) {
	//logs.Info("copyConnGroup.........")
	cg, ok := group.(connGroup)
	if !ok {
		return
	}
	defer cg.wg.Done()
	var err error
	err = copyBuffer(cg.dst, cg.src, cg.opt)
	if err != nil {
		cg.src.Close()
		cg.dst.Close()
		//logs.Warn("close npc by copy from nps", err, c.connId)
	}

	//if conns.flow != nil {
	//	conns.flow.Add(in, out)
	//}
}

type Conns struct {
	conn1 io.ReadWriteCloser // mux connection
	conn2 net.Conn           // outside connection
	flow  *file.Flow
	wg    *sync.WaitGroup
	task  *file.Tunnel
}

func NewConns(c1 io.ReadWriteCloser, c2 net.Conn, flow *file.Flow, wg *sync.WaitGroup, task *file.Tunnel) Conns {
	return Conns{
		conn1: c1,
		conn2: c2,
		flow:  flow,
		wg:    wg,
		task:  task,
	}
}

func copyConns(group interface{}) {
	//logs.Info("copyConns.........")
	conns := group.(Conns)
	defer conns.wg.Done()
	wg := new(sync.WaitGroup)
	wg.Add(2)
	var in, out int64
	remoteAddr := conns.conn2.RemoteAddr().String()
	if err := connCopyPool.Invoke(newConnGroupWithOptions(conns.conn1, conns.conn2, wg, &in, newCopyOptions(conns.flow, nil, remoteAddr))); err != nil {
		logs.Error(err)
		conns.conn1.Close()
		conns.conn2.Close()
		wg.Done()
	}
	// outside to mux : incoming
	if err := connCopyPool.Invoke(newConnGroupWithOptions(conns.conn2, conns.conn1, wg, &out, newCopyOptions(conns.flow, conns.task, remoteAddr))); err != nil {
		logs.Error(err)
		conns.conn1.Close()
		conns.conn2.Close()
		wg.Done()
	}
	// mux to outside : outgoing
	wg.Wait()
	//if conns.flow != nil {
	//	conns.flow.Add(in, out)
	//}
}

func poolSizeFromEnv(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	size, err := strconv.Atoi(value)
	if err != nil || size <= 0 {
		logs.Warn("invalid %s=%q, using %d", name, value, fallback)
		return fallback
	}
	return size
}

var connCopyPool, _ = ants.NewPoolWithFunc(poolSizeFromEnv("NPS_CONN_COPY_POOL_SIZE", 200000), copyConnGroup, ants.WithNonblocking(false))
var CopyConnsPool, _ = ants.NewPoolWithFunc(poolSizeFromEnv("NPS_COPY_CONNS_POOL_SIZE", 100000), copyConns, ants.WithNonblocking(false))
