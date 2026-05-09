package goroutine

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type benchmarkAddr string

func (a benchmarkAddr) Network() string {
	return "benchmark"
}

func (a benchmarkAddr) String() string {
	return string(a)
}

type benchmarkConn struct {
	reader io.Reader
}

func (c *benchmarkConn) Read(p []byte) (int, error) {
	if c.reader == nil {
		return 0, io.EOF
	}
	return c.reader.Read(p)
}

func (c *benchmarkConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *benchmarkConn) Close() error {
	return nil
}

func (c *benchmarkConn) LocalAddr() net.Addr {
	return benchmarkAddr("local")
}

func (c *benchmarkConn) RemoteAddr() net.Addr {
	return benchmarkAddr("remote")
}

func (c *benchmarkConn) SetDeadline(time.Time) error {
	return nil
}

func (c *benchmarkConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *benchmarkConn) SetWriteDeadline(time.Time) error {
	return nil
}

func BenchmarkCopyBufferMemory(b *testing.B) {
	payload := bytes.Repeat([]byte("nps-benchmark"), 8<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		src := bytes.NewReader(payload)
		if err := CopyBuffer(io.Discard, src, nil, nil, "127.0.0.1:0"); err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}
}

func BenchmarkCopyConnsPoolMemoryConn(b *testing.B) {
	payload := bytes.Repeat([]byte("nps-pipe-benchmark"), 4<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		muxSide := &benchmarkConn{reader: bytes.NewReader(payload)}
		userSide := &benchmarkConn{}
		var wg sync.WaitGroup
		wg.Add(1)
		if err := CopyConnsPool.Invoke(NewConns(muxSide, userSide, nil, &wg, nil)); err != nil {
			b.Fatal(err)
		}
		wg.Wait()
	}
}
