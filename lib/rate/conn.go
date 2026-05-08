package rate

import (
	"io"
)

type rateConn struct {
	conn io.ReadWriteCloser
	rate *Rate
}

func NewRateConn(conn io.ReadWriteCloser, rate *Rate) io.ReadWriteCloser {
	if rate == nil {
		return conn
	}
	return &rateConn{
		conn: conn,
		rate: rate,
	}
}

func (s *rateConn) Read(b []byte) (n int, err error) {
	n, err = s.conn.Read(b)
	s.rate.Get(int64(n))
	return
}

func (s *rateConn) Write(b []byte) (n int, err error) {
	n, err = s.conn.Write(b)
	s.rate.Get(int64(n))
	return
}

func (s *rateConn) Close() error {
	return s.conn.Close()
}
