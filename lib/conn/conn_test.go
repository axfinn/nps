package conn

import (
	"net"
	"testing"
	"time"
)

// TestReadFlag verifies that ReadFlag returns the four bytes actually read.
//
// The original implementation was
//
//	return string(buf), binary.Read(s, binary.LittleEndian, &buf)
//
// which converts the still-empty buffer to a string before binary.Read fills
// it. Go does not guarantee the evaluation order between the conversion and the
// call, so the handshake flag could come back blank, silently breaking the
// WORK_MAIN / NEW_UDP_CONN / WORK_CONFIG negotiations.
func TestReadFlag(t *testing.T) {
	for _, want := range []string{"clse", "main", "chan", "conf"} {
		server, client := net.Pipe()
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		go func(payload string) {
			_, _ = client.Write([]byte(payload))
			_ = client.Close()
		}(want)

		got, err := NewConn(server).ReadFlag()
		_ = server.Close()
		if err != nil {
			t.Fatalf("ReadFlag(%q) error: %v", want, err)
		}
		if got != want {
			t.Fatalf("ReadFlag = %q, want %q", got, want)
		}
	}
}

// TestReadFlagShortInput ensures a truncated flag surfaces an error rather than
// returning a partially-filled buffer.
func TestReadFlagShortInput(t *testing.T) {
	server, client := net.Pipe()
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	go func() {
		_, _ = client.Write([]byte("ab"))
		_ = client.Close()
	}()

	if _, err := NewConn(server).ReadFlag(); err == nil {
		_ = server.Close()
		t.Fatal("expected an error on a short flag read")
	}
	_ = server.Close()
}
