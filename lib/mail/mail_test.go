package mail

import (
	"bufio"
	"errors"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestEmailHelpers(t *testing.T) {
	valid := []string{"a@b.com", "  User.Name+tag@Example.COM  ", "x@y.z"}
	invalid := []string{"", "abc", "a@b", "a b@c.com", "a@\nBcc: evil@x.com"}
	for _, v := range valid {
		if !ValidEmail(v) {
			t.Fatalf("expected %q to be valid", v)
		}
	}
	for _, v := range invalid {
		if ValidEmail(v) {
			t.Fatalf("expected %q to be invalid", v)
		}
	}
	if NormalizeEmail("  A@B.COM ") != "a@b.com" {
		t.Fatal("normalization failed")
	}
	if !regexp.MustCompile(`^\d{6}$`).MatchString(GenNumericCode()) {
		t.Fatal("code must be six digits")
	}
}

func TestCodeStoreLifecycle(t *testing.T) {
	clock := time.Now()
	store := NewCodeStore(10*time.Minute, 60*time.Second, 3, 2)
	store.now = func() time.Time { return clock }

	code, err := store.Issue("a@x.com", PurposeLogin, "1.2.3.4")
	if err != nil || len(code) != 6 {
		t.Fatal("issue failed", code, err)
	}
	if _, err := store.Issue("a@x.com", PurposeLogin, "1.2.3.4"); !errors.Is(err, ErrTooFrequent) {
		t.Fatal("resend cooldown not enforced:", err)
	}
	if store.Consume("a@x.com", PurposeBind, code) {
		t.Fatal("a login code must not work for binding")
	}
	wrong := "000000"
	if wrong == code {
		wrong = "111111"
	}
	if store.Consume("a@x.com", PurposeLogin, wrong) {
		t.Fatal("wrong code accepted")
	}
	if !store.Consume("a@x.com", PurposeLogin, code) {
		t.Fatal("correct code rejected")
	}
	if store.Consume("a@x.com", PurposeLogin, code) {
		t.Fatal("code must be single use")
	}

	// Two successful sends from one IP exhaust the hourly quota.
	if _, err := store.Issue("b@x.com", PurposeLogin, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Issue("c@x.com", PurposeLogin, "1.2.3.4"); !errors.Is(err, ErrIPRateLimit) {
		t.Fatal("IP rate limit not enforced:", err)
	}
	// Another IP is unaffected.
	if _, err := store.Issue("d@x.com", PurposeLogin, "5.6.7.8"); err != nil {
		t.Fatal(err)
	}

	// Too many wrong guesses invalidate the code.
	store2 := NewCodeStore(10*time.Minute, time.Second, 2, 100)
	store2.now = func() time.Time { return clock }
	c2, _ := store2.Issue("e@x.com", PurposeBind, "")
	wrong2 := "111111"
	if wrong2 == c2 {
		wrong2 = "222222"
	}
	if store2.Consume("e@x.com", PurposeBind, wrong2) {
		t.Fatal("wrong code accepted")
	}
	if store2.Consume("e@x.com", PurposeBind, "333333") {
		t.Fatal("wrong code accepted")
	}
	if store2.Consume("e@x.com", PurposeBind, c2) {
		t.Fatal("code should be invalidated after too many guesses")
	}
}

func TestCodeStoreExpiryAndRevoke(t *testing.T) {
	clock := time.Now()
	store := NewCodeStore(2*time.Minute, time.Second, 5, 100)
	store.now = func() time.Time { return clock }
	code, err := store.Issue("f@x.com", PurposeLogin, "")
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(3 * time.Minute)
	if store.Consume("f@x.com", PurposeLogin, code) {
		t.Fatal("expired code must be rejected")
	}
	clock = clock.Add(time.Second)
	if _, err := store.Issue("f@x.com", PurposeLogin, ""); err != nil {
		t.Fatal("expired code should not block a new one:", err)
	}
	store.Revoke("f@x.com", PurposeLogin)
	if store.Consume("f@x.com", PurposeLogin, code) {
		t.Fatal("revoked code must be rejected")
	}
	if _, err := store.Issue("", PurposeLogin, ""); !errors.Is(err, ErrInvalidEmail) {
		t.Fatal("invalid email must be rejected:", err)
	}
	if _, err := store.Issue("g@x.com", Purpose("other"), ""); !errors.Is(err, ErrInvalidPurpose) {
		t.Fatal("invalid purpose must be rejected:", err)
	}
}

func TestConfigured(t *testing.T) {
	if (Config{}).Configured() {
		t.Fatal("empty config must be unconfigured")
	}
	cfg := Config{Host: "smtp.example.com", Port: 465, User: "noreply@example.com", Password: "secret"}
	if !cfg.Configured() || cfg.FromOrDefault() != "noreply@example.com" || cfg.port() != 465 {
		t.Fatal("config defaults failed")
	}
	if err := Send(Config{}, "a@b.com", "s", "b"); err == nil {
		t.Fatal("unconfigured send must fail")
	}
}

// startFakeSMTP is a minimal, non-TLS SMTP server used to verify the whole
// dial/EHLO/MAIL/RCPT/DATA flow without touching the network.
func startFakeSMTP(t *testing.T) (host string, port int, received chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	received = make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)
		write := func(s string) { _, _ = w.WriteString(s); _ = w.Flush() }
		write("220 localhost ESMTP ready\r\n")
		inData := false
		var body strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if strings.TrimSpace(line) == "." {
					write("250 OK queued\r\n")
					inData = false
					received <- body.String()
					continue
				}
				body.WriteString(line)
				continue
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				// Deliberately advertise neither AUTH nor STARTTLS.
				write("250-localhost\r\n250 SIZE 10485760\r\n")
			case cmd == "DATA":
				write("354 End data with <CR><LF>.<CR><LF>\r\n")
				inData = true
				body.Reset()
			case cmd == "QUIT":
				write("221 Bye\r\n")
				return
			default:
				write("250 OK\r\n")
			}
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, received
}

func TestSendOverSMTP(t *testing.T) {
	host, port, received := startFakeSMTP(t)
	cfg := Config{
		Host:          host,
		Port:          port,
		User:          "noreply@example.com",
		Password:      "secret",
		SubjectPrefix: "[NPS] ",
		Timeout:       3 * time.Second,
	}
	if err := Send(cfg, "user@example.com", "登录验证码", "你的验证码是 123456"); err != nil {
		t.Fatal("send failed:", err)
	}
	select {
	case msg := <-received:
		for _, want := range []string{"From: noreply@example.com", "To: user@example.com",
			"Content-Type: text/plain; charset=UTF-8", "123456", "=?UTF-8?"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("message missing %q:\n%s", want, msg)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fake SMTP server received no message")
	}
}

func TestBuildMessageHeaderInjection(t *testing.T) {
	cfg := Config{Host: "h", User: "noreply@example.com", Password: "p"}
	msg := buildMessage(cfg, "user@example.com", "hi\r\nBcc: attacker@x.com", "body")
	if strings.Contains(msg, "\r\nBcc:") || strings.Contains(msg, "\r\n\r\nBcc") {
		// The CRLF must be flattened into the Subject value, never start a
		// new header line that a server would interpret as a recipient.
		t.Fatal("header injection not sanitized")
	}
}
