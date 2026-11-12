// Package mail provides the SMTP delivery used by email verification codes.
//
// The connection strategy mirrors the devtools project (backend/notif):
// port 465 uses implicit TLS, other ports use STARTTLS when advertised,
// authentication is SMTP PLAIN with the configured user as the envelope sender.
// Keeping both projects on the same strategy means the very same smtp_host /
// smtp_port / smtp_user / smtp_pass values can be pasted into nps.conf.
package mail

import (
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the SMTP credentials. Host/User/Password are mandatory; From
// falls back to User, Port falls back to 465.
type Config struct {
	Host          string
	Port          int
	User          string
	Password      string
	From          string
	SubjectPrefix string
	Timeout       time.Duration
}

// Configured reports whether the minimum credentials are present.
func (c Config) Configured() bool {
	return strings.TrimSpace(c.Host) != "" &&
		strings.TrimSpace(c.User) != "" &&
		strings.TrimSpace(c.Password) != "" &&
		strings.TrimSpace(c.FromOrDefault()) != ""
}

// FromOrDefault returns the From header value, defaulting to the SMTP user.
func (c Config) FromOrDefault() string {
	if v := strings.TrimSpace(c.From); v != "" {
		return v
	}
	return strings.TrimSpace(c.User)
}

func (c Config) port() int {
	if c.Port <= 0 {
		return 465
	}
	return c.Port
}

func (c Config) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 15 * time.Second
	}
	return c.Timeout
}

// Send delivers one plain-text message. No dependency on the web framework,
// so callers can plug in configuration from anywhere (or a test server).
func Send(cfg Config, to, subject, body string) error {
	if !cfg.Configured() {
		return fmt.Errorf("mail: smtp not configured")
	}
	to = strings.TrimSpace(to)
	if to == "" || !ValidEmail(to) {
		return fmt.Errorf("mail: invalid recipient")
	}

	port := cfg.port()
	host := strings.TrimSpace(cfg.Host)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	msg := buildMessage(cfg, to, subject, body)

	client, conn, err := dialSMTP(host, addr, port, cfg.timeout())
	if err != nil {
		return err
	}
	defer func() {
		_ = client.Close()
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(cfg.timeout()))

	if ok, _ := client.Extension("AUTH"); ok {
		auth := smtp.PlainAuth("", cfg.User, cfg.Password, host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("mail: smtp auth: %w", err)
		}
	}
	if err := client.Mail(cfg.User); err != nil {
		return fmt.Errorf("mail: smtp MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("mail: smtp RCPT TO: %w", err)
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("mail: smtp DATA: %w", err)
	}
	if _, err := io.WriteString(wc, msg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("mail: smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("mail: smtp commit: %w", err)
	}
	// Some servers close the connection before answering QUIT. The message is
	// already committed at this point, so do not treat it as a failure.
	_ = client.Quit()
	return nil
}

func dialSMTP(host, addr string, port int, timeout time.Duration) (*smtp.Client, net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	tlsCfg := &tls.Config{ServerName: host}
	var (
		conn   net.Conn
		client *smtp.Client
		err    error
	)
	if port == 465 {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err != nil {
			return nil, nil, fmt.Errorf("mail: smtp ssl dial: %w", err)
		}
		client, err = smtp.NewClient(conn, host)
	} else {
		conn, err = dialer.Dial("tcp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("mail: smtp dial: %w", err)
		}
		client, err = smtp.NewClient(conn, host)
		if err == nil {
			if ok, _ := client.Extension("STARTTLS"); ok {
				if err = client.StartTLS(tlsCfg); err != nil {
					_ = client.Close()
					_ = conn.Close()
					return nil, nil, fmt.Errorf("mail: smtp starttls: %w", err)
				}
			}
		}
	}
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, nil, fmt.Errorf("mail: smtp client: %w", err)
	}
	return client, conn, nil
}

func buildMessage(cfg Config, to, subject, body string) string {
	prefix := cfg.SubjectPrefix
	if prefix == "" {
		prefix = "[NPS] "
	}
	messageIDHost := "nps.local"
	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		messageIDHost = h
	}
	headers := []string{
		"From: " + headerValue(cfg.FromOrDefault()),
		"To: " + headerValue(to),
		"Subject: " + mime.QEncoding.Encode("UTF-8", prefix+headerValue(subject)),
		"Date: " + time.Now().Format(time.RFC1123Z),
		fmt.Sprintf("Message-ID: <%d.%s@%s>", time.Now().UnixNano(), randomHex(8), messageIDHost),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + body
}

// headerValue strips CR/LF so untrusted input cannot inject extra headers.
func headerValue(v string) string {
	v = strings.ReplaceAll(v, "\r", " ")
	v = strings.ReplaceAll(v, "\n", " ")
	return strings.TrimSpace(v)
}
