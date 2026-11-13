// Package mail delivers verification codes through the central mail service
// at t.jaxiu.cn/api/mail/v1 (OAuth2 client_credentials + POST /send).
//
// This project keeps no local SMTP configuration: no host, no account, no
// authorization code. The tenant credentials are supplied by the caller, in
// practice from the process environment, and the sender must be listed in the
// tenant's from allowlist on the /mail-service admin page.
package mail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is the machine-to-machine endpoint of the central mail service.
const DefaultBaseURL = "https://t.jaxiu.cn/api/mail/v1"

// DefaultFrom is the central mail service's own sender address (mail.from in
// devtools' config.yaml). The service fills it in when a request omits from,
// and it is registered in the nps tenant's from allowlist. It is an address,
// not a credential, so it is safe to keep here as a default.
const DefaultFrom = "devtools@jaxiu.cn"

// Config holds the tenant credentials. ClientID and ClientSecret are
// mandatory; From is optional and falls back to DefaultFrom. A custom From
// must also be added to the tenant's sender allowlist, otherwise the service
// answers 403 from_not_allowed.
type Config struct {
	BaseURL       string
	ClientID      string
	ClientSecret  string
	From          string
	SubjectPrefix string
	Timeout       time.Duration
	HTTPClient    *http.Client // optional, mainly useful for tests
}

// FromOrDefault returns the sender address, falling back to the central
// mail service's default sender.
func (c Config) FromOrDefault() string {
	if v := strings.TrimSpace(c.From); v != "" {
		return v
	}
	return DefaultFrom
}

// Configured reports whether the minimum credentials are present.
func (c Config) Configured() bool {
	return strings.TrimSpace(c.ClientID) != "" &&
		strings.TrimSpace(c.ClientSecret) != "" &&
		ValidEmail(c.FromOrDefault())
}

func (c Config) baseURL() string {
	if v := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/"); v != "" {
		return v
	}
	return DefaultBaseURL
}

func (c Config) subject(subject string) string {
	prefix := c.SubjectPrefix
	if prefix == "" {
		prefix = "[NPS] "
	}
	return prefix + cleanHeaderValue(subject)
}

func (c Config) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 15 * time.Second
	}
	return c.Timeout
}

func (c Config) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: c.timeout()}
}

// cleanHeaderValue strips CR/LF so untrusted input cannot smuggle extra
// headers into the subject when the service builds the MIME message.
func cleanHeaderValue(v string) string {
	v = strings.ReplaceAll(v, "\r", " ")
	v = strings.ReplaceAll(v, "\n", " ")
	return strings.TrimSpace(v)
}

type cachedToken struct {
	value     string
	expiresAt time.Time
}

// access tokens are process local; a restart simply exchanges a new one.
var (
	tokenMu    sync.Mutex
	tokenCache = map[string]cachedToken{}
)

func tokenCacheKey(c Config) string {
	return c.baseURL() + "|" + strings.TrimSpace(c.ClientID)
}

// accessToken returns a cached bearer token, refreshing shortly before
// expiry. force is used after a 401 so a revoked token is replaced at once.
func accessToken(c Config, force bool) (string, error) {
	tokenMu.Lock()
	defer tokenMu.Unlock()
	key := tokenCacheKey(c)
	if !force {
		if t, ok := tokenCache[key]; ok && time.Now().Add(30*time.Second).Before(t.expiresAt) {
			return t.value, nil
		}
	}
	value, ttl, err := requestToken(c)
	if err != nil {
		return "", err
	}
	if ttl <= 0 {
		// Unknown lifetime: keep it briefly instead of caching forever.
		ttl = 300
	}
	tokenCache[key] = cachedToken{
		value:     value,
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
	return value, nil
}

func requestToken(c Config) (string, int, error) {
	form := url.Values{"grant_type": []string{"client_credentials"}}
	req, err := http.NewRequest(http.MethodPost, c.baseURL()+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("mail: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(strings.TrimSpace(c.ClientID), strings.TrimSpace(c.ClientSecret))
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("mail: token request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, fmt.Errorf("mail: read token response: %w", err)
	}
	var out struct {
		AccessToken      string `json:"access_token"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", 0, fmt.Errorf("mail: decode token response (HTTP %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || out.AccessToken == "" {
		return "", 0, fmt.Errorf("mail: oauth token (HTTP %d): %s", resp.StatusCode,
			apiError(out.Error, out.ErrorDescription))
	}
	return out.AccessToken, out.ExpiresIn, nil
}

func apiError(code, description string) string {
	if code == "" {
		code = "unknown_error"
	}
	if description != "" {
		return code + ": " + description
	}
	return code
}

// Send delivers one plain-text message through the central mail service.
// No dependency on the web framework, so callers can plug in configuration
// from anywhere (or a test server).
func Send(c Config, to, subject, body string) error {
	if !c.Configured() {
		return fmt.Errorf("mail: mail service not configured")
	}
	to = strings.TrimSpace(to)
	if to == "" || !ValidEmail(to) {
		return fmt.Errorf("mail: invalid recipient")
	}
	payload, err := json.Marshal(struct {
		From    string   `json:"from"`
		To      []string `json:"to"`
		Subject string   `json:"subject"`
		Body    string   `json:"body"`
	}{
		From:    c.FromOrDefault(),
		To:      []string{to},
		Subject: c.subject(subject),
		Body:    body,
	})
	if err != nil {
		return fmt.Errorf("mail: encode send request: %w", err)
	}

	token, err := accessToken(c, false)
	if err != nil {
		return err
	}
	status, detail, err := postSend(c, token, payload)
	if err != nil {
		return err
	}
	if status == http.StatusUnauthorized {
		// The token may have been revoked server side: exchange a fresh one
		// and retry the exact same message once.
		if token, err = accessToken(c, true); err != nil {
			return err
		}
		if status, detail, err = postSend(c, token, payload); err != nil {
			return err
		}
	}
	if status < 200 || status >= 300 {
		if detail == "" {
			detail = "no error detail"
		}
		return fmt.Errorf("mail: send (HTTP %d): %s", status, detail)
	}
	return nil
}

func postSend(c Config, token string, payload []byte) (int, string, error) {
	req, err := http.NewRequest(http.MethodPost, c.baseURL()+"/send", bytes.NewReader(payload))
	if err != nil {
		return 0, "", fmt.Errorf("mail: build send request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("mail: send request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, "", fmt.Errorf("mail: read send response: %w", err)
	}
	var out struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(raw, &out); err != nil && len(raw) > 0 {
		// A non-JSON error page is still worth reporting verbatim.
		return resp.StatusCode, strings.TrimSpace(string(raw)), nil
	}
	detail := ""
	if out.Error != "" || out.ErrorDescription != "" {
		detail = apiError(out.Error, out.ErrorDescription)
	}
	return resp.StatusCode, detail, nil
}
