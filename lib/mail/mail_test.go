package mail

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
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
	cfg := Config{ClientID: "mt_test", ClientSecret: "secret", From: "noreply@example.com"}
	if !cfg.Configured() {
		t.Fatal("complete tenant config must be configured")
	}
	// From is optional: the central service's default sender is used.
	if !(Config{ClientID: "mt_test", ClientSecret: "secret"}).Configured() {
		t.Fatal("from should be optional")
	}
	if (Config{ClientID: "mt_test", ClientSecret: "secret"}).FromOrDefault() != DefaultFrom {
		t.Fatal("default sender failed")
	}
	if (Config{From: "noreply@example.com"}).FromOrDefault() != "noreply@example.com" {
		t.Fatal("explicit from must win")
	}
	if (Config{ClientID: "mt_test", ClientSecret: "secret", From: "bad"}).Configured() {
		t.Fatal("invalid explicit from must be rejected")
	}
	if cfg.baseURL() != DefaultBaseURL {
		t.Fatal("default base url failed")
	}
	if (Config{BaseURL: "http://127.0.0.1:1/api/mail/v1/"}).baseURL() != "http://127.0.0.1:1/api/mail/v1" {
		t.Fatal("trailing slash not trimmed")
	}
	if cfg.subject("hi") != "[NPS] hi" {
		t.Fatal("subject prefix failed")
	}
	if err := Send(Config{}, "a@b.com", "s", "b"); err == nil {
		t.Fatal("unconfigured send must fail")
	}
	if err := Send(cfg, "not-an-address", "s", "b"); err == nil {
		t.Fatal("invalid recipient must fail")
	}
}

func TestDefaultFromIsSent(t *testing.T) {
	f, srv := newFakeMailService(t, "mt_test", "secret")
	cfg := testConfig(srv)
	cfg.From = "" // NPS_MAIL_FROM unset
	if err := Send(cfg, "user@example.com", "test", "body"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lastFrom != DefaultFrom {
		t.Fatalf("default sender not used, got %q", f.lastFrom)
	}
}

// fakeMailService mimics POST /oauth/token and POST /send so the whole
// client_credentials -> bearer -> JSON send flow can run offline.
type fakeMailService struct {
	mu           sync.Mutex
	clientID     string
	clientSecret string
	token        string
	tokenCalls   int
	sendCalls    int
	basicOK      bool
	grantOK      bool
	lastBearer   string
	lastType     string
	lastFrom     string
	lastTo       []string
	lastSubject  string
	lastBody     string

	// configurable behaviour
	unauthorizedOnce bool
	sendStatus       int
	sendErrorCode    string
	sendErrorDesc    string
	rejectToken      bool
}

func newFakeMailService(t *testing.T, clientID, secret string) (*fakeMailService, *httptest.Server) {
	t.Helper()
	f := &fakeMailService{clientID: clientID, clientSecret: secret}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", f.handleToken)
	mux.HandleFunc("/send", f.handleSend)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeMailService) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	user, pass, ok := r.BasicAuth()
	f.mu.Lock()
	f.tokenCalls++
	f.basicOK = ok && user == f.clientID && pass == f.clientSecret
	f.grantOK = r.PostForm.Get("grant_type") == "client_credentials"
	valid := f.basicOK && f.grantOK
	token := fmt.Sprintf("tk_%d", f.tokenCalls)
	if valid {
		f.token = token
	}
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if !valid || f.rejectToken {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": token, "token_type": "Bearer", "expires_in": 3600, "scope": "mail:send",
	})
}

func (f *fakeMailService) handleSend(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var p struct {
		From    string   `json:"from"`
		To      []string `json:"to"`
		Subject string   `json:"subject"`
		Body    string   `json:"body"`
	}
	_ = json.Unmarshal(raw, &p)

	f.mu.Lock()
	f.sendCalls++
	f.lastBearer = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.lastType = r.Header.Get("Content-Type")
	f.lastFrom, f.lastTo, f.lastSubject, f.lastBody = p.From, p.To, p.Subject, p.Body
	valid := f.lastBearer == f.token
	reject := f.unauthorizedOnce
	if reject {
		f.unauthorizedOnce = false // consume: only the next send is refused
	}
	status := f.sendStatus
	code, desc := f.sendErrorCode, f.sendErrorDesc
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if !valid || reject {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
		return
	}
	if status != 0 {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "sent", "message": "email delivered via mail service"})
}

func testConfig(srv *httptest.Server) Config {
	return Config{
		BaseURL:       srv.URL,
		ClientID:      "mt_test",
		ClientSecret:  "secret",
		From:          "noreply@example.com",
		SubjectPrefix: "[NPS] ",
		Timeout:       3 * time.Second,
		HTTPClient:    srv.Client(),
	}
}

func TestSendViaMailService(t *testing.T) {
	f, srv := newFakeMailService(t, "mt_test", "secret")
	cfg := testConfig(srv)
	if err := Send(cfg, "user@example.com", "登录验证码", "你的验证码是 123456"); err != nil {
		t.Fatal("send failed:", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokenCalls != 1 || f.sendCalls != 1 || !f.basicOK || !f.grantOK {
		t.Fatalf("oauth flow incorrect: token=%d send=%d basic=%v grant=%v",
			f.tokenCalls, f.sendCalls, f.basicOK, f.grantOK)
	}
	if f.lastBearer != "tk_1" || f.lastType != "application/json" {
		t.Fatalf("send headers incorrect: bearer=%q content-type=%q", f.lastBearer, f.lastType)
	}
	if f.lastFrom != "noreply@example.com" || len(f.lastTo) != 1 || f.lastTo[0] != "user@example.com" {
		t.Fatalf("send addresses incorrect: from=%q to=%v", f.lastFrom, f.lastTo)
	}
	if f.lastSubject != "[NPS] 登录验证码" || f.lastBody != "你的验证码是 123456" {
		t.Fatalf("send content incorrect: subject=%q body=%q", f.lastSubject, f.lastBody)
	}
}

func TestTokenReuseAndRefreshAfter401(t *testing.T) {
	f, srv := newFakeMailService(t, "mt_test", "secret")
	cfg := testConfig(srv)
	if err := Send(cfg, "a@x.com", "one", "one"); err != nil {
		t.Fatal(err)
	}
	if err := Send(cfg, "b@x.com", "two", "two"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if f.tokenCalls != 1 || f.sendCalls != 2 {
		t.Fatalf("token should be cached: token=%d send=%d", f.tokenCalls, f.sendCalls)
	}
	f.unauthorizedOnce = true
	f.mu.Unlock()

	// Next send is rejected with 401: the client must force a token refresh
	// and retry, which consumes the "once" flag on the following call.
	if err := Send(cfg, "c@x.com", "three", "three"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokenCalls != 2 || f.sendCalls != 4 || f.lastBearer != "tk_2" {
		t.Fatalf("refresh retry incorrect: token=%d send=%d bearer=%q", f.tokenCalls, f.sendCalls, f.lastBearer)
	}
}

func TestSendErrorPropagation(t *testing.T) {
	f, srv := newFakeMailService(t, "mt_test", "secret")
	f.sendStatus = http.StatusForbidden
	f.sendErrorCode = "from_not_allowed"
	f.sendErrorDesc = "from address not allowed by tenant scope"
	err := Send(testConfig(srv), "a@x.com", "s", "b")
	if err == nil || !strings.Contains(err.Error(), "from_not_allowed") ||
		!strings.Contains(err.Error(), "HTTP 403") {
		t.Fatal("send error not propagated:", err)
	}
}

func TestInvalidClient(t *testing.T) {
	f, srv := newFakeMailService(t, "mt_test", "secret")
	f.rejectToken = true
	err := Send(testConfig(srv), "a@x.com", "s", "b")
	if err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatal("token error not propagated:", err)
	}
}

func TestSubjectHeaderInjection(t *testing.T) {
	f, srv := newFakeMailService(t, "mt_test", "secret")
	if err := Send(testConfig(srv), "a@x.com", "hi\r\nBcc: attacker@x.com", "body"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.ContainsAny(f.lastSubject, "\r\n") || !strings.Contains(f.lastSubject, "Bcc:") {
		t.Fatalf("CR/LF must be flattened into the JSON subject, got %q", f.lastSubject)
	}
}
