package controllers

import (
	"os"
	"strings"
	"sync"
	"time"

	"ehang.io/nps/lib/mail"
	"github.com/astaxie/beego"
)

// mailServiceConfig builds the tenant config for the central mail service.
// Credentials come from the process environment only: no SMTP host, account
// or secret is kept in nps.conf or anywhere else in this repository. Docker
// deployments should pass them with -e (or mount a 0600 file for the secret).
// The sender is optional: mail.DefaultFrom (devtools@jaxiu.cn), the central
// service's own sender, is used when NPS_MAIL_FROM is unset.
func mailServiceConfig() mail.Config {
	cfg := mail.Config{
		BaseURL:       envOrEmpty("NPS_MAIL_BASE_URL"),
		ClientID:      envOrEmpty("NPS_MAIL_CLIENT_ID"),
		ClientSecret:  envOrFile("NPS_MAIL_CLIENT_SECRET"),
		From:          envOrEmpty("NPS_MAIL_FROM"),
		SubjectPrefix: "[NPS] ",
	}
	if v := envOrEmpty("NPS_MAIL_SUBJECT_PREFIX"); v != "" {
		cfg.SubjectPrefix = v
	}
	return cfg
}

func envOrEmpty(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

// envOrFile lets docker deployments keep the client_secret out of the
// process environment (which shows up in docker inspect) by mounting a file:
// NPS_MAIL_CLIENT_SECRET_FILE=/run/secrets/nps_mail_client_secret.
func envOrFile(key string) string {
	if v := envOrEmpty(key); v != "" {
		return v
	}
	if path := envOrEmpty(key + "_FILE"); path != "" {
		if b, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

// emailLoginEnabled is true only when the feature is switched on AND the
// central mail service credentials are complete. An unconfigured server
// simply keeps the classic password login and never exposes the email tab.
func emailLoginEnabled() bool {
	return beego.AppConfig.DefaultBool("email_login_enable", true) && mailServiceConfig().Configured()
}

var (
	codeStoreOnce sync.Once
	globalStore   *mail.CodeStore
)

func emailCodeStore() *mail.CodeStore {
	codeStoreOnce.Do(func() {
		ttl := time.Duration(beego.AppConfig.DefaultInt("email_code_ttl_minutes", 10)) * time.Minute
		resend := time.Duration(beego.AppConfig.DefaultInt("email_code_resend_seconds", 60)) * time.Second
		attempts := beego.AppConfig.DefaultInt("email_code_max_attempts", 5)
		ipLimit := beego.AppConfig.DefaultInt("email_code_ip_limit", 10)
		globalStore = mail.NewCodeStore(ttl, resend, attempts, ipLimit)
	})
	return globalStore
}
