package controllers

import (
	"os"
	"strconv"
	"sync"
	"time"

	"ehang.io/nps/lib/mail"
	"github.com/astaxie/beego"
)

// SMTP settings use the same field names as the devtools project, so the four
// values from devtools' config.yaml (smtp_host / smtp_port / smtp_user /
// smtp_pass) can be copied into nps.conf verbatim. Environment variables are
// also honoured, which is handy for docker deployments where the password
// should not live in a mounted config file.
func smtpConfig() mail.Config {
	cfg := mail.Config{
		Host:          beego.AppConfig.String("smtp_host"),
		Port:          beego.AppConfig.DefaultInt("smtp_port", 465),
		User:          beego.AppConfig.String("smtp_user"),
		Password:      beego.AppConfig.String("smtp_pass"),
		From:          beego.AppConfig.String("smtp_from"),
		SubjectPrefix: "[NPS] ",
	}
	if v := os.Getenv("NPS_SMTP_HOST"); v != "" {
		cfg.Host = v
	}
	if v := os.Getenv("NPS_SMTP_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Port = n
		}
	}
	if v := os.Getenv("NPS_SMTP_USER"); v != "" {
		cfg.User = v
	}
	if v := os.Getenv("NPS_SMTP_PASS"); v != "" {
		cfg.Password = v
	}
	if v := os.Getenv("NPS_SMTP_FROM"); v != "" {
		cfg.From = v
	}
	return cfg
}

// emailLoginEnabled is true only when the feature is switched on AND the SMTP
// credentials are complete. An unconfigured server simply keeps the classic
// password login and never exposes the email tab.
func emailLoginEnabled() bool {
	return beego.AppConfig.DefaultBool("email_login_enable", true) && smtpConfig().Configured()
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
