package mail

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	// ErrTooFrequent is returned when the same address asks for another code
	// before the resend interval has elapsed.
	ErrTooFrequent = errors.New("verification code requested too frequently")
	// ErrIPRateLimit is returned when one IP exceeds its hourly send quota.
	ErrIPRateLimit = errors.New("too many verification codes from this address")
	// ErrInvalidEmail / ErrInvalidPurpose guard the public entry points.
	ErrInvalidEmail   = errors.New("invalid email address")
	ErrInvalidPurpose = errors.New("invalid verification code purpose")
)

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// Purpose separates a login code from a bind-email code. A code issued for
// one purpose can never be redeemed for the other.
type Purpose string

const (
	PurposeLogin Purpose = "login"
	PurposeBind  Purpose = "bind"
)

// ValidPurpose reports whether p is a supported purpose.
func ValidPurpose(p Purpose) bool {
	return p == PurposeLogin || p == PurposeBind
}

// NormalizeEmail lower-cases and trims an address for stable lookups.
func NormalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// ValidEmail performs a pragmatic format check (the same one devtools uses).
func ValidEmail(s string) bool {
	return emailRe.MatchString(NormalizeEmail(s))
}

// GenNumericCode returns a cryptographically random six digit code.
func GenNumericCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
	}
	return fmt.Sprintf("%06d", n.Int64())
}

type codeEntry struct {
	code      string
	issuedAt  time.Time
	expiresAt time.Time
	attempts  int
}

// CodeStore keeps short lived, single-use codes in memory. It is process
// local by design: nps is a single web process, and a code never needs to
// survive a restart. Both the address and the source IP are rate limited.
type CodeStore struct {
	mu             sync.Mutex
	ttl            time.Duration
	resendInterval time.Duration
	maxAttempts    int
	ipWindow       time.Duration
	ipLimit        int
	codes          map[string]*codeEntry
	ipHits         map[string][]time.Time
	now            func() time.Time
}

// NewCodeStore builds a store. ttl is the code lifetime, resendInterval the
// per-address cooldown, maxAttempts the failed-guess budget, ipLimit the
// number of sends allowed from one IP within ipWindow (one hour).
func NewCodeStore(ttl, resendInterval time.Duration, maxAttempts, ipLimit int) *CodeStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if resendInterval <= 0 {
		resendInterval = 60 * time.Second
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if ipLimit <= 0 {
		ipLimit = 10
	}
	return &CodeStore{
		ttl:            ttl,
		resendInterval: resendInterval,
		maxAttempts:    maxAttempts,
		ipWindow:       time.Hour,
		ipLimit:        ipLimit,
		codes:          make(map[string]*codeEntry),
		ipHits:         make(map[string][]time.Time),
		now:            time.Now,
	}
}

func (s *CodeStore) key(email string, purpose Purpose) string {
	return string(purpose) + "|" + NormalizeEmail(email)
}

// Issue creates (or replaces) a code and returns it so the caller can mail it.
func (s *CodeStore) Issue(email string, purpose Purpose, ip string) (string, error) {
	if !ValidEmail(email) {
		return "", ErrInvalidEmail
	}
	if !ValidPurpose(purpose) {
		return "", ErrInvalidPurpose
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.cleanup(now)

	key := s.key(email, purpose)
	if old, ok := s.codes[key]; ok && now.Sub(old.issuedAt) < s.resendInterval {
		return "", ErrTooFrequent
	}
	ip = strings.TrimSpace(ip)
	if ip != "" {
		hits := s.ipHits[ip][:0]
		for _, t := range s.ipHits[ip] {
			if now.Sub(t) < s.ipWindow {
				hits = append(hits, t)
			}
		}
		if len(hits) >= s.ipLimit {
			s.ipHits[ip] = hits
			return "", ErrIPRateLimit
		}
		hits = append(hits, now)
		s.ipHits[ip] = hits
	}

	code := GenNumericCode()
	s.codes[key] = &codeEntry{code: code, issuedAt: now, expiresAt: now.Add(s.ttl)}
	return code, nil
}

// Revoke drops a code, e.g. when the mail service delivery failed.
func (s *CodeStore) Revoke(email string, purpose Purpose) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, s.key(email, purpose))
}

// Consume validates a code exactly once. Too many wrong guesses invalidate it.
func (s *CodeStore) Consume(email string, purpose Purpose, code string) bool {
	if !ValidEmail(email) || !ValidPurpose(purpose) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	key := s.key(email, purpose)
	e, ok := s.codes[key]
	if !ok || now.After(e.expiresAt) {
		delete(s.codes, key)
		return false
	}
	if strings.TrimSpace(code) != e.code {
		e.attempts++
		if e.attempts >= s.maxAttempts {
			delete(s.codes, key)
		}
		return false
	}
	delete(s.codes, key)
	return true
}

func (s *CodeStore) cleanup(now time.Time) {
	for k, e := range s.codes {
		if now.After(e.expiresAt) {
			delete(s.codes, k)
		}
	}
	for ip, hits := range s.ipHits {
		kept := hits[:0]
		for _, t := range hits {
			if now.Sub(t) < s.ipWindow {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(s.ipHits, ip)
		} else {
			s.ipHits[ip] = kept
		}
	}
}
