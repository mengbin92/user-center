package data

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
	"github.com/mengbin92/user-center/pkg/aesgcm"
)

func encryptString(v string, key []byte) (string, error) { return aesgcm.Encrypt(v, key) }
func decryptString(v string, key []byte) (string, error) { return aesgcm.Decrypt(v, key) }

// ---------------------------------------------------------------- challenges

type challengeStore struct {
	d   *Data
	mem *memoryKV
}

func NewChallengeStore(d *Data) biz.ChallengeStore {
	return &challengeStore{d: d, mem: newMemoryKV()}
}

func challengeKey(purpose, id string) string { return "uc:challenge:" + purpose + ":" + id }

func (s *challengeStore) Put(ctx context.Context, c biz.Challenge) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if s.d.redis != nil {
		return s.d.redis.Set(ctx, challengeKey(c.Purpose, c.ID), raw, time.Until(c.ExpiresAt)).Err()
	}
	s.mem.set(challengeKey(c.Purpose, c.ID), raw, c.ExpiresAt)
	return nil
}

func (s *challengeStore) load(ctx context.Context, purpose, id string) (biz.Challenge, []byte, error) {
	key := challengeKey(purpose, id)
	var raw []byte
	var err error
	if s.d.redis != nil {
		raw, err = s.d.redis.Get(ctx, key).Bytes()
		if errors.Is(err, redis.Nil) {
			return biz.Challenge{}, nil, biz.ErrChallengeInvalid
		}
	} else {
		raw, err = s.mem.get(key)
		if errors.Is(err, errMemoryMiss) {
			return biz.Challenge{}, nil, biz.ErrChallengeInvalid
		}
	}
	if err != nil {
		return biz.Challenge{}, nil, biz.ErrDependency
	}
	var c biz.Challenge
	if err := json.Unmarshal(raw, &c); err != nil {
		return biz.Challenge{}, nil, biz.ErrChallengeInvalid
	}
	if time.Now().UTC().After(c.ExpiresAt) {
		_ = s.Delete(ctx, id)
		return biz.Challenge{}, nil, biz.ErrChallengeInvalid
	}
	return c, raw, nil
}

func (s *challengeStore) save(ctx context.Context, c biz.Challenge, raw []byte) error {
	if s.d.redis != nil {
		return s.d.redis.Set(ctx, challengeKey(c.Purpose, c.ID), raw, time.Until(c.ExpiresAt)).Err()
	}
	s.mem.set(challengeKey(c.Purpose, c.ID), raw, c.ExpiresAt)
	return nil
}

func (s *challengeStore) Get(ctx context.Context, purpose, id string) (biz.Challenge, error) {
	c, _, err := s.load(ctx, purpose, id)
	return c, err
}

func (s *challengeStore) Verify(ctx context.Context, purpose, id, code string) (biz.Challenge, error) {
	c, raw, err := s.load(ctx, purpose, id)
	if err != nil {
		return biz.Challenge{}, err
	}
	if c.Attempts >= 10 {
		_ = s.Delete(ctx, id)
		return biz.Challenge{}, biz.ErrChallengeInvalid
	}
	if c.CodeHash == "" {
		return biz.Challenge{}, biz.ErrChallengeInvalid
	}
	if subtle.ConstantTimeCompare([]byte(c.CodeHash), []byte(biz.HMACCode(s.d.challengeSecret(), purpose, code))) != 1 {
		c.Attempts++
		if err := s.save(ctx, c, raw); err != nil {
			return biz.Challenge{}, biz.ErrDependency
		}
		return biz.Challenge{}, biz.ErrChallengeInvalid
	}
	return c, nil
}

func (s *challengeStore) Delete(ctx context.Context, id string) error {
	if s.d.redis != nil {
		keys, _ := s.d.redis.Keys(ctx, "uc:challenge:*:"+id).Result()
		if len(keys) > 0 {
			return s.d.redis.Del(ctx, keys...).Err()
		}
		return nil
	}
	s.mem.deleteSuffix(":" + id)
	return nil
}

// ---------------------------------------------------------------- rate limit

type rateLimiter struct {
	d   *Data
	mem *memoryKV
	mu  sync.Mutex
}

func NewRateLimiter(d *Data) biz.RateLimiter {
	return &rateLimiter{d: d, mem: newMemoryKV()}
}

func (l *rateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if limit <= 0 {
		return true, nil
	}
	now := time.Now().UTC()
	bucket := now.Truncate(window).Unix()
	k := fmt.Sprintf("uc:rate:%s:%d", key, bucket)
	if l.d.redis != nil {
		n, err := l.d.redis.Incr(ctx, k).Result()
		if err != nil {
			return false, biz.ErrDependency
		}
		if n == 1 {
			_ = l.d.redis.Expire(ctx, k, window+time.Second).Err()
		}
		return n <= int64(limit), nil
	}
	raw, _ := l.mem.get(k)
	n := 0
	if len(raw) > 0 {
		_, _ = fmt.Sscanf(string(raw), "%d", &n)
	}
	n++
	l.mem.set(k, []byte(fmt.Sprintf("%d", n)), now.Add(window))
	return n <= limit, nil
}

// ---------------------------------------------------------------- step-up

type stepUpStore struct {
	d   *Data
	mem *memoryKV
}

func NewStepUpStore(d *Data) biz.StepUpStore {
	return &stepUpStore{d: d, mem: newMemoryKV()}
}

func (s *stepUpStore) Put(ctx context.Context, sessionID string, until time.Time) error {
	if s.d.redis != nil {
		return s.d.redis.Set(ctx, "uc:stepup:"+sessionID, until.Format(time.RFC3339Nano), time.Until(until)).Err()
	}
	s.mem.set("uc:stepup:"+sessionID, []byte(until.Format(time.RFC3339Nano)), until)
	return nil
}

func (s *stepUpStore) Get(ctx context.Context, sessionID string) (time.Time, error) {
	var raw []byte
	var err error
	if s.d.redis != nil {
		raw, err = s.d.redis.Get(ctx, "uc:stepup:"+sessionID).Bytes()
		if errors.Is(err, redis.Nil) {
			return time.Time{}, nil
		}
	} else {
		raw, err = s.mem.get("uc:stepup:" + sessionID)
		if errors.Is(err, errMemoryMiss) {
			return time.Time{}, nil
		}
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339Nano, string(raw))
}

func (s *stepUpStore) Delete(ctx context.Context, sessionID string) error {
	if s.d.redis != nil {
		return s.d.redis.Del(ctx, "uc:stepup:"+sessionID).Err()
	}
	s.mem.delete("uc:stepup:" + sessionID)
	return nil
}

// ---------------------------------------------------------------- mail

type mailSender struct {
	d    *Data
	log  *zap.Logger
	conf *conf.Mail
}

func NewMailSender(d *Data, log *zap.Logger, mailConf *conf.Mail) biz.MailSender {
	return &mailSender{d: d, log: log, conf: mailConf}
}

func (m *mailSender) Send(ctx context.Context, to, subject, body string) error {
	driver, from, host, port, username, password := "console", "no-reply@localhost", "", 587, "", ""
	if settings, secret, err := NewSettingsRepo(m.d).GetEmail(ctx, nil); err == nil {
		driver, from, host, port, username = settings.Driver, settings.From, settings.SMTPHost, settings.SMTPPort, settings.SMTPUsername
		if secret != "" {
			if plain, derr := NewSecretBox(m.d.secure).Decrypt(secret); derr == nil {
				password = plain
			}
		}
	}
	if (driver == "" || host == "") && m.conf != nil && m.conf.Smtp != nil && m.conf.Smtp.Host != "" {
		driver, from, host, port = "smtp", m.conf.From, m.conf.Smtp.Host, int(m.conf.Smtp.Port)
		username, password = m.conf.Smtp.Username, m.conf.Smtp.Password
	}
	if driver == "smtp" && host != "" {
		addr := fmt.Sprintf("%s:%d", host, port)
		var auth smtp.Auth
		if username != "" {
			auth = smtp.PlainAuth("", username, password, host)
		}
		if from == "" {
			from = username
		}
		msg := []byte("From: " + from + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/plain; charset=UTF-8\r\n\r\n" + body + "\r\n")
		if err := smtp.SendMail(addr, auth, from, []string{to}, msg); err != nil {
			m.log.Error("send mail failed", zap.String("to", to), zap.Error(err))
			return err
		}
		return nil
	}
	m.log.Info("mail (console driver)", zap.String("to", to), zap.String("subject", subject), zap.String("body", body))
	return nil
}

// ---------------------------------------------------------------- memory KV

var errMemoryMiss = errors.New("memory key miss")

type memoryEntry struct {
	value   []byte
	expires time.Time
}

type memoryKV struct {
	mu   sync.Mutex
	data map[string]memoryEntry
}

func newMemoryKV() *memoryKV { return &memoryKV{data: map[string]memoryEntry{}} }

func (m *memoryKV) set(key string, value []byte, expires time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = map[string]memoryEntry{}
	}
	m.data[key] = memoryEntry{value: append([]byte(nil), value...), expires: expires}
}

func (m *memoryKV) get(key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.data[key]
	if !ok {
		return nil, errMemoryMiss
	}
	if !e.expires.IsZero() && time.Now().After(e.expires) {
		delete(m.data, key)
		return nil, errMemoryMiss
	}
	return append([]byte(nil), e.value...), nil
}

func (m *memoryKV) delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
}

func (m *memoryKV) deleteSuffix(suffix string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.data {
		if strings.HasSuffix(k, suffix) {
			delete(m.data, k)
		}
	}
}
