package data

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/internal/conf"
)

// Data owns the long-lived MySQL and Redis clients shared by every repository.
// Repositories never open a second pool.
type Data struct {
	db     *gorm.DB
	redis  *redis.Client
	log    *zap.Logger
	conf   *conf.Data
	secure *conf.Security

	// Per-organization schema routing. Tenant pools are opened lazily and
	// cached; the platform pool above stays the default for every request that
	// is not bound to a tenant. See tenancy.go.
	tenancy    *conf.Tenancy
	driver     string
	baseSource string
	tenants    map[int64]*tenantPool
	tenantsMu  sync.Mutex
}

func NewData(dataConf *conf.Data, sec *conf.Security, log *zap.Logger) (*Data, func(), error) {
	driver := "mysql"
	if dataConf != nil && dataConf.Database != nil {
		driver = dataConf.Database.Driver
	}
	if driver == "" {
		driver = "mysql"
	}
	if driver != "mysql" && driver != "sqlite" && driver != "sqlite3" {
		return nil, nil, fmt.Errorf("unsupported database driver %q", driver)
	}
	if driver == "mysql" || sec != nil && sec.CookieSecure {
		if err := validateProductionSecrets(sec); err != nil {
			return nil, nil, err
		}
	}
	var dial gorm.Dialector
	baseSource := ""
	switch driver {
	case "sqlite", "sqlite3":
		source := "file::memory:?cache=shared"
		if dataConf != nil && dataConf.Database != nil && dataConf.Database.Source != "" {
			source = dataConf.Database.Source
		}
		baseSource = source
		if path := strings.TrimPrefix(source, "file:"); path != source {
			if i := strings.IndexByte(path, '?'); i >= 0 {
				path = path[:i]
			}
			if dir := filepath.Dir(path); dir != "." && dir != "" {
				if err := os.MkdirAll(dir, 0o750); err != nil {
					return nil, nil, fmt.Errorf("create sqlite dir: %w", err)
				}
			}
		}
		dial = sqlite.Open(source)
	default:
		source := "usercenter:usercenter@tcp(127.0.0.1:3306)/usercenter?parseTime=true&loc=UTC&charset=utf8mb4"
		if dataConf != nil && dataConf.Database != nil && dataConf.Database.Source != "" {
			source = dataConf.Database.Source
		}
		baseSource = source
		dial = mysql.Open(source)
	}
	db, err := gorm.Open(dial, &gorm.Config{
		Logger:  logger.Default.LogMode(logger.Silent),
		NowFunc: func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, nil, fmt.Errorf("database handle: %w", err)
	}
	maxOpen := 20
	maxIdle := 10
	if dataConf != nil && dataConf.Database != nil {
		if dataConf.Database.MaxOpenConns > 0 {
			maxOpen = int(dataConf.Database.MaxOpenConns)
		}
		if dataConf.Database.MaxIdleConns > 0 {
			maxIdle = int(dataConf.Database.MaxIdleConns)
		}
	}
	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetMaxIdleConns(maxIdle)
	sqlDB.SetConnMaxLifetime(time.Hour)

	var tenancy *conf.Tenancy
	if dataConf != nil {
		tenancy = dataConf.Tenancy
	}
	d := &Data{
		db: db, log: log, conf: dataConf, secure: sec,
		tenancy: tenancy, driver: driver, baseSource: baseSource,
		tenants: make(map[int64]*tenantPool),
	}
	cleanupRedis := func() {}
	if dataConf != nil && dataConf.Redis != nil && dataConf.Redis.Addr != "" {
		rc := redis.NewClient(&redis.Options{
			Addr:     dataConf.Redis.Addr,
			Password: dataConf.Redis.Password,
			DB:       int(dataConf.Redis.Db),
		})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := rc.Ping(ctx).Err(); err != nil {
			_ = rc.Close()
			_ = sqlDB.Close()
			return nil, nil, fmt.Errorf("configured redis is unavailable: %w", err)
		} else {
			d.redis = rc
			cleanupRedis = func() { _ = rc.Close() }
		}
	}
	cleanup := func() {
		cleanupRedis()
		d.closeTenantPools()
		_ = sqlDB.Close()
	}
	return d, cleanup, nil
}

func validateProductionSecrets(sec *conf.Security) error {
	if sec == nil {
		return fmt.Errorf("production security configuration is required")
	}
	for _, field := range []struct{ name, value string }{
		{"SESSION_SECRET", sec.SessionSecret},
		{"CSRF_SECRET", sec.CsrfSecret},
		{"MFA_ENCRYPTION_KEY", sec.MfaEncryptionKey},
	} {
		value := strings.TrimSpace(field.value)
		if len(value) < 32 || strings.HasPrefix(value, "sample-") || strings.HasPrefix(value, "dev-") || strings.HasPrefix(value, "development-") {
			return fmt.Errorf("%s must be a non-sample secret of at least 32 bytes in production", field.name)
		}
	}
	return nil
}

func (d *Data) DB() *gorm.DB { return d.db }

func (d *Data) challengeSecret() string {
	if d.secure != nil && d.secure.SessionSecret != "" {
		return d.secure.SessionSecret
	}
	return "development-only-challenge-secret"
}

func (d *Data) SessionSecret() string {
	if d.secure != nil {
		return d.secure.SessionSecret
	}
	return ""
}

func (d *Data) CSRFSecret() string {
	if d.secure != nil {
		return d.secure.CsrfSecret
	}
	return ""
}

func (d *Data) Redis() *redis.Client { return d.redis }

// AutoMigrate is used by tests and development SQLite only. Production schema
// changes go through versioned SQL migrations.
func (d *Data) AutoMigrate() error {
	return d.db.AutoMigrate(models()...)
}

func (d *Data) InTx(ctx context.Context, fn func(context.Context, biz.Tx) error) error {
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(ctx, tx)
	})
}

func (d *Data) dbOr(tx biz.Tx) *gorm.DB {
	if g, ok := tx.(*gorm.DB); ok && g != nil {
		return g
	}
	return d.db
}

type Clock struct{}

func (Clock) Now() time.Time { return time.Now().UTC() }

type IDs struct{}

func (IDs) NewID() string { return uuid.NewString() }

type SecretBox struct {
	key []byte
}

func NewSecretBox(sec *conf.Security) *SecretBox {
	raw := ""
	if sec != nil {
		raw = sec.MfaEncryptionKey
	}
	sum := sha256.Sum256([]byte(raw))
	return &SecretBox{key: sum[:]}
}

func (s *SecretBox) Encrypt(v string) (string, error) {
	return encryptString(v, s.key)
}

func (s *SecretBox) Decrypt(v string) (string, error) {
	return decryptString(v, s.key)
}

func models() []any {
	return []any{
		&userPO{}, &credentialPO{}, &passwordHistoryPO{}, &mfaPO{}, &externalIdentityPO{},
		&sessionPO{}, &sessionRolePO{}, &securityEventPO{}, &flowCompletionPO{},
		&policyStatePO{}, &resourcePO{}, &permissionPO{}, &rolePO{},
		&roleGrantPO{}, &roleInheritancePO{}, &assignmentPO{}, &delegationPO{}, &constraintPO{},
		&menuPO{}, &auditEventPO{}, &authSettingsPO{}, &emailSettingsPO{},
		&exportJobPO{}, &outboxEventPO{}, &deliveryPO{}, &integrationClientPO{}, &legacyImportBatchPO{}, &organizationPO{}, &organizationMemberPO{}, &organizationDepartmentPO{}, &organizationInvitationPO{}, &oidcClientPO{}, &oidcCodePO{}, &oidcRefreshPO{}, &oidcConsentPO{}, &oidcConsentRequestPO{}, &webauthnCredentialPO{}, &legalHoldPO{},
		&scimTokenPO{}, &scimIdentityPO{}, &scimGroupPO{}, &scimGroupMemberPO{},
		&directorySourcePO{}, &directoryRunPO{}, &directoryObjectPO{},
	}
}
