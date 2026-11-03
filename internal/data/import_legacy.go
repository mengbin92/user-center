package data

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

var legacyBcryptHash = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)

type LegacyUser struct {
	ID            int64    `json:"id"`
	Username      string   `json:"username"`
	DisplayName   string   `json:"display_name"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Status        string   `json:"status"`
	PasswordHash  string   `json:"password_hash"`
	RoleCodes     []string `json:"role_codes"`
}

type LegacyImportSpec struct {
	SourceCommit     string       `json:"source_commit"`
	SnapshotPosition string       `json:"snapshot_position"`
	Users            []LegacyUser `json:"users"`
}

type LegacyImportResult struct {
	BatchID     string         `json:"batch_id"`
	Applied     bool           `json:"applied"`
	Counts      map[string]int `json:"counts"`
	Conflicts   []string       `json:"conflicts,omitempty"`
	Fingerprint string         `json:"fingerprint"`
}

// ImportLegacy imports a bounded, validated user snapshot. IDs are preserved;
// sessions, API keys and business attributes are never imported. Dry-run is
// the default at the command layer.
func ImportLegacy(ctx context.Context, d *Data, spec LegacyImportSpec, batchID string, apply bool) (*LegacyImportResult, error) {
	if len(spec.Users) == 0 {
		return nil, fmt.Errorf("snapshot contains no users")
	}
	if batchID == "" {
		batchID = "batch-" + uuid.NewString()
	}
	if len(batchID) > 64 || len(spec.SourceCommit) > 64 || len(spec.SnapshotPosition) > 128 {
		return nil, fmt.Errorf("import provenance exceeds its storage limit")
	}
	if strings.TrimSpace(spec.SourceCommit) == "" {
		return nil, fmt.Errorf("source_commit is required")
	}
	// Validation must not modify the caller's snapshot or change a later
	// apply fingerprint merely because dry-run normalized its slice.
	spec.Users = append([]LegacyUser(nil), spec.Users...)
	raw, err := jsonx.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("encode snapshot: %w", err)
	}
	sum := sha256.Sum256(raw)
	fingerprint := hex.EncodeToString(sum[:])
	result := &LegacyImportResult{BatchID: batchID, Fingerprint: fingerprint, Counts: map[string]int{}}
	seenIDs := map[int64]bool{}
	seenNames := map[string]bool{}
	seenEmails := map[string]bool{}
	for i := range spec.Users {
		u := &spec.Users[i]
		u.Username = strings.TrimSpace(u.Username)
		u.Email = strings.ToLower(strings.TrimSpace(u.Email))
		if u.ID <= 0 {
			result.Conflicts = append(result.Conflicts, fmt.Sprintf("user #%d: id must be positive", i))
		}
		if seenIDs[u.ID] {
			result.Conflicts = append(result.Conflicts, fmt.Sprintf("user #%d: duplicate id %d", i, u.ID))
		}
		seenIDs[u.ID] = true
		name := strings.ToLower(u.Username)
		if name == "" || len(name) > 128 {
			result.Conflicts = append(result.Conflicts, fmt.Sprintf("user %d: invalid username", u.ID))
		}
		if seenNames[name] {
			result.Conflicts = append(result.Conflicts, fmt.Sprintf("user %d: duplicate username %s", u.ID, u.Username))
		}
		seenNames[name] = true
		if u.Email != "" {
			if seenEmails[u.Email] {
				result.Conflicts = append(result.Conflicts, fmt.Sprintf("user %d: duplicate email %s", u.ID, u.Email))
			}
			seenEmails[u.Email] = true
		}
		switch u.Status {
		case "", "1", "enabled":
			u.Status = "enabled"
		case "2", "disabled":
			u.Status = "disabled"
		case "archived":
		default:
			result.Conflicts = append(result.Conflicts, fmt.Sprintf("user %d: invalid status %q", u.ID, u.Status))
		}
		if !legacyBcryptHash.MatchString(u.PasswordHash) {
			result.Conflicts = append(result.Conflicts, fmt.Sprintf("user %d: a valid bcrypt login credential is required", u.ID))
		} else if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err != nil {
			result.Conflicts = append(result.Conflicts, fmt.Sprintf("user %d: invalid bcrypt credential", u.ID))
		}
		if u.Email != "" {
			address, err := mail.ParseAddress(u.Email)
			if err != nil || address.Address != u.Email || len(u.Email) > 254 {
				result.Conflicts = append(result.Conflicts, fmt.Sprintf("user %d: invalid email", u.ID))
			}
		} else if u.EmailVerified {
			result.Conflicts = append(result.Conflicts, fmt.Sprintf("user %d: an empty email cannot be verified", u.ID))
		}
		if u.DisplayName == "" {
			u.DisplayName = u.Username
		}
		if len(u.DisplayName) > 128 {
			result.Conflicts = append(result.Conflicts, fmt.Sprintf("user %d: display name exceeds storage limit", u.ID))
		}
	}
	if len(result.Conflicts) > 0 {
		return result, nil
	}
	// Explicit conflict checks by id, username, email.
	for _, u := range spec.Users {
		var count int64
		name := strings.ToLower(u.Username)
		if err := d.db.WithContext(ctx).Model(&userPO{}).
			Where("id = ? OR username_normalized = ? OR (email_normalized IS NOT NULL AND email_normalized = ?)", u.ID, name, u.Email).
			Count(&count).Error; err != nil {
			return nil, err
		}
		if count > 0 {
			result.Conflicts = append(result.Conflicts, fmt.Sprintf("user %d/%s already exists in the target database", u.ID, u.Username))
		}
	}
	if len(result.Conflicts) > 0 {
		return result, nil
	}
	var roles []rolePO
	if err := d.db.WithContext(ctx).Find(&roles).Error; err != nil {
		return nil, err
	}
	roleByCode := map[string]*rolePO{}
	for i := range roles {
		roleByCode[roles[i].Code] = &roles[i]
	}
	for _, u := range spec.Users {
		seenRoles := map[string]bool{}
		for _, code := range u.RoleCodes {
			if seenRoles[code] {
				result.Conflicts = append(result.Conflicts, fmt.Sprintf("user %d: duplicate role %s", u.ID, code))
			}
			seenRoles[code] = true
			r := roleByCode[code]
			if r == nil || r.Status != "active" {
				result.Conflicts = append(result.Conflicts, fmt.Sprintf("user %d: unknown/disabled role %s", u.ID, code))
			}
		}
	}
	if len(result.Conflicts) > 0 {
		return result, nil
	}
	result.Counts["users"] = len(spec.Users)
	result.Counts["credentials"] = countHashes(spec.Users)
	result.Counts["assignments"] = countAssignments(spec.Users)
	if !apply {
		return result, nil
	}
	now := time.Now().UTC()
	err = d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, u := range spec.Users {
			verified := (*time.Time)(nil)
			if u.EmailVerified {
				t := now
				verified = &t
			}
			p := &userPO{
				ID: u.ID, Username: u.Username, UsernameNormalized: strings.ToLower(u.Username),
				DisplayName: u.DisplayName, Status: u.Status, Revision: 1, IdentityVersion: 1,
				CreatedAt: now, UpdatedAt: now, EmailVerifiedAt: verified,
			}
			if u.Email != "" {
				e, n := u.Email, u.Email
				p.Email, p.EmailNormalized = &e, &n
			}
			if err := tx.Create(p).Error; err != nil {
				return err
			}
			if err := tx.Create(&credentialPO{
				UserID: u.ID, PasswordHash: u.PasswordHash, Algorithm: "bcrypt",
				PasswordVersion: 1, Revision: 1, UpdatedAt: now,
			}).Error; err != nil {
				return err
			}
			for _, code := range u.RoleCodes {
				// The snapshot does not carry the old assignment boundary.
				// Governance roles remain candidates until explicitly reviewed
				// and regranted; missing scope must never become global access.
				status, scope := "pending", authorization.Scope{}
				if code == "member" {
					status, scope = "active", authorization.Scope{Self: true}
				}
				boundary, _ := jsonx.Marshal(scope)
				if err := tx.Create(&assignmentPO{
					UserID: u.ID, RoleID: roleByCode[code].ID, Boundary: string(boundary),
					StartsAt: now, Status: status, Origin: "legacy_candidate",
					Revision: 1, CreatedAt: now,
				}).Error; err != nil {
					return err
				}
			}
		}
		counts, _ := jsonx.Marshal(result.Counts)
		return tx.Create(&legacyImportBatchPO{
			BatchID: batchID, SourceCommit: spec.SourceCommit, SnapshotPosition: spec.SnapshotPosition,
			Counts: string(counts), Fingerprint: fingerprint, State: "completed",
			CreatedAt: now, CompletedAt: &now,
		}).Error
	})
	if err != nil {
		return nil, err
	}
	result.Applied = true
	// MySQL and SQLite both advance their generated-ID sequence when an
	// explicit larger ID is inserted. Avoid a separate, nontransactional DDL
	// operation (and an int64 overflow for the largest imported identifier).
	return result, nil
}

func countHashes(users []LegacyUser) int {
	n := 0
	for _, u := range users {
		if u.PasswordHash != "" {
			n++
		}
	}
	return n
}

func countAssignments(users []LegacyUser) int {
	n := 0
	for _, u := range users {
		n += len(u.RoleCodes)
	}
	return n
}
