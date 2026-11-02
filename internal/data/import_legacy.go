package data

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

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
		batchID = "batch-" + time.Now().UTC().Format("20060102T150405")
	}
	raw, _ := jsonx.Marshal(spec)
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
		if u.PasswordHash != "" && !strings.HasPrefix(u.PasswordHash, "$2") {
			result.Conflicts = append(result.Conflicts, fmt.Sprintf("user %d: password hash is not bcrypt", u.ID))
		}
		if u.DisplayName == "" {
			u.DisplayName = u.Username
		}
	}
	if len(result.Conflicts) > 0 {
		return result, nil
	}
	var existing int64
	if err := d.db.WithContext(ctx).Model(&userPO{}).Where("id <= ?", maxLegacyID(spec.Users)).Count(&existing).Error; err != nil {
		return nil, err
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
		for _, code := range u.RoleCodes {
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
	err := d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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
				boundary, _ := jsonx.Marshal(authorization.Scope{All: true})
				if err := tx.Create(&assignmentPO{
					UserID: u.ID, RoleID: roleByCode[code].ID, Boundary: string(boundary),
					StartsAt: now, Status: "active", Origin: "legacy_candidate",
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
	if d.conf != nil && d.conf.Database != nil && d.conf.Database.Driver == "mysql" {
		_ = d.db.Exec("ALTER TABLE users AUTO_INCREMENT = ?", maxLegacyID(spec.Users)+1).Error
	}
	return result, nil
}

func maxLegacyID(users []LegacyUser) int64 {
	var max int64
	for _, u := range users {
		if u.ID > max {
			max = u.ID
		}
	}
	return max
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
