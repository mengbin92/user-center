package biz

import (
	"context"
	"errors"
	"fmt"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

// BootstrapRoot creates the initial highest-governance account. It is only
// invoked by the offline admin-rescue command or a one-time startup bootstrap;
// it never bypasses audit and never creates a hidden HTTP backdoor.
func (s *Services) BootstrapRoot(ctx context.Context, username, email, password string) (*User, error) {
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	if email != "" {
		if err := ValidateEmail(NormalizeEmail(email)); err != nil {
			return nil, err
		}
	}
	if err := ValidatePassword(password, 12); err != nil {
		return nil, err
	}
	if existing, err := s.Users.GetByUsername(ctx, nil, NormalizeUsername(username)); err == nil {
		return existing, errors.New("root username already exists")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	now := s.Clock.Now().UTC()
	u := &User{
		Username: username, UsernameNormalized: NormalizeUsername(username),
		DisplayName: username, Email: NormalizeEmail(email), EmailNormalized: NormalizeEmail(email),
		Status: UserStatusEnabled, Revision: 1, IdentityVersion: 1, CreatedAt: now, UpdatedAt: now,
		EmailVerified: NormalizeEmail(email) != "",
	}
	var created *User
	err = s.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		c, err := s.Users.Create(ctx, tx, u)
		if err != nil {
			return err
		}
		created = c
		if err := s.Credentials.Create(ctx, tx, &Credential{
			UserID: c.ID, PasswordHash: hash, Algorithm: "bcrypt",
			PasswordVersion: 1, Revision: 1, UpdatedAt: now,
		}); err != nil {
			return err
		}
		root, err := s.IAM.GetRoleByCode(ctx, tx, "root")
		if err != nil {
			return fmt.Errorf("root role must be seeded before bootstrap: %w", err)
		}
		if _, err := s.IAM.CreateAssignment(ctx, tx, &Assignment{
			UserID: c.ID, RoleID: root.ID, Boundary: authorization.Scope{All: true},
			StartsAt: now, Origin: OriginBootstrap, Revision: 1, CreatedAt: now,
		}); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, ActorContext{Actor: authorization.Actor{ServiceID: "bootstrap"}}, "account.bootstrap", itoa(c.ID), "{}", "{}", "{}", "offline bootstrap", "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": c.ID, "username": c.Username})
		return s.emit(ctx, tx, "user", c.ID, c.Revision, "user.created", string(payload))
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

// ResetRoot restores the root credential after an operator proves host access.
// Existing sessions are revoked and the identity version is bumped.
func (s *Services) ResetRoot(ctx context.Context, username, password string) error {
	if err := ValidatePassword(password, 12); err != nil {
		return err
	}
	u, err := s.Users.GetByUsername(ctx, nil, NormalizeUsername(username))
	if err != nil {
		return ErrUserNotFound
	}
	root, err := s.IAM.GetRoleByCode(ctx, nil, "root")
	if err != nil {
		return ErrDependency
	}
	roles, _ := s.Users.RolesForUser(ctx, nil, u.ID)
	isRoot := false
	for _, r := range roles {
		if r.ID == root.ID {
			isRoot = true
		}
	}
	if !isRoot {
		return ErrProtectedAccount
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	now := s.Clock.Now().UTC()
	return s.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		cred, err := s.Credentials.Get(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		if _, err := s.Credentials.UpdatePassword(ctx, tx, u.ID, hash, "bcrypt", cred.Revision, false); err != nil {
			return err
		}
		if u.Status != UserStatusEnabled {
			u.Status = UserStatusEnabled
			if _, err := s.Users.Update(ctx, tx, u, u.Revision); err != nil {
				return err
			}
		}
		if _, err := s.Users.BumpIdentityVersion(ctx, tx, u.ID); err != nil {
			return err
		}
		if err := s.Sessions.RevokeAllForUser(ctx, tx, u.ID, &now); err != nil {
			return err
		}
		return s.audit(ctx, tx, ActorContext{Actor: authorization.Actor{ServiceID: "admin-rescue"}}, "account.rescue", itoa(u.ID), "{}", "{}", "{}", "offline root rescue", "success")
	})
}
