package biz

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mengbin92/user-center/domain/authorization"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

type UpdateMeInput struct {
	DisplayName      string
	UpdateMask       string
	ExpectedRevision uint64
}

type CreateUserInput struct {
	Username        string
	Email           string
	DisplayName     string
	RoleIDs         []int64
	SendActivation  bool
	InitialPassword string
	Reason          string
}

type UpdateUserInput struct {
	DisplayName      string
	UpdateMask       string
	ExpectedRevision uint64
	ExpectedPolicy   uint64
	Reason           string
}

type UserListItem struct {
	User       *User
	MFAEnabled bool
}

type Overview struct {
	Total, Enabled, Disabled, Archived, MFA, ActiveSessions, Logins24h, Failed24h int64
}

func (uc *UserUsecase) Me(ctx context.Context, actor ActorContext) (*User, error) {
	u, err := uc.Users.Get(ctx, nil, actor.User.ID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	roles, _ := uc.Users.RolesForUser(ctx, nil, u.ID)
	u.Roles = roles
	if state, err := uc.MFA.Get(ctx, nil, u.ID); err == nil {
		u.MFAEnabled = state.Enabled()
	}
	return u, nil
}

func (uc *UserUsecase) UpdateMe(ctx context.Context, actor ActorContext, in UpdateMeInput) (*User, error) {
	if _, err := mutationFields(in.UpdateMask, "display_name"); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(in.DisplayName)
	if name == "" || len([]rune(name)) > 64 {
		return nil, Validation("昵称必须为 1-64 个字符")
	}
	if in.ExpectedRevision != actor.User.Revision {
		return nil, ConflictRevision(actor.User.Revision)
	}
	var updated *User
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		user := *actor.User
		user.DisplayName = name
		var err error
		updated, err = uc.Users.Update(ctx, tx, &user, in.ExpectedRevision)
		if err != nil {
			return err
		}
		if err := uc.audit(ctx, tx, actor, "identity.user.profile.update", itoa(user.ID), "{}", "{}", "{}", "self-service profile update", "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": itoa(updated.ID), "display_name": name})
		return uc.emit(ctx, tx, "user", updated.ID, updated.Revision, "user.profile.updated", string(payload))
	})
	if err != nil {
		return nil, err
	}
	return uc.Me(ctx, ActorContext{User: updated, Session: actor.Session, Actor: actor.Actor})
}

func (uc *UserUsecase) ChangePassword(ctx context.Context, actor ActorContext, current, next string) error {
	settings, err := uc.Settings.GetAuth(ctx, nil)
	if err != nil {
		return ErrDependency
	}
	cred, err := uc.Credentials.Get(ctx, nil, actor.User.ID)
	if err != nil && !errors.Is(err, ErrResourceNotFound) {
		return ErrDependency
	}
	if err := uc.confirmPrimaryAuthentication(ctx, actor, current); err != nil {
		return err
	}
	if cred == nil || cred.PasswordHash == "" {
		mfa, err := uc.MFA.Get(ctx, nil, actor.User.ID)
		if err != nil && !errors.Is(err, ErrResourceNotFound) {
			return ErrDependency
		}
		if mfa != nil && mfa.Enabled() {
			if err := uc.RequireStepUp(ctx, actor); err != nil {
				return err
			}
		}
	}
	policy := settings.PasswordPolicy()
	if err := ValidatePassword(next, policy); err != nil {
		return err
	}
	if err := uc.CheckPasswordReuse(ctx, nil, actor.User.ID, next, policy, cred); err != nil {
		return err
	}
	if cred != nil && VerifyPassword(cred.PasswordHash, next) {
		return Validation("新密码不能与当前密码相同")
	}
	hash, err := HashPassword(next)
	if err != nil {
		return ErrDependency
	}
	if err := uc.clearStepUp(ctx, actor.Session); err != nil {
		return err
	}
	now := uc.Clock.Now().UTC()
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if cred == nil || cred.PasswordHash == "" {
			user, err := uc.Users.Get(ctx, tx, actor.User.ID)
			if err != nil {
				return ErrDependency
			}
			if user.IdentityVersion != actor.Session.IdentityVersion {
				return ErrStepUpRequired
			}
			if _, err := uc.Users.Update(ctx, tx, user, user.Revision); err != nil {
				return err
			}
		}
		if cred == nil {
			if err := uc.Credentials.Create(ctx, tx, &Credential{UserID: actor.User.ID, PasswordHash: hash, Algorithm: "bcrypt", PasswordVersion: 1, Revision: 1, ChangedAt: now, UpdatedAt: now}); err != nil {
				return err
			}
		} else {
			if _, err := uc.Credentials.UpdatePassword(ctx, tx, actor.User.ID, hash, "bcrypt", cred.Revision, false); err != nil {
				return err
			}
		}
		if err := uc.RecordPasswordHistory(ctx, tx, actor.User.ID, hash, policy); err != nil {
			return ErrDependency
		}
		version, err := uc.Users.BumpIdentityVersion(ctx, tx, actor.User.ID)
		if err != nil {
			return err
		}
		rows, err := uc.Sessions.ListByUser(ctx, tx, actor.User.ID)
		if err != nil {
			return err
		}
		for _, s := range rows {
			if s.ID == actor.Session.ID {
				continue
			}
			if err := uc.Sessions.Revoke(ctx, tx, s.ID, &now); err != nil {
				return err
			}
		}
		if err := uc.Sessions.SetIdentityVersion(ctx, tx, actor.Session.ID, version); err != nil {
			return err
		}
		if err := uc.audit(ctx, tx, actor, "credential.password.change", itoa(actor.User.ID), "{}", "{}", "{}", "self-service password change", "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": actor.User.ID, "identity_version": version})
		return uc.emit(ctx, tx, "user", actor.User.ID, version, "credential.changed", string(payload))
	})
}

func (uc *UserUsecase) CreateEmailChallenge(ctx context.Context, actor ActorContext, newEmail, password string) (string, time.Time, error) {
	if err := uc.Services.confirmPassword(ctx, actor.User.ID, password); err != nil {
		return "", time.Time{}, err
	}
	newEmail = NormalizeEmail(newEmail)
	if err := ValidateEmail(newEmail); err != nil {
		return "", time.Time{}, err
	}
	if other, err := uc.Users.GetByEmail(ctx, nil, newEmail); err == nil && other.ID != actor.User.ID {
		return "", time.Time{}, Validation("该邮箱已被使用")
	}
	code, err := GenerateCode()
	if err != nil {
		return "", time.Time{}, ErrDependency
	}
	id := uc.IDs.NewID()
	expires := uc.Clock.Now().Add(uc.ChallengeTTL)
	if err := uc.Challenges.Put(ctx, Challenge{
		ID: id, Purpose: "email_change",
		CodeHash: HMACCode(uc.CodeSecret, "email_change", code),
		UserID:   actor.User.ID, Email: newEmail, ExpiresAt: expires,
	}); err != nil {
		return "", time.Time{}, ErrDependency
	}
	if err := uc.Mail.Send(ctx, newEmail, "用户中心邮箱验证码", fmt.Sprintf("你的邮箱绑定验证码是 %s，%d 分钟内有效。", code, int(uc.ChallengeTTL.Minutes()))); err != nil {
		return "", time.Time{}, ErrDependency
	}
	return id, expires, nil
}

func (uc *UserUsecase) ConfirmEmail(ctx context.Context, actor ActorContext, challengeID, code string) (*User, error) {
	if err := uc.clearStepUp(ctx, actor.Session); err != nil {
		return nil, err
	}
	c, err := uc.Challenges.Verify(ctx, "email_change", challengeID, code)
	if err != nil {
		return nil, err
	}
	if c.UserID != actor.User.ID {
		return nil, ErrChallengeInvalid
	}
	email := NormalizeEmail(c.Email)
	if err := ValidateEmail(email); err != nil {
		return nil, err
	}
	if other, err := uc.Users.GetByEmail(ctx, nil, email); err == nil && other.ID != actor.User.ID {
		return nil, Validation("该邮箱已被使用")
	}
	now := uc.Clock.Now().UTC()
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		u, err := uc.Users.Get(ctx, tx, actor.User.ID)
		if err != nil {
			return err
		}
		u.Email, u.EmailNormalized, u.EmailVerified = email, email, true
		if _, err := uc.Users.Update(ctx, tx, u, u.Revision); err != nil {
			return err
		}
		version, err := uc.Users.BumpIdentityVersion(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		if err := uc.Sessions.SetIdentityVersion(ctx, tx, actor.Session.ID, version); err != nil {
			return err
		}
		rows, err := uc.Sessions.ListByUser(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		for _, sess := range rows {
			if sess.ID == actor.Session.ID {
				continue
			}
			if err := uc.Sessions.Revoke(ctx, tx, sess.ID, &now); err != nil {
				return err
			}
		}
		if err := uc.Flows.Complete(ctx, tx, c.ID, "email_change", u.ID, "email"); err != nil {
			return err
		}
		if err := uc.audit(ctx, tx, actor, "identity.user.email.update", itoa(u.ID), "{}", "{}", "{}", "self-service email binding", "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": u.ID, "email_verified": true, "at": now})
		return uc.emit(ctx, tx, "user", u.ID, u.Revision, "user.profile.updated", string(payload))
	})
	if err != nil {
		return nil, err
	}
	_ = uc.Challenges.Delete(ctx, c.ID)
	return uc.Me(ctx, actor)
}

func (uc *UserUsecase) CreateAdminEmailChange(ctx context.Context, actor ActorContext, targetID int64, newEmail, reason string) (string, time.Time, error) {
	if _, err := uc.managementTarget(ctx, nil, actor, targetID, false); err != nil {
		return "", time.Time{}, err
	}
	if _, err := uc.Authorize(ctx, actor, "identity.user.email_binding.update", targetID, false); err != nil {
		return "", time.Time{}, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return "", time.Time{}, err
	}
	newEmail = NormalizeEmail(newEmail)
	if err := ValidateEmail(newEmail); err != nil {
		return "", time.Time{}, err
	}
	user, err := uc.Users.Get(ctx, nil, targetID)
	if err != nil {
		return "", time.Time{}, ErrUserNotFound
	}
	if user.Status == UserStatusArchived {
		return "", time.Time{}, Validation("已归档账号不能变更邮箱")
	}
	if other, err := uc.Users.GetByEmail(ctx, nil, newEmail); err == nil && other.ID != targetID {
		return "", time.Time{}, Validation("该邮箱已被使用")
	}
	code, err := GenerateCode()
	if err != nil {
		return "", time.Time{}, ErrDependency
	}
	challengeID := uc.IDs.NewID()
	expires := uc.Clock.Now().Add(uc.ChallengeTTL)
	if err := uc.Challenges.Put(ctx, Challenge{
		ID: challengeID, Purpose: "admin_email_change",
		CodeHash: HMACCode(uc.CodeSecret, "admin_email_change", code),
		UserID:   targetID, Email: newEmail, ExpiresAt: expires,
	}); err != nil {
		return "", time.Time{}, ErrDependency
	}
	if err := uc.Mail.Send(ctx, newEmail, "用户中心邮箱变更验证码", fmt.Sprintf("管理员发起邮箱变更。验证码：%s，%d 分钟内有效。", code, int(uc.ChallengeTTL.Minutes()))); err != nil {
		return "", time.Time{}, ErrDependency
	}
	_ = uc.audit(ctx, nil, actor, "identity.user.email.change_request", itoa(targetID), "{}", "{}", string(mustJSON(map[string]string{"new_email": newEmail})), reason, "success")
	return challengeID, expires, nil
}

func (uc *UserUsecase) ConfirmAdminEmailChange(ctx context.Context, actor ActorContext, targetID int64, challengeID, code, reason string) (*User, error) {
	if _, err := uc.managementTarget(ctx, nil, actor, targetID, false); err != nil {
		return nil, err
	}
	if _, err := uc.Authorize(ctx, actor, "identity.user.email_binding.update", targetID, false); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	c, err := uc.Challenges.Verify(ctx, "admin_email_change", challengeID, code)
	if err != nil {
		return nil, err
	}
	if c.UserID != targetID {
		return nil, ErrChallengeInvalid
	}
	email := NormalizeEmail(c.Email)
	now := uc.Clock.Now().UTC()
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.managementTarget(ctx, tx, actor, targetID, false); err != nil {
			return err
		}
		u, err := uc.Users.Get(ctx, tx, targetID)
		if err != nil {
			return ErrUserNotFound
		}
		if other, oerr := uc.Users.GetByEmail(ctx, tx, email); oerr == nil && other.ID != targetID {
			return Validation("该邮箱已被使用")
		}
		u.Email, u.EmailNormalized, u.EmailVerified = email, email, true
		if _, err := uc.Users.Update(ctx, tx, u, u.Revision); err != nil {
			return err
		}
		version, err := uc.Users.BumpIdentityVersion(ctx, tx, targetID)
		if err != nil {
			return err
		}
		if err := uc.Sessions.RevokeAllForUser(ctx, tx, targetID, &now); err != nil {
			return err
		}
		if err := uc.Flows.Complete(ctx, tx, c.ID, "admin_email_change", targetID, "email"); err != nil {
			return err
		}
		if err := uc.audit(ctx, tx, actor, "identity.user.email.update", itoa(targetID), "{}", "{}", string(mustJSON(map[string]string{"new_email": email})), reason, "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": targetID, "email_verified": true, "identity_version": version})
		return uc.emit(ctx, tx, "user", targetID, version, "user.profile.updated", string(payload))
	})
	if err != nil {
		return nil, err
	}
	_ = uc.Challenges.Delete(ctx, challengeID)
	return uc.loadUserWithRoles(ctx, actor, targetID)
}

func (uc *UserUsecase) ExternalIdentities(ctx context.Context, actor ActorContext) ([]*ExternalIdentity, error) {
	return uc.Identities.ListByUser(ctx, nil, actor.User.ID)
}

func (uc *UserUsecase) DeleteExternalIdentity(ctx context.Context, actor ActorContext, id int64) error {
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return err
	}
	user, err := uc.Users.Get(ctx, nil, actor.User.ID)
	if err != nil {
		return ErrDependency
	}
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		// The user CAS serializes removal of different external identities.
		// Counting before this lock would let both requests remove the last
		// two login methods after observing the same count.
		if _, err := uc.Users.Update(ctx, tx, user, user.Revision); err != nil {
			return err
		}
		identity, err := uc.Identities.GetByID(ctx, tx, id)
		if errors.Is(err, ErrResourceNotFound) || err == nil && identity.UserID != actor.User.ID {
			return ErrResourceNotFound
		}
		if err != nil {
			return ErrDependency
		}
		cred, err := uc.Credentials.Get(ctx, tx, actor.User.ID)
		if err != nil && !errors.Is(err, ErrResourceNotFound) {
			return ErrDependency
		}
		passwordAvailable := cred != nil && cred.PasswordHash != ""
		count, err := uc.Identities.CountByUser(ctx, tx, actor.User.ID)
		if err != nil {
			return ErrDependency
		}
		if !passwordAvailable && count <= 1 {
			return ErrLastLoginMethod
		}
		if err := uc.Identities.Delete(ctx, tx, id, actor.User.ID); err != nil {
			return err
		}
		if err := uc.audit(ctx, tx, actor, "identity.external.unbind", itoa(actor.User.ID), "{}", "{}", "{}", "self-service external identity removal", "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": actor.User.ID, "provider": identity.Provider})
		return uc.emit(ctx, tx, "user", actor.User.ID, user.Revision, "user.profile.updated", string(payload))
	})
}

func (uc *UserUsecase) SecurityEvents(ctx context.Context, actor ActorContext, pageSize int, token string) ([]*SecurityEvent, string, error) {
	offset, err := DecodePageToken(token, "self-events")
	if err != nil {
		return nil, "", err
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	items, _, err := uc.Events.ListByUser(ctx, nil, actor.User.ID, pageSize, itoa(int64(offset)))
	if err != nil {
		return nil, "", ErrDependency
	}
	next := ""
	if len(items) == pageSize {
		next = EncodePageToken(offset+len(items), "self-events")
	}
	return items, next, nil
}

// Overview reports scoped counters. Counters never turn an unauthorized read
// into zero; the caller must hold identity.user.list.
func (uc *UserUsecase) OverviewView(ctx context.Context, actor ActorContext) (*Overview, error) {
	filter, _, err := uc.listUserFilter(ctx, actor, "identity.user.list", UserFilter{})
	if err != nil {
		return nil, err
	}
	now := uc.Clock.Now().UTC()
	stats, err := uc.Users.Overview(ctx, nil, filter, now.Add(-24*time.Hour), now)
	if err != nil {
		return nil, ErrDependency
	}
	return stats, nil
}

// ListScope authorizes a tenant-scoped list and returns the coarse SQL filter.
// Deny scopes are applied per row by FilterVisible.
func (s *Services) ListScope(ctx context.Context, actor ActorContext, operation string) (authorization.Scope, error) {
	facts, err := s.LoadAuthzFacts(ctx, actor.User.ID, actor.Session.ActiveRoleIDs)
	if err != nil {
		return authorization.Scope{}, ErrAuthorizationDown
	}
	return s.scopeWithFacts(ctx, facts, actor, operation)
}

// scopeWithFacts is ListScope for callers that already hold a snapshot. Listing
// a page needs the same facts for the scope, the deny scan and every row, so
// reloading them per helper made one request read the policy four times.
func (s *Services) scopeWithFacts(ctx context.Context, facts *AuthzFacts, actor ActorContext, operation string) (authorization.Scope, error) {
	p, err := s.permissionWithFacts(ctx, facts, operation)
	if err != nil {
		return authorization.Scope{}, ErrPermissionDenied
	}
	if p.Status != PermissionStatusActive || p.Binding != BindingBound {
		return authorization.Scope{}, ErrPermissionDenied
	}
	now := s.Clock.Now()
	if !actor.Actor.Valid(now) || actor.User.Status != UserStatusEnabled || !actor.Session.Valid(now) {
		return authorization.Scope{}, ErrPermissionDenied
	}
	if CheckConstraints(actor.Session.ActiveRoleIDs, facts.Constraints) != nil {
		return authorization.Scope{}, ErrPermissionDenied
	}
	if err := s.requireAdminMFA(ctx, actor); err != nil {
		return authorization.Scope{}, err
	}
	scope := scopeForFacts(facts, actor, operation, s.Clock.Now())
	if scope.Empty() {
		return authorization.Scope{}, ErrPermissionDenied
	}
	return scope, nil
}

func (uc *UserUsecase) ListUsers(ctx context.Context, actor ActorContext, filter UserFilter) ([]*UserListItem, int64, error) {
	filter, facts, err := uc.listUserFilter(ctx, actor, "identity.user.list", filter)
	if err != nil {
		return nil, 0, err
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 20
	}
	users, total, err := uc.Users.List(ctx, nil, filter)
	if err != nil {
		return nil, 0, ErrDependency
	}
	// The scope filter above already loaded the snapshot; reusing it here keeps
	// a page of rows down to two batch lookups plus two permission reads.
	ids := make([]int64, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	roleMap, err := uc.Users.RolesForUsers(ctx, nil, ids)
	if err != nil {
		return nil, 0, ErrDependency
	}
	mfaMap, err := uc.MFA.ListByUsers(ctx, nil, ids)
	if err != nil {
		return nil, 0, ErrDependency
	}
	out := make([]*UserListItem, 0, len(users))
	for _, u := range users {
		d, derr := uc.decideWithFacts(ctx, facts, actor, "identity.user.list", u.ID, false)
		if derr != nil {
			return nil, 0, ErrAuthorizationDown
		}
		if !d.Allowed {
			continue
		}
		u.Roles = roleMap[u.ID]
		if state := mfaMap[u.ID]; state != nil {
			u.MFAEnabled = state.Enabled()
		}
		if contact, cerr := uc.decideWithFacts(ctx, facts, actor, "identity.user.contact.read", u.ID, false); cerr != nil || !contact.Allowed {
			u.Email = ""
			u.EmailNormalized = ""
		}
		out = append(out, &UserListItem{User: u, MFAEnabled: u.MFAEnabled})
	}
	return out, total, nil
}

func (uc *UserUsecase) GetUser(ctx context.Context, actor ActorContext, id int64) (*User, error) {
	if _, err := uc.Authorize(ctx, actor, "identity.user.read", id, false); err != nil {
		return nil, err
	}
	u, err := uc.Users.Get(ctx, nil, id)
	if err != nil {
		return nil, ErrUserNotFound
	}
	u.Roles, _ = uc.Users.RolesForUser(ctx, nil, id)
	if state, merr := uc.MFA.Get(ctx, nil, id); merr == nil {
		u.MFAEnabled = state.Enabled()
	}
	if d, derr := uc.Decide(ctx, actor, "identity.user.contact.read", id, false); derr != nil || !d.Allowed {
		u.Email, u.EmailNormalized = "", ""
	}
	return u, nil
}

func (uc *UserUsecase) loadUserWithRoles(ctx context.Context, actor ActorContext, id int64) (*User, error) {
	u, err := uc.Users.Get(ctx, nil, id)
	if err != nil {
		return nil, ErrUserNotFound
	}
	u.Roles, _ = uc.Users.RolesForUser(ctx, nil, id)
	if state, merr := uc.MFA.Get(ctx, nil, id); merr == nil {
		u.MFAEnabled = state.Enabled()
	}
	if d, derr := uc.Decide(ctx, actor, "identity.user.contact.read", id, false); derr != nil || !d.Allowed {
		u.Email, u.EmailNormalized = "", ""
	}
	return u, nil
}

func (uc *UserUsecase) CreateUser(ctx context.Context, actor ActorContext, in CreateUserInput) (*User, error) {
	if err := uc.managementPolicy(ctx, nil, actor); err != nil {
		return nil, err
	}
	if _, err := uc.Authorize(ctx, actor, "identity.user.create", 0, true); err != nil {
		return nil, err
	}
	in.Username = strings.TrimSpace(in.Username)
	in.Email = NormalizeEmail(in.Email)
	if err := ValidateUsername(in.Username); err != nil {
		return nil, err
	}
	if in.Email != "" {
		if err := ValidateEmail(in.Email); err != nil {
			return nil, err
		}
	}
	settings, err := uc.Settings.GetAuth(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	displayName := strings.TrimSpace(in.DisplayName)
	if displayName == "" {
		displayName = in.Username
	}
	var hash string
	if in.InitialPassword != "" {
		if _, err := uc.Authorize(ctx, actor, "identity.user.credential.update", 0, true); err != nil {
			return nil, err
		}
		if err := uc.RequireStepUp(ctx, actor); err != nil {
			return nil, err
		}
		if err := ValidatePassword(in.InitialPassword, settings.PasswordPolicy()); err != nil {
			return nil, err
		}
		hash, err = HashPassword(in.InitialPassword)
		if err != nil {
			return nil, ErrDependency
		}
	}
	member, err := uc.IAM.GetRoleByCode(ctx, nil, "member")
	if err != nil {
		return nil, ErrDependency
	}
	if member.Status != RoleStatusActive {
		return nil, Validation("默认成员角色不可用")
	}
	for _, roleID := range in.RoleIDs {
		if roleID != member.ID {
			return nil, ErrPermissionDenied
		}
	}
	roleIDs := []int64{member.ID}
	if hash == "" && in.Email == "" {
		return nil, Validation("未设置初始密码时必须提供激活邮箱")
	}
	now := uc.Clock.Now().UTC()
	// An account created without an initial password has no password age; leave
	// it zero so the expiry rule never treats it as stale.
	var changedAt time.Time
	if hash != "" {
		changedAt = now
	}
	u := &User{
		Username: in.Username, UsernameNormalized: NormalizeUsername(in.Username),
		DisplayName: displayName, Email: in.Email, EmailNormalized: NormalizeEmail(in.Email),
		Status: UserStatusEnabled, Revision: 1, IdentityVersion: 1,
		CreatedAt: now, UpdatedAt: now,
	}
	var created *User
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.managementPolicy(ctx, tx, actor); err != nil {
			return err
		}
		created0, err := uc.Users.Create(ctx, tx, u)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrUsernameExists
			}
			return err
		}
		created = created0
		if err := uc.Credentials.Create(ctx, tx, &Credential{
			UserID: created.ID, PasswordHash: hash, Algorithm: "bcrypt",
			PasswordVersion: 1, MustChangePassword: hash != "", ChangedAt: changedAt, Revision: 1, UpdatedAt: now,
		}); err != nil {
			return err
		}
		if hash != "" {
			if err := uc.RecordPasswordHistory(ctx, tx, created.ID, hash, settings.PasswordPolicy()); err != nil {
				return ErrDependency
			}
		}
		for _, roleID := range roleIDs {
			if _, err := uc.IAM.CreateAssignment(ctx, tx, &Assignment{
				UserID: created.ID, RoleID: roleID,
				Boundary: authorization.Scope{All: true}, StartsAt: now,
				Origin: OriginExplicit, AssignedBy: actor.User.ID, Revision: 1, CreatedAt: now,
			}); err != nil {
				return err
			}
		}
		if err := uc.audit(ctx, tx, actor, "identity.user.create", itoa(created.ID), "{}", "{}", "{}", in.Reason, "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": created.ID, "username": created.Username, "role_ids": roleIDs})
		return uc.emit(ctx, tx, "user", created.ID, created.Revision, "user.created", string(payload))
	})
	if err != nil {
		return nil, err
	}
	if hash == "" || in.SendActivation {
		if code, cerr := uc.createActivation(ctx, created, actor); cerr == nil {
			_ = code
		}
	}
	created.Roles, _ = uc.Users.RolesForUser(ctx, nil, created.ID)
	return created, nil
}

func (uc *UserUsecase) createActivation(ctx context.Context, user *User, actor ActorContext) (string, error) {
	if user.Email == "" {
		return "", errors.New("no email")
	}
	code, err := GenerateCode()
	if err != nil {
		return "", err
	}
	id := uc.IDs.NewID()
	if err := uc.Challenges.Put(ctx, Challenge{
		ID: id, Purpose: "password_reset",
		CodeHash: HMACCode(uc.CodeSecret, "password_reset", code),
		UserID:   user.ID, Email: user.Email,
		ExpiresAt: uc.Clock.Now().Add(uc.ActivationTTL),
	}); err != nil {
		return "", err
	}
	link := fmt.Sprintf("%s/reset-password?challenge=%s&code=%s", strings.TrimRight(uc.PublicBaseURL, "/"), id, code)
	body := fmt.Sprintf("你的账号已创建。请通过以下链接设置密码：\n\n%s\n\n链接 24 小时内有效。", link)
	_ = uc.Mail.Send(ctx, user.Email, "用户中心账号激活", body)
	if err := uc.audit(ctx, nil, actor, "identity.user.activation.send", itoa(user.ID), "{}", "{}", "{}", "account activation", "success"); err != nil {
		return id, nil
	}
	return id, nil
}

func (uc *UserUsecase) UpdateUser(ctx context.Context, actor ActorContext, id int64, in UpdateUserInput) (*User, error) {
	if err := uc.managementPolicy(ctx, nil, actor); err != nil {
		return nil, err
	}
	if _, err := uc.Authorize(ctx, actor, "identity.user.update", id, false); err != nil {
		return nil, err
	}
	if _, err := mutationFields(in.UpdateMask, "display_name"); err != nil {
		return nil, err
	}
	policy, err := uc.Policy.PolicyRevision(ctx, nil)
	if err != nil {
		return nil, ErrDependency
	}
	if in.ExpectedPolicy != 0 && in.ExpectedPolicy != policy {
		return nil, ConflictPolicy(policy)
	}
	if in.ExpectedRevision == 0 {
		return nil, Validation("expected_revision 不能为空")
	}
	name := strings.TrimSpace(in.DisplayName)
	if name == "" || len([]rune(name)) > 64 {
		return nil, Validation("昵称必须为 1-64 个字符")
	}
	u, err := uc.Users.Get(ctx, nil, id)
	if err != nil {
		return nil, ErrUserNotFound
	}
	if u.Revision != in.ExpectedRevision {
		return nil, ConflictRevision(u.Revision)
	}
	before, _ := jsonx.Marshal(map[string]string{"display_name": u.DisplayName})
	u.DisplayName = name
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.managementPolicy(ctx, tx, actor); err != nil {
			return err
		}
		updated, err := uc.Users.Update(ctx, tx, u, in.ExpectedRevision)
		if err != nil {
			return err
		}
		if err := uc.audit(ctx, tx, actor, "identity.user.update", itoa(id), string(before), "{}", string(mustJSON(map[string]string{"display_name": name})), in.Reason, "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": id, "display_name": name})
		return uc.emit(ctx, tx, "user", id, updated.Revision, "user.profile.updated", string(payload))
	})
	if err != nil {
		return nil, err
	}
	return uc.loadUserWithRoles(ctx, actor, id)
}

func (uc *UserUsecase) SetStatus(ctx context.Context, actor ActorContext, id int64, status string, expected uint64, reason string) (*User, error) {
	if err := uc.managementPolicy(ctx, nil, actor); err != nil {
		return nil, err
	}
	if status != UserStatusEnabled && status != UserStatusDisabled {
		return nil, Validation("状态只能是 enabled 或 disabled")
	}
	op := "identity.user.enable"
	if status == UserStatusDisabled {
		op = "identity.user.disable"
	}
	if _, err := uc.Authorize(ctx, actor, op, id, false); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	if id == actor.User.ID && status == UserStatusDisabled {
		return nil, ErrProtectedAccount
	}
	if status == UserStatusDisabled {
		if err := uc.ensureNotLastRoot(ctx, id); err != nil {
			return nil, err
		}
	}
	u, err := uc.Users.Get(ctx, nil, id)
	if err != nil {
		return nil, ErrUserNotFound
	}
	if u.Status == UserStatusArchived {
		return nil, Validation("已归档账号不能改回启用")
	}
	if u.Revision != expected {
		return nil, ConflictRevision(u.Revision)
	}
	now := uc.Clock.Now().UTC()
	before := u.Status
	u.Status = status
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.managementPolicy(ctx, tx, actor); err != nil {
			return err
		}
		if err := uc.governableTarget(ctx, tx, actor, id); err != nil {
			return err
		}
		if status == UserStatusDisabled {
			if err := uc.ensureNotLastRootTx(ctx, tx, id); err != nil {
				return err
			}
		}

		updated, err := uc.Users.Update(ctx, tx, u, expected)
		if err != nil {
			return err
		}
		version, err := uc.Users.BumpIdentityVersion(ctx, tx, id)
		if err != nil {
			return err
		}
		if status == UserStatusDisabled {
			if err := uc.Sessions.RevokeAllForUser(ctx, tx, id, &now); err != nil {
				return err
			}
		}
		if err := uc.audit(ctx, tx, actor, "identity.user.status", itoa(id), before, status, "{}", reason, "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": id, "status": status, "identity_version": version})
		if err := uc.emit(ctx, tx, "user", id, version, "user.status.changed", string(payload)); err != nil {
			return err
		}
		if status == UserStatusDisabled {
			rev, _ := jsonx.Marshal(map[string]any{"user_id": id, "reason": "account disabled"})
			return uc.emit(ctx, tx, "user", id, version, "session.revoked", string(rev))
		}
		_ = updated
		return nil
	})
	if err != nil {
		return nil, err
	}
	return uc.loadUserWithRoles(ctx, actor, id)
}

func (uc *UserUsecase) Archive(ctx context.Context, actor ActorContext, id int64, expected uint64, reason string) (*User, error) {
	if err := uc.managementPolicy(ctx, nil, actor); err != nil {
		return nil, err
	}
	if _, err := uc.Authorize(ctx, actor, "identity.user.archive", id, false); err != nil {
		return nil, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	if id == actor.User.ID {
		return nil, ErrProtectedAccount
	}
	if err := uc.ensureNotLastRoot(ctx, id); err != nil {
		return nil, err
	}
	u, err := uc.Users.Get(ctx, nil, id)
	if err != nil {
		return nil, ErrUserNotFound
	}
	if u.Status == UserStatusArchived {
		return nil, Validation("账号已归档")
	}
	if u.Revision != expected {
		return nil, ConflictRevision(u.Revision)
	}
	now := uc.Clock.Now().UTC()
	before := u.Status
	u.Status = UserStatusArchived
	u.ArchivedAt = &now
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if err := uc.managementPolicy(ctx, tx, actor); err != nil {
			return err
		}
		if err := uc.governableTarget(ctx, tx, actor, id); err != nil {
			return err
		}
		if err := uc.ensureNotLastRootTx(ctx, tx, id); err != nil {
			return err
		}

		if _, err := uc.Users.Update(ctx, tx, u, expected); err != nil {
			return err
		}
		version, err := uc.Users.BumpIdentityVersion(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := uc.Sessions.RevokeAllForUser(ctx, tx, id, &now); err != nil {
			return err
		}
		if err := uc.audit(ctx, tx, actor, "identity.user.archive", itoa(id), before, u.Status, "{}", reason, "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": id, "status": u.Status, "identity_version": version})
		return uc.emit(ctx, tx, "user", id, version, "user.status.changed", string(payload))
	})
	if err != nil {
		return nil, err
	}
	return uc.loadUserWithRoles(ctx, actor, id)
}

func (uc *UserUsecase) CreatePasswordResetTask(ctx context.Context, actor ActorContext, id int64, reason string) (time.Time, error) {
	if _, err := uc.managementTarget(ctx, nil, actor, id, false); err != nil {
		return time.Time{}, err
	}
	if _, err := uc.Authorize(ctx, actor, "identity.user.credential.update", id, false); err != nil {
		return time.Time{}, err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return time.Time{}, err
	}
	u, err := uc.Users.Get(ctx, nil, id)
	if err != nil {
		return time.Time{}, ErrUserNotFound
	}
	if u.Status == UserStatusArchived || u.Email == "" {
		return time.Time{}, Validation("该账号无法接收密码重置邮件")
	}
	code, err := GenerateCode()
	if err != nil {
		return time.Time{}, ErrDependency
	}
	challengeID := uc.IDs.NewID()
	expires := uc.Clock.Now().Add(uc.ResetTTL)
	if err := uc.Challenges.Put(ctx, Challenge{
		ID: challengeID, Purpose: "password_reset",
		CodeHash: HMACCode(uc.CodeSecret, "password_reset:"+itoa(u.ID), code),
		UserID:   u.ID, Email: u.Email, ExpiresAt: expires,
	}); err != nil {
		return time.Time{}, ErrDependency
	}
	link := fmt.Sprintf("%s/reset-password?challenge=%s&code=%s", strings.TrimRight(uc.PublicBaseURL, "/"), challengeID, code)
	body := fmt.Sprintf("管理员已发起密码重置。请通过以下链接设置新密码：\n\n%s\n\n链接 30 分钟内有效。", link)
	if err := uc.Mail.Send(ctx, u.Email, "用户中心密码重置", body); err != nil {
		return time.Time{}, ErrDependency
	}
	_ = uc.audit(ctx, nil, actor, "identity.user.password.reset_request", itoa(id), "{}", "{}", "{}", reason, "success")
	return expires, nil
}

func (uc *UserUsecase) ResetMFA(ctx context.Context, actor ActorContext, id int64, reason string) error {
	if _, err := uc.managementTarget(ctx, nil, actor, id, false); err != nil {
		return err
	}
	if _, err := uc.Authorize(ctx, actor, "identity.user.mfa.reset", id, false); err != nil {
		return err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return err
	}
	if _, err := uc.Users.Get(ctx, nil, id); err != nil {
		return ErrUserNotFound
	}
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.managementTarget(ctx, tx, actor, id, true); err != nil {
			return err
		}
		if err := uc.MFA.Delete(ctx, tx, id); err != nil {
			return err
		}
		now := uc.Clock.Now().UTC()
		if err := uc.Sessions.RevokeAllForUser(ctx, tx, id, &now); err != nil {
			return err
		}
		version, err := uc.Users.BumpIdentityVersion(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := uc.audit(ctx, tx, actor, "identity.user.mfa.reset", itoa(id), "{}", "{}", "{}", reason, "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": id, "mfa_enabled": false, "identity_version": version})
		return uc.emit(ctx, tx, "user", id, version, "credential.changed", string(payload))
	})
}

func (uc *UserUsecase) UserSessions(ctx context.Context, actor ActorContext, id int64) ([]*Session, error) {
	if _, err := uc.Authorize(ctx, actor, "identity.user.session.read", id, false); err != nil {
		return nil, err
	}
	return uc.Sessions.ListByUser(ctx, nil, id)
}

func (uc *UserUsecase) RevokeUserSessions(ctx context.Context, actor ActorContext, id int64, ids []string, all bool, reason string) error {
	if _, err := uc.managementTarget(ctx, nil, actor, id, false); err != nil {
		return err
	}
	if _, err := uc.Authorize(ctx, actor, "identity.user.session.revoke", id, false); err != nil {
		return err
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return err
	}
	now := uc.Clock.Now().UTC()
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.managementTarget(ctx, tx, actor, id, true); err != nil {
			return err
		}
		if all {
			if err := uc.Sessions.RevokeAllForUser(ctx, tx, id, &now); err != nil {
				return err
			}
		} else {
			for _, sid := range ids {
				s, err := uc.Sessions.Get(ctx, tx, sid)
				if errors.Is(err, ErrResourceNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				if s.UserID != id {
					return ErrPermissionDenied
				}
				if err := uc.Sessions.Revoke(ctx, tx, sid, &now); err != nil {
					return err
				}
			}
		}
		if err := uc.audit(ctx, tx, actor, "identity.user.sessions.revoke", itoa(id), "{}", "{}", "{}", reason, "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": id, "revoke_all": all})
		return uc.emit(ctx, tx, "user", id, 0, "session.revoked", string(payload))
	})
}

func (uc *UserUsecase) EffectivePermissions(ctx context.Context, actor ActorContext, id int64) ([]AuthorizationGrant, uint64, error) {
	if _, err := uc.Authorize(ctx, actor, "identity.user.authorization.read", id, false); err != nil {
		return nil, 0, err
	}
	return uc.Services.EffectivePermissions(ctx, id, nil)
}

func (uc *UserUsecase) ExportUsers(ctx context.Context, actor ActorContext, keyword, status string, fields []string, roleID int64, mfa *bool, reason string) (*ExportJob, error) {
	filter, _, err := uc.listUserFilter(ctx, actor, "identity.user.export", UserFilter{Keyword: keyword, Status: status, RoleID: roleID, MFA: mfa, Limit: 100000})
	if err != nil {
		return nil, err
	}
	snapshot, err := uc.exportSnapshot(ctx, actor)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{"id": true, "username": true, "display_name": true, "status": true, "mfa_enabled": true, "created_at": true, "roles": true, "email": true, "email_verified": true}
	if len(fields) == 0 {
		fields = []string{"id", "username", "display_name", "status", "mfa_enabled", "created_at"}
	}
	for _, f := range fields {
		if !allowed[f] {
			return nil, Validation("不支持的导出字段: " + f)
		}
	}
	users, _, err := uc.Users.List(ctx, nil, filter)
	if err != nil {
		return nil, ErrDependency
	}
	job := &ExportJob{
		Kind: "users", ActorUserID: actor.User.ID, ActorSessionID: actor.Session.ID,
		ScopeSnapshot: snapshot, RequestedFields: fields, Status: ExportPending,
		CreatedAt: uc.Clock.Now().UTC(), ExpiresAt: uc.Clock.Now().Add(24 * time.Hour),
		ArtifactName: uc.IDs.NewID() + ".csv",
	}
	path := filepath.Join(uc.ArtifactDir, job.ArtifactName)
	keepArtifact := false
	defer func() {
		if !keepArtifact {
			_ = os.Remove(path)
		}
	}()
	if err := os.MkdirAll(uc.ArtifactDir, 0o750); err != nil {
		return nil, ErrDependency
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, ErrDependency
	}
	w := csv.NewWriter(f)
	_ = w.Write(fields)
	for _, u := range users {
		d, derr := uc.Decide(ctx, actor, "identity.user.export", u.ID, false)
		if derr != nil {
			_ = f.Close()
			return nil, ErrAuthorizationDown
		}
		if !d.Allowed {
			continue
		}
		if slices.Contains(fields, "email") || slices.Contains(fields, "email_verified") {
			if _, err := uc.Authorize(ctx, actor, "identity.user.contact.read", u.ID, false); err != nil {
				_ = f.Close()
				return nil, err
			}
		}
		roles, _ := uc.Users.RolesForUser(ctx, nil, u.ID)
		mfa := false
		if state, merr := uc.MFA.Get(ctx, nil, u.ID); merr == nil {
			mfa = state.Enabled()
		}
		row := make([]string, 0, len(fields))
		for _, field := range fields {
			switch field {
			case "id":
				row = append(row, itoa(u.ID))
			case "username":
				row = append(row, u.Username)
			case "display_name":
				row = append(row, u.DisplayName)
			case "email":
				row = append(row, u.Email)
			case "email_verified":
				row = append(row, fmt.Sprint(u.EmailVerified))
			case "status":
				row = append(row, u.Status)
			case "mfa_enabled":
				row = append(row, fmt.Sprint(mfa))
			case "created_at":
				row = append(row, u.CreatedAt.Format(time.RFC3339))
			case "roles":
				codes := make([]string, 0, len(roles))
				for _, r := range roles {
					codes = append(codes, r.Code)
				}
				row = append(row, strings.Join(codes, "|"))
			}
		}
		_ = w.Write(csvSafeRow(row))
	}
	w.Flush()
	if err := w.Error(); err != nil {
		_ = f.Close()
		return nil, ErrDependency
	}
	if err := f.Close(); err != nil {
		return nil, ErrDependency
	}
	job.Status = ExportReady
	var saved *ExportJob
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		var err error
		saved, err = uc.Exports.Create(ctx, tx, job)
		if err != nil {
			return err
		}
		return uc.audit(ctx, tx, actor, "identity.user.export", "users", "{}", "{}", string(mustJSON(map[string]any{"fields": fields})), reason, "success")
	})
	if err != nil {
		return nil, err
	}
	keepArtifact = true
	return saved, nil
}

func (uc *UserUsecase) GetExport(ctx context.Context, actor ActorContext, id int64) (*ExportJob, error) {
	job, err := uc.Exports.Get(ctx, id)
	if err != nil {
		return nil, ErrResourceNotFound
	}
	if job.ActorUserID != actor.User.ID || job.ActorSessionID != actor.Session.ID {
		return nil, ErrResourceNotFound
	}
	if job.Kind == "org_audits" {
		// Tenant exports must pass the same membership + permission + snapshot
		// re-check as the tenant download route, even via the platform path.
		return (&OrganizationUsecase{Services: uc.Services}).GetAuditExport(ctx, actor, job.OrganizationID, id)
	}
	if err := uc.authorizeExport(ctx, actor, job); err != nil {
		return nil, err
	}
	return job, nil
}

func (uc *UserUsecase) ListExports(ctx context.Context, actor ActorContext, pageSize int, token string) ([]*ExportJob, string, error) {
	offset, err := DecodePageToken(token, "exports")
	if err != nil {
		return nil, "", err
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	items, _, err := uc.Exports.ListByActor(ctx, actor.User.ID, pageSize, itoa(int64(offset)))
	if err != nil {
		return nil, "", ErrDependency
	}
	next := ""
	if len(items) == pageSize {
		next = EncodePageToken(offset+len(items), "exports")
	}
	return items, next, nil
}

func (uc *UserUsecase) ensureNotLastRoot(ctx context.Context, targetID int64) error {
	return uc.ensureNotLastRootTx(ctx, nil, targetID)
}

func (uc *UserUsecase) ensureNotLastRootTx(ctx context.Context, tx Tx, targetID int64) error {
	root, err := uc.IAM.GetRoleByCode(ctx, tx, "root")
	if err != nil {
		return ErrDependency
	}
	roles, err := uc.Users.RolesForUser(ctx, tx, targetID)
	if err != nil {
		return ErrDependency
	}
	isRoot := false
	for _, r := range roles {
		if r.ID == root.ID {
			isRoot = true
			break
		}
	}
	if !isRoot {
		return nil
	}
	count, err := uc.Users.CountsByRole(ctx, tx, root.ID)
	if err != nil {
		return ErrDependency
	}
	if count <= 1 {
		return ErrRootProtected
	}
	return nil
}

func mustJSON(v any) []byte {
	b, _ := jsonx.Marshal(v)
	return b
}
