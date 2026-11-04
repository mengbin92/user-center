package biz

import (
	"context"
	"errors"
	"strings"

	"github.com/mengbin92/user-center/pkg/jsonx"
)

// R10 username change (V2.4). The self-service path requires Step-up and the
// current password; administrative rename is intentionally not exposed so the
// audit subject cannot be changed by a third party.

var reservedUsernames = map[string]bool{
	"root": true, "admin": true, "administrator": true,
	"system": true, "user-center": true, "usercenter": true,
}

func UsernameReserved(raw string) bool {
	return reservedUsernames[NormalizeUsername(raw)]
}

type UpdateUsernameInput struct {
	Username         string
	CurrentPassword  string
	ExpectedRevision uint64
	Reason           string
}

func (uc *UserUsecase) UpdateUsername(ctx context.Context, actor ActorContext, in UpdateUsernameInput) (*User, error) {
	if strings.TrimSpace(in.Reason) == "" {
		return nil, Validation("reason 不能为空")
	}
	if err := uc.RequireStepUp(ctx, actor); err != nil {
		return nil, err
	}
	if in.ExpectedRevision != actor.User.Revision {
		return nil, ConflictRevision(actor.User.Revision)
	}
	if err := uc.confirmPassword(ctx, actor.User.ID, in.CurrentPassword); err != nil {
		return nil, err
	}
	username := strings.TrimSpace(in.Username)
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	if UsernameReserved(username) {
		return nil, Validation("该用户名为系统保留字")
	}
	normalized := NormalizeUsername(username)
	if normalized == actor.User.UsernameNormalized {
		return nil, Validation("新用户名不能与当前用户名相同")
	}
	if _, err := uc.Users.GetByUsername(ctx, nil, normalized); err == nil {
		return nil, ErrUsernameExists
	} else if !errors.Is(err, ErrUserNotFound) {
		return nil, ErrDependency
	}
	before := actor.User.Username
	user := *actor.User
	user.Username, user.UsernameNormalized = username, normalized
	var updated *User
	err := uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		row, err := uc.Users.Update(ctx, tx, &user, in.ExpectedRevision)
		if err != nil {
			return err
		}
		updated = row
		if err := uc.audit(ctx, tx, actor, "identity.user.username.update", itoa(user.ID),
			string(mustJSON(map[string]string{"username": before})),
			string(mustJSON(map[string]string{"username": username})), "{}",
			strings.TrimSpace(in.Reason), "success"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{"user_id": user.ID, "username": username, "revision": row.Revision})
		return uc.emit(ctx, tx, "user", user.ID, row.Revision, "user.username.updated", string(payload))
	})
	if err != nil {
		return nil, err
	}
	return uc.Me(ctx, ActorContext{User: updated, Session: actor.Session, Actor: actor.Actor})
}
