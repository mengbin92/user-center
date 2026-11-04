package biz

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mengbin92/user-center/pkg/jsonx"
)

// Organization invitations (V2.4 R3).
//
// An administrator invites an e-mail address, not an account: the token is
// delivered by mail, stored only as a hash, and can only be accepted by a
// logged-in user whose verified account e-mail matches exactly. No account is
// created implicitly, so registration policy cannot be bypassed.

const (
	MaxPendingInvitationsPerOrg = 50

	InvitationErrExpired        = "ORGANIZATION_INVITATION_EXPIRED"
	InvitationErrRevoked        = "ORGANIZATION_INVITATION_REVOKED"
	InvitationErrUsed           = "ORGANIZATION_INVITATION_USED"
	InvitationErrAlreadyMember  = "ORGANIZATION_INVITATION_ALREADY_MEMBER"
	InvitationErrEmailMismatch  = "ORGANIZATION_INVITATION_EMAIL_MISMATCH"
	InvitationErrQuota          = "ORGANIZATION_INVITATION_LIMIT"
	InvitationErrOrgUnavailable = "ORGANIZATION_INVITATION_ORG_UNAVAILABLE"
)

type InvitationInput struct {
	Email        string
	Role         string
	DepartmentID *int64
}

func (uc *OrganizationUsecase) invitationGuard(ctx context.Context, actor ActorContext, orgID int64, write bool) (string, error) {
	_, role, err := uc.orgAccess(ctx, actor, orgID)
	if err != nil {
		return "", err
	}
	operation := PermOrgMemberRead
	if write {
		operation = PermOrgMemberManage
	}
	if err := uc.orgPermission(ctx, actor, orgID, operation, 0, true); err != nil {
		return "", err
	}
	if write {
		if err := uc.RequireStepUp(ctx, actor); err != nil {
			return "", err
		}
	}
	return role, nil
}

func (uc *OrganizationUsecase) CreateInvitation(ctx context.Context, actor ActorContext, orgID int64, in InvitationInput, reason string) (*OrganizationInvitation, string, error) {
	role, err := uc.invitationGuard(ctx, actor, orgID, true)
	if err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(reason) == "" {
		return nil, "", Validation("reason 不能为空")
	}
	in.Email = NormalizeEmail(in.Email)
	if err := ValidateEmail(in.Email); err != nil {
		return nil, "", err
	}
	if in.Role == "" {
		in.Role = OrgRoleMember
	}
	if !validOrgRole(in.Role) {
		return nil, "", Validation("组织角色只能是 owner/admin/member")
	}
	// Only an owner (or the platform administrator) may invite another admin/owner.
	if (in.Role == OrgRoleAdmin || in.Role == OrgRoleOwner) && role != "platform" && role != OrgRoleOwner {
		return nil, "", ErrPermissionDenied
	}
	if in.DepartmentID != nil {
		if _, err := uc.Organizations.GetDepartment(ctx, nil, orgID, *in.DepartmentID); err != nil {
			return nil, "", Validation("部门不存在")
		}
	}
	raw, err := newToken(32)
	if err != nil {
		return nil, "", ErrDependency
	}
	now := uc.Clock.Now().UTC()
	expires := now.Add(uc.OrgInvitationTTL)
	var created *OrganizationInvitation
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		n, err := uc.Organizations.CountPendingInvitations(ctx, tx, orgID, now)
		if err != nil {
			return ErrDependency
		}
		if n >= MaxPendingInvitationsPerOrg {
			return ConflictCode(InvitationErrQuota, "本组织待接受邀请已达上限")
		}
		if existing, err := uc.Organizations.GetInvitationByEmail(ctx, tx, orgID, in.Email); err == nil {
			// Re-inviting the same address rotates the token instead of piling up
			// pending invitations; the old token stops working.
			existing.Status = OrgInvitationRevoked
			if _, err := uc.Organizations.UpdateInvitation(ctx, tx, existing, existing.Revision); err != nil {
				return err
			}
		} else if !errors.Is(err, ErrResourceNotFound) {
			return ErrDependency
		}
		row, err := uc.Organizations.CreateInvitation(ctx, tx, &OrganizationInvitation{
			OrganizationID: orgID, Email: in.Email, EmailNormalized: in.Email,
			Role: in.Role, DepartmentID: in.DepartmentID, TokenHash: HashToken(raw),
			InvitedBy: actor.User.ID, ExpiresAt: expires,
		})
		if err != nil {
			return err
		}
		created = row
		return uc.auditIn(ctx, tx, actor, orgID, "organization.invitation.create", itoa(row.ID), reason)
	})
	if err != nil {
		return nil, "", err
	}
	org, err := uc.Organizations.GetOrganization(ctx, nil, orgID)
	if err != nil {
		return nil, "", ErrDependency
	}
	link := strings.TrimRight(uc.PublicBaseURL, "/") + "/accept-invitation?token=" + raw
	body := fmt.Sprintf("你被邀请加入组织「%s」，角色为 %s。\n请在 %d 小时内登录用户中心并打开以下链接接受邀请：\n%s\n\n如果还没有账号，请先注册与收件邮箱一致的账号，再打开链接。\n如非本人操作请忽略此邮件。",
		org.Name, in.Role, int(uc.OrgInvitationTTL.Hours()), link)
	if err := uc.Mail.Send(ctx, in.Email, "用户中心组织邀请", body); err != nil {
		return nil, "", ErrDependency
	}
	return created, raw, nil
}

func (uc *OrganizationUsecase) ListInvitations(ctx context.Context, actor ActorContext, orgID int64, status string) ([]*OrganizationInvitation, error) {
	if _, err := uc.invitationGuard(ctx, actor, orgID, false); err != nil {
		return nil, err
	}
	items, err := uc.Organizations.ListInvitations(ctx, nil, orgID, status)
	if err != nil {
		return nil, ErrDependency
	}
	now := uc.Clock.Now()
	for _, item := range items {
		if item.Status == OrgInvitationPending && !now.Before(item.ExpiresAt) {
			item.Status = OrgInvitationExpired
		}
	}
	return items, nil
}

func (uc *OrganizationUsecase) RevokeInvitation(ctx context.Context, actor ActorContext, orgID, invitationID int64, expected uint64, reason string) error {
	if _, err := uc.invitationGuard(ctx, actor, orgID, true); err != nil {
		return err
	}
	if strings.TrimSpace(reason) == "" {
		return Validation("reason 不能为空")
	}
	invitation, err := uc.Organizations.GetInvitation(ctx, nil, invitationID)
	if err != nil || invitation.OrganizationID != orgID {
		return ErrResourceNotFound
	}
	if invitation.Status != OrgInvitationPending {
		return ConflictCode(InvitationErrUsed, "邀请已不可撤销")
	}
	invitation.Status = OrgInvitationRevoked
	return uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		if _, err := uc.Organizations.UpdateInvitation(ctx, tx, invitation, expected); err != nil {
			return err
		}
		return uc.auditIn(ctx, tx, actor, orgID, "organization.invitation.revoke", itoa(invitationID), reason)
	})
}

// AcceptInvitation is the self-service accept path. Every rejection uses one
// stable shape so the token cannot be used to enumerate invitations or users.
func (uc *OrganizationUsecase) AcceptInvitation(ctx context.Context, actor ActorContext, raw string) (*OrganizationMember, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrResourceNotFound
	}
	now := uc.Clock.Now().UTC()
	invitation, err := uc.Organizations.GetInvitationByTokenHash(ctx, nil, HashToken(raw))
	if err != nil {
		if errors.Is(err, ErrResourceNotFound) {
			return nil, ErrResourceNotFound
		}
		return nil, ErrDependency
	}
	// The account e-mail must match exactly; the response is deliberately the
	// same as for a token that does not exist.
	if NormalizeEmail(actor.User.Email) != invitation.EmailNormalized {
		return nil, ErrResourceNotFound
	}
	switch invitation.Status {
	case OrgInvitationAccepted:
		return nil, ConflictCode(InvitationErrUsed, "邀请已被接受")
	case OrgInvitationRevoked:
		return nil, ConflictCode(InvitationErrRevoked, "邀请已被撤销")
	}
	if !now.Before(invitation.ExpiresAt) {
		return nil, ConflictCode(InvitationErrExpired, "邀请已过期")
	}
	org, err := uc.Organizations.GetOrganization(ctx, nil, invitation.OrganizationID)
	if err != nil || org.Status != OrgStatusActive {
		return nil, ConflictCode(InvitationErrOrgUnavailable, "组织不可用")
	}
	if existing, err := uc.Organizations.GetMember(ctx, nil, invitation.OrganizationID, actor.User.ID); err == nil {
		if existing.Status == OrgMemberActive {
			return nil, ConflictCode(InvitationErrAlreadyMember, "你已经是该组织成员")
		}
	} else if !errors.Is(err, ErrResourceNotFound) {
		return nil, ErrDependency
	}
	var member *OrganizationMember
	err = uc.Tx.InTx(ctx, func(ctx context.Context, tx Tx) error {
		invitation.Status, invitation.AcceptedBy, invitation.AcceptedAt = OrgInvitationAccepted, actor.User.ID, &now
		if _, err := uc.Organizations.UpdateInvitation(ctx, tx, invitation, invitation.Revision); err != nil {
			return err
		}
		existing, lookupErr := uc.Organizations.GetMember(ctx, tx, invitation.OrganizationID, actor.User.ID)
		switch {
		case lookupErr == nil && existing.Status != OrgMemberActive:
			member, err = uc.Organizations.RestoreMember(ctx, tx, invitation.OrganizationID, actor.User.ID,
				invitation.Role, invitation.DepartmentID, invitation.InvitedBy)
		case errors.Is(lookupErr, ErrResourceNotFound):
			member, err = uc.Organizations.AddMember(ctx, tx, &OrganizationMember{
				OrganizationID: invitation.OrganizationID, UserID: actor.User.ID,
				Role: invitation.Role, DepartmentID: invitation.DepartmentID,
				InvitedBy: invitation.InvitedBy,
			})
		default:
			return ConflictCode(InvitationErrAlreadyMember, "你已经是该组织成员")
		}
		if err != nil {
			return err
		}
		if err := syncOrgMembershipRole(ctx, uc.Services, tx, invitation.OrganizationID, actor.User.ID, invitation.Role, invitation.InvitedBy); err != nil {
			return err
		}
		if err := uc.auditIn(ctx, tx, actor, invitation.OrganizationID, "organization.invitation.accept", itoa(invitation.ID), "self-service invitation acceptance"); err != nil {
			return err
		}
		payload, _ := jsonx.Marshal(map[string]any{
			"organization_id": invitation.OrganizationID, "user_id": actor.User.ID,
			"role": invitation.Role, "revision": member.Revision,
		})
		return uc.emit(ctx, tx, "organization", invitation.OrganizationID, member.Revision, "organization.member.added", string(payload))
	})
	if err != nil {
		return nil, err
	}
	return member, nil
}
