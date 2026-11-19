package biz

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/mengbin92/user-center/pkg/jsonx"
)

// Directory connectors are deliberately small and stateless: the sync engine
// owns retries, cursors and reconciliation. Adding a source (Entra ID, 飞书,
// 企业微信 ...) means adding one Fetch implementation, not changing the engine.

type DirectoryConfig struct {
	URL             string `json:"url"`
	BaseDN          string `json:"base_dn,omitempty"`
	BindDN          string `json:"bind_dn,omitempty"`
	UserFilter      string `json:"user_filter,omitempty"`
	PageSize        int    `json:"page_size,omitempty"`
	Interval        int    `json:"interval_seconds,omitempty"`
	Deletion        string `json:"deletion_policy,omitempty"`
	Conflict        string `json:"conflict_policy,omitempty"`
	ExternalIDAttr  string `json:"external_id_attr,omitempty"`
	UserNameAttr    string `json:"user_name_attr,omitempty"`
	DisplayNameAttr string `json:"display_name_attr,omitempty"`
	EmailAttr       string `json:"email_attr,omitempty"`
}

func (c *DirectoryConfig) Normalize() {
	if c.Interval <= 0 {
		c.Interval = 300
	}
	if c.PageSize <= 0 {
		c.PageSize = 500
	}
	if c.Deletion == "" {
		c.Deletion = "disable"
	}
	if c.Conflict == "" {
		c.Conflict = "source_wins"
	}
	if c.ExternalIDAttr == "" {
		c.ExternalIDAttr = "entryUUID"
	}
	if c.UserNameAttr == "" {
		c.UserNameAttr = "uid"
	}
	if c.DisplayNameAttr == "" {
		c.DisplayNameAttr = "displayName"
	}
	if c.EmailAttr == "" {
		c.EmailAttr = "mail"
	}
}

// validate accepts omitted optional fields; Normalize() (called by the
// usecase before persisting) fills their defaults. A value receiver here would
// silently discard normalization, so the caller must own that step.
func (c DirectoryConfig) validate() error {
	if strings.TrimSpace(c.URL) == "" {
		return Validation("目录地址不能为空")
	}
	if c.Deletion != "" && c.Deletion != "disable" && c.Deletion != "delete" && c.Deletion != "keep" {
		return Validation("deletion_policy 只能是 disable / delete / keep")
	}
	if c.Conflict != "" && c.Conflict != "source_wins" && c.Conflict != "local_wins" {
		return Validation("conflict_policy 只能是 source_wins / local_wins")
	}
	if c.Interval != 0 && c.Interval < 30 {
		return Validation("interval_seconds 不能小于 30")
	}
	return nil
}

type DirectoryRecord struct {
	ExternalID  string
	UserName    string
	DisplayName string
	Email       string
	Active      bool
}

type DirectorySnapshot struct {
	Records []DirectoryRecord
	Deleted []string
	Cursor  string
	// Full means the caller can use absence as a tombstone. Delta snapshots
	// must list deletions explicitly.
	Full bool
}

type DirectoryConnector interface {
	Kind() string
	Fetch(ctx context.Context, cfg DirectoryConfig, secret, cursor string) (*DirectorySnapshot, error)
}

func NewDirectoryConnectors() map[string]DirectoryConnector {
	ldap := &ldapConnector{}
	feed := &jsonFeedConnector{}
	return map[string]DirectoryConnector{ldap.Kind(): ldap, feed.Kind(): feed}
}

// validateDirectoryURL rejects plaintext HTTP to non-loopback hosts and
// disables redirects. Directory URLs are configured by a platform admin, but
// an SSRF guard is still required: the worker follows them unattended.
func validateDirectoryURL(raw string, allowedSchemes ...string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, Validation("目录地址不是合法 URL")
	}
	ok := false
	for _, scheme := range allowedSchemes {
		if u.Scheme == scheme {
			ok = true
		}
	}
	if !ok {
		return nil, Validation("目录地址协议不被支持")
	}
	if u.Scheme == "http" || u.Scheme == "ldap" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, Validation("明文协议只允许回环地址")
		}
	}
	return u, nil
}

// ---------------------------------------------------------------------------
// Generic JSON feed (Entra/Okta/飞书 export gateways, and test fixtures)

type jsonFeedPayload struct {
	Users   *[]jsonFeedUser `json:"users"`
	Deleted []string        `json:"deleted"`
	Cursor  string          `json:"cursor"`
	Full    bool            `json:"full"`
}

type jsonFeedUser struct {
	ExternalID  string `json:"externalId"`
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Active      *bool  `json:"active"`
}

type jsonFeedConnector struct{}

func (jsonFeedConnector) Kind() string { return "jsonfeed" }

func (jsonFeedConnector) Fetch(ctx context.Context, cfg DirectoryConfig, secret, cursor string) (*DirectorySnapshot, error) {
	u, err := validateDirectoryURL(cfg.URL, "http", "https")
	if err != nil {
		return nil, err
	}
	if cursor != "" {
		q := u.Query()
		q.Set("since", cursor)
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, ErrDependency
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrDependency
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, Validation("目录源返回 " + strconv.Itoa(resp.StatusCode))
	}
	const maxFeedBytes = 8 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, ErrDependency
	}
	if len(raw) > maxFeedBytes {
		return nil, Validation("目录源响应超过大小上限")
	}
	var payload *jsonFeedPayload
	if err := jsonx.Unmarshal(raw, &payload); err != nil || payload == nil || payload.Full && payload.Users == nil {
		return nil, Validation("目录源返回的 JSON 不合法")
	}
	out := &DirectorySnapshot{Cursor: payload.Cursor, Full: payload.Full, Deleted: payload.Deleted}
	if out.Cursor == "" {
		out.Cursor = cursor
	}
	if payload.Users == nil {
		return out, nil
	}
	for _, u := range *payload.Users {
		if strings.TrimSpace(u.ExternalID) == "" || strings.TrimSpace(u.UserName) == "" {
			return nil, Validation("目录用户缺少 externalId 或 userName")
		}
		active := true
		if u.Active != nil {
			active = *u.Active
		}
		out.Records = append(out.Records, DirectoryRecord{
			ExternalID: u.ExternalID, UserName: u.UserName,
			DisplayName: u.DisplayName, Email: u.Email, Active: active,
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// LDAP / Active Directory

type ldapConnector struct{}

func (ldapConnector) Kind() string { return "ldap" }

func (ldapConnector) Fetch(ctx context.Context, cfg DirectoryConfig, secret, cursor string) (*DirectorySnapshot, error) {
	startedAt := time.Now().UTC()
	u, err := validateDirectoryURL(cfg.URL, "ldap", "ldaps")
	if err != nil {
		return nil, err
	}
	cfg.Normalize()
	conn, err := ldap.DialURL(u.String(), ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}))
	if err != nil {
		return nil, ErrDependency
	}
	defer conn.Close()
	conn.SetTimeout(15 * time.Second)
	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, secret); err != nil {
			return nil, Validation("LDAP 绑定失败")
		}
	} else if secret != "" {
		return nil, Validation("简单绑定需要提供 bind_dn")
	}
	filter := cfg.UserFilter
	if filter == "" {
		filter = "(objectClass=inetOrgPerson)"
	}
	if cursor != "" {
		// AD's whenChanged uses the generalized-time form YYYYMMDDHHMMSS.0Z.
		filter = fmt.Sprintf("(&%s(whenChanged>=%s))", filter, ldap.EscapeFilter(cursor))
	}
	attrs := []string{cfg.ExternalIDAttr, cfg.UserNameAttr, cfg.DisplayNameAttr, cfg.EmailAttr, "userAccountControl"}
	paging := ldap.NewControlPaging(uint32(cfg.PageSize))
	out := &DirectorySnapshot{Full: cursor == "", Cursor: startedAt.Format("20060102150405.0Z")}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		req := ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, 0, false, filter, attrs, nil)
		req.Controls = []ldap.Control{paging}
		res, err := conn.Search(req)
		if err != nil {
			return nil, ErrDependency
		}
		for _, entry := range res.Entries {
			externalID := entry.GetAttributeValue(cfg.ExternalIDAttr)
			if externalID == "" {
				externalID = entry.DN
			}
			name := entry.GetAttributeValue(cfg.UserNameAttr)
			if name == "" {
				name = externalID
			}
			active := true
			if raw := entry.GetAttributeValue("userAccountControl"); raw != "" {
				if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n&2 != 0 {
					active = false
				}
			}
			out.Records = append(out.Records, DirectoryRecord{
				ExternalID: externalID, UserName: name,
				DisplayName: entry.GetAttributeValue(cfg.DisplayNameAttr),
				Email:       entry.GetAttributeValue(cfg.EmailAttr), Active: active,
			})
		}
		pc := ldap.FindControl(res.Controls, ldap.ControlTypePaging)
		if pc == nil {
			break
		}
		pagingResult := pc.(*ldap.ControlPaging)
		if len(pagingResult.Cookie) == 0 {
			break
		}
		paging.SetCookie(pagingResult.Cookie)
	}
	return out, nil
}
