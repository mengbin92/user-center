package service

import (
	"io"
	"net/http"
	"strconv"
	"strings"

	kerrors "github.com/go-kratos/kratos/v3/errors"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

// SCIM 2.0 protocol surface (RFC 7643 / 7644).
//
// This is a raw HTTP handler rather than a protobuf service: SCIM defines its
// own JSON schemas, error shape, PATCH grammar and filter syntax, none of which
// map onto the project's proto HTTP conventions. It still obeys the layering
// rule -- this file is DTO conversion only, every decision is made in biz.
//
// Supported: /ServiceProviderConfig, /ResourceTypes, /Schemas, Users and
// Groups CRUD, ListResponse paging, a closed filter grammar, PATCH over the
// mutable core attributes, ETag/If-Match, and SCIM error responses.
// Not supported (documented, and refused explicitly rather than silently):
// /Bulk, /Me, sortBy/sortOrder, nested attribute projection, and arbitrary
// value-path filters inside PATCH.

const (
	scimSchemaUser      = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimSchemaGroup     = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimSchemaList      = "urn:ietf:params:scim:schemas:core:2.0:ListResponse"
	scimSchemaError     = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimSchemaPatch     = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimSchemaSPConfig  = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	scimSchemaResources = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	scimSchemaSchema    = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	scimContentType     = "application/scim+json"
)

func scimWriteJSON(w http.ResponseWriter, status int, payload any, etag string) {
	w.Header().Set("Content-Type", scimContentType)
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	w.WriteHeader(status)
	body, err := jsonx.Marshal(payload)
	if err != nil {
		body = []byte(`{"schemas":["` + scimSchemaError + `"],"status":"500","detail":"serialization failed"}`)
	}
	_, _ = w.Write(body)
}

func scimError(w http.ResponseWriter, status int, scimType, detail string) {
	payload := map[string]any{
		"schemas": []string{scimSchemaError}, "status": strconv.Itoa(status), "detail": detail,
	}
	if scimType != "" {
		payload["scimType"] = scimType
	}
	scimWriteJSON(w, status, payload, "")
}

// scimStatus maps a biz error onto the closest SCIM HTTP status. A kratos
// validation error is 400, a revision conflict 409, and a missing row 404 --
// the last one matters because "not found" is also what a foreign tenant id
// must look like.
func scimStatus(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}
	if e := kerrors.FromError(err); e != nil {
		switch e.Code {
		case 400:
			return http.StatusBadRequest, "invalidValue"
		case 401:
			return http.StatusUnauthorized, ""
		case 403:
			return http.StatusForbidden, ""
		case 404:
			return http.StatusNotFound, ""
		case 409:
			return http.StatusConflict, "uniqueness"
		case 503:
			return http.StatusServiceUnavailable, ""
		}
	}
	return http.StatusInternalServerError, ""
}

func scimFail(w http.ResponseWriter, err error) {
	status, scimType := scimStatus(err)
	detail := err.Error()
	if e := kerrors.FromError(err); e != nil {
		detail = e.Message
	}
	scimError(w, status, scimType, detail)
}

func scimBearer(r *http.Request) string {
	raw := r.Header.Get("Authorization")
	if len(raw) < 8 || !strings.EqualFold(raw[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(raw[7:])
}

func scimID(path string) (int64, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 4 {
		return 0, false
	}
	raw := parts[len(parts)-1]
	if raw == "Users" || raw == "Groups" || raw == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

func scimUserResource(u *biz.SCIMUser, baseURL string) map[string]any {
	location := baseURL + "/scim/v2/Users/" + strconv.FormatInt(u.ID, 10)
	emails := []any{}
	if u.Email != "" {
		emails = append(emails, map[string]any{"value": u.Email, "type": "work", "primary": true})
	}
	return map[string]any{
		"schemas":     []string{scimSchemaUser},
		"id":          strconv.FormatInt(u.ID, 10),
		"externalId":  u.ExternalID,
		"userName":    u.UserName,
		"displayName": u.DisplayName,
		"name":        map[string]any{"formatted": u.DisplayName},
		"emails":      emails,
		"active":      u.Active,
		"meta": map[string]any{
			"resourceType": "User", "location": location,
			"version": `W/"` + strconv.FormatUint(u.Revision, 10) + `"`,
		},
	}
}

func scimGroupResource(g *biz.SCIMGroup, baseURL string) map[string]any {
	location := baseURL + "/scim/v2/Groups/" + strconv.FormatInt(g.ID, 10)
	members := make([]any, 0, len(g.MemberIDs))
	for _, uid := range g.MemberIDs {
		members = append(members, map[string]any{
			"value": strconv.FormatInt(uid, 10),
			"$ref":  baseURL + "/scim/v2/Users/" + strconv.FormatInt(uid, 10),
			"type":  "User",
		})
	}
	return map[string]any{
		"schemas":     []string{scimSchemaGroup},
		"id":          strconv.FormatInt(g.ID, 10),
		"externalId":  g.ExternalID,
		"displayName": g.DisplayName,
		"members":     members,
		"meta": map[string]any{
			"resourceType": "Group", "location": location,
			"version": `W/"` + strconv.FormatUint(g.Revision, 10) + `"`,
		},
	}
}

func scimListResponse(resources []any, total, startIndex int) map[string]any {
	return map[string]any{
		"schemas":      []string{scimSchemaList},
		"totalResults": total,
		"startIndex":   startIndex,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	}
}

func scimETag(revision uint64) string {
	return `W/"` + strconv.FormatUint(revision, 10) + `"`
}

// scimIfMatch enforces the optimistic concurrency version an IdP read earlier.
// A missing If-Match is allowed (many IdPs do not send it); a wrong one is not.
func scimIfMatchOK(r *http.Request, revision uint64) bool {
	raw := strings.TrimSpace(r.Header.Get("If-Match"))
	if raw == "" || raw == "*" {
		return true
	}
	raw = strings.TrimPrefix(raw, "W/")
	raw = strings.Trim(raw, `"`)
	v, err := strconv.ParseUint(raw, 10, 64)
	return err == nil && v == revision
}

func scimPaging(r *http.Request) (int, int, error) {
	start, count := 1, 100
	if raw := r.URL.Query().Get("startIndex"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 {
			return 0, 0, biz.Validation("startIndex 必须为正整数")
		}
		start = v
	}
	if raw := r.URL.Query().Get("count"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 {
			return 0, 0, biz.Validation("count 必须为非负整数")
		}
		count = v
		if count > 1000 {
			count = 1000
		}
	}
	return start, count, nil
}

func scimPage[T any](items []T, start, count int) []T {
	offset := start - 1
	if offset >= len(items) || count == 0 {
		return nil
	}
	end := offset + count
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}

// scimFilter is a closed grammar: attribute eq "value" (or eq true/false),
// joined by "and". Anything else is refused with invalidFilter rather than
// interpreted loosely -- a loose parser is how a filter becomes a data leak.
func scimFilter(raw string, resource string) (func(*biz.SCIMUser) bool, func(*biz.SCIMGroup) bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return func(*biz.SCIMUser) bool { return true }, func(*biz.SCIMGroup) bool { return true }, nil
	}
	clauses := strings.Split(raw, " and ")
	type predicate struct{ attr, value string }
	preds := make([]predicate, 0, len(clauses))
	for _, clause := range clauses {
		parts := strings.SplitN(strings.TrimSpace(clause), " eq ", 2)
		if len(parts) != 2 {
			return nil, nil, biz.Validation("不支持的 filter 语法")
		}
		attr := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		allowed := map[string]bool{
			"userName": true, "externalId": true, "id": true, "active": true,
			"emails.value": true, "emails[type eq \"work\"].value": true,
		}
		if resource == "Group" {
			allowed = map[string]bool{"displayName": true, "externalId": true, "id": true}
		}
		if !allowed[attr] {
			return nil, nil, biz.Validation("不支持的 filter 属性: " + attr)
		}
		preds = append(preds, predicate{attr, value})
	}
	userMatch := func(u *biz.SCIMUser) bool {
		for _, p := range preds {
			var got string
			switch p.attr {
			case "userName":
				got = u.UserName
			case "externalId":
				got = u.ExternalID
			case "id":
				got = strconv.FormatInt(u.ID, 10)
			case "active":
				got = strconv.FormatBool(u.Active)
			case "emails.value", `emails[type eq "work"].value`:
				got = u.Email
			}
			if !strings.EqualFold(got, p.value) {
				return false
			}
		}
		return true
	}
	groupMatch := func(g *biz.SCIMGroup) bool {
		for _, p := range preds {
			var got string
			switch p.attr {
			case "displayName":
				got = g.DisplayName
			case "externalId":
				got = g.ExternalID
			case "id":
				got = strconv.FormatInt(g.ID, 10)
			}
			if !strings.EqualFold(got, p.value) {
				return false
			}
		}
		return true
	}
	return userMatch, groupMatch, nil
}

type scimInput struct {
	Schemas     []string        `json:"schemas"`
	ID          string          `json:"id"`
	ExternalID  string          `json:"externalId"`
	UserName    string          `json:"userName"`
	DisplayName string          `json:"displayName"`
	Active      *bool           `json:"active"`
	Emails      []scimEmail     `json:"emails"`
	Name        scimName        `json:"name"`
	Members     []scimMemberRef `json:"members"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type"`
	Primary bool   `json:"primary"`
}

type scimName struct {
	Formatted string `json:"formatted"`
}

type scimMemberRef struct {
	Value string `json:"value"`
}

func (in scimInput) primaryEmail() string {
	for _, e := range in.Emails {
		if e.Primary {
			return strings.TrimSpace(e.Value)
		}
	}
	if len(in.Emails) > 0 {
		return strings.TrimSpace(in.Emails[0].Value)
	}
	return ""
}

func (in scimInput) display() string {
	if strings.TrimSpace(in.DisplayName) != "" {
		return in.DisplayName
	}
	return in.Name.Formatted
}

func (in scimInput) userInput() biz.SCIMUserInput {
	return biz.SCIMUserInput{
		ExternalID: in.ExternalID, UserName: in.UserName,
		DisplayName: in.display(), Email: in.primaryEmail(), Active: in.Active,
	}
}

func (in scimInput) memberIDs() ([]int64, error) {
	out := make([]int64, 0, len(in.Members))
	for _, m := range in.Members {
		v, err := strconv.ParseInt(m.Value, 10, 64)
		if err != nil || v <= 0 {
			return nil, biz.Validation("members.value 必须为用户 id")
		}
		out = append(out, v)
	}
	return out, nil
}

// readLimited is shared by POST/PUT and PATCH. The global middleware caps
// /api/v1/ bodies but SCIM lives under its own prefix, so the limit is
// enforced here too.
func readLimited(r *http.Request, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, biz.Validation("无法读取请求体")
	}
	if int64(len(raw)) > limit {
		return nil, biz.Validation("请求体不能超过 1 MiB")
	}
	return raw, nil
}

func scimDecodeBody(r *http.Request, expectedSchema string) (scimInput, error) {
	var in scimInput
	raw, err := readLimited(r, 1<<20)
	if err != nil {
		return in, err
	}
	if err := jsonx.Unmarshal(raw, &in); err != nil {
		return in, biz.Validation("请求体不是合法的 SCIM JSON")
	}
	if expectedSchema != "" && !scimHasSchema(in.Schemas, expectedSchema) {
		return in, biz.Validation("schemas 必须包含 " + expectedSchema)
	}
	return in, nil
}

func scimHasSchema(schemas []string, want string) bool {
	for _, s := range schemas {
		if s == want {
			return true
		}
	}
	return false
}

// ServeSCIM is mounted for every /scim/v2/... route. It authenticates first,
// then dispatches by path and method; there is no unauthenticated branch.
func (s *SCIMService) ServeSCIM(w http.ResponseWriter, r *http.Request) {
	token, err := s.uc.Authenticate(r.Context(), scimBearer(r))
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
		scimError(w, http.StatusUnauthorized, "", "invalid or disabled bearer token")
		return
	}
	orgID := token.OrganizationID
	baseURL := strings.TrimSuffix(s.uc.PublicBaseURL, "/")
	path := strings.Trim(r.URL.Path, "/")

	switch {
	case path == "scim/v2/ServiceProviderConfig":
		s.scimServiceProviderConfig(w, r, baseURL)
	case path == "scim/v2/ResourceTypes":
		s.scimResourceTypes(w, r, baseURL)
	case strings.HasPrefix(path, "scim/v2/ResourceTypes/"):
		s.scimResourceType(w, r, baseURL, strings.TrimPrefix(path, "scim/v2/ResourceTypes/"))
	case path == "scim/v2/Schemas":
		s.scimSchemas(w, r, baseURL)
	case strings.HasPrefix(path, "scim/v2/Schemas/"):
		s.scimSchema(w, r, baseURL, strings.TrimPrefix(path, "scim/v2/Schemas/"))
	case path == "scim/v2/Users" || strings.HasPrefix(path, "scim/v2/Users/"):
		s.serveSCIMUsers(w, r, orgID, baseURL)
	case path == "scim/v2/Groups" || strings.HasPrefix(path, "scim/v2/Groups/"):
		s.serveSCIMGroups(w, r, orgID, baseURL)
	default:
		scimError(w, http.StatusNotFound, "", "unknown SCIM resource")
	}
}

func requireSCIMMethod(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	scimError(w, http.StatusMethodNotAllowed, "", "method not allowed on this SCIM resource")
	return false
}

func (s *SCIMService) scimServiceProviderConfig(w http.ResponseWriter, r *http.Request, baseURL string) {
	if !requireSCIMMethod(w, r, http.MethodGet) {
		return
	}
	scimWriteJSON(w, http.StatusOK, map[string]any{
		"schemas":          []string{scimSchemaSPConfig},
		"documentationUri": "https://www.rfc-editor.org/rfc/rfc7644",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": 1000},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": true},
		"authenticationSchemes": []any{map[string]any{
			"type": "oauthbearertoken", "name": "SCIM Bearer Token",
			"description": "Tenant-bound bearer token issued by the platform administrator",
			"specUri":     "https://www.rfc-editor.org/rfc/rfc6750", "primary": true,
		}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": baseURL + "/scim/v2/ServiceProviderConfig"},
	}, "")
}

func (s *SCIMService) scimResourceTypes(w http.ResponseWriter, r *http.Request, baseURL string) {
	if !requireSCIMMethod(w, r, http.MethodGet) {
		return
	}
	items := make([]any, 0, 2)
	for _, item := range s.resourceTypeItems(baseURL) {
		items = append(items, item)
	}
	scimWriteJSON(w, http.StatusOK, scimListResponse(items, len(items), 1), "")
}

func (s *SCIMService) scimResourceType(w http.ResponseWriter, r *http.Request, baseURL, id string) {
	if !requireSCIMMethod(w, r, http.MethodGet) {
		return
	}
	for _, item := range s.resourceTypeItems(baseURL) {
		if item["id"] == id {
			scimWriteJSON(w, http.StatusOK, item, "")
			return
		}
	}
	scimError(w, http.StatusNotFound, "", "unknown resource type")
}

func (s *SCIMService) resourceTypeItems(baseURL string) []map[string]any {
	return []map[string]any{
		{"schemas": []string{scimSchemaResources}, "id": "User", "name": "User",
			"endpoint": "/Users", "description": "User Account", "schema": scimSchemaUser,
			"meta": map[string]any{"resourceType": "ResourceType", "location": baseURL + "/scim/v2/ResourceTypes/User"}},
		{"schemas": []string{scimSchemaResources}, "id": "Group", "name": "Group",
			"endpoint": "/Groups", "description": "Group", "schema": scimSchemaGroup,
			"meta": map[string]any{"resourceType": "ResourceType", "location": baseURL + "/scim/v2/ResourceTypes/Group"}},
	}
}

func (s *SCIMService) scimSchema(w http.ResponseWriter, r *http.Request, baseURL, id string) {
	if !requireSCIMMethod(w, r, http.MethodGet) {
		return
	}
	for _, item := range s.schemaItems(baseURL) {
		if item["id"] == id {
			scimWriteJSON(w, http.StatusOK, item, "")
			return
		}
	}
	scimError(w, http.StatusNotFound, "", "unknown schema")
}

func (s *SCIMService) schemaItems(baseURL string) []map[string]any {
	return []map[string]any{
		{"schemas": []string{scimSchemaSchema}, "id": scimSchemaUser, "name": "User",
			"meta": map[string]any{"resourceType": "Schema", "location": baseURL + "/scim/v2/Schemas/" + scimSchemaUser}},
		{"schemas": []string{scimSchemaSchema}, "id": scimSchemaGroup, "name": "Group",
			"meta": map[string]any{"resourceType": "Schema", "location": baseURL + "/scim/v2/Schemas/" + scimSchemaGroup}},
	}
}

func (s *SCIMService) scimSchemas(w http.ResponseWriter, r *http.Request, baseURL string) {
	if !requireSCIMMethod(w, r, http.MethodGet) {
		return
	}
	items := make([]any, 0, 2)
	for _, item := range s.schemaItems(baseURL) {
		items = append(items, item)
	}
	scimWriteJSON(w, http.StatusOK, scimListResponse(items, len(items), 1), "")
}
