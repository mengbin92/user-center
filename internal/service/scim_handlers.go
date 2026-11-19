package service

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/mengbin92/user-center/internal/biz"
	"github.com/mengbin92/user-center/pkg/jsonx"
)

// Users and Groups dispatch. Every branch takes orgID from the authenticated
// token; a resource id is resolved only through that tenant's identity map.

func (s *SCIMService) serveSCIMUsers(w http.ResponseWriter, r *http.Request, orgID int64, baseURL string) {
	id, err := scimID(r.URL.Path, "Users")
	if err != nil {
		scimFail(w, err)
		return
	}
	if id == 0 {
		switch r.Method {
		case http.MethodGet:
			s.scimListUsers(w, r, orgID, baseURL)
		case http.MethodPost:
			s.scimCreateUser(w, r, orgID, baseURL)
		default:
			requireSCIMMethod(w, r, http.MethodGet, http.MethodPost)
		}
		return
	}
	var expected uint64
	switch r.Method {
	case http.MethodPut, http.MethodPatch, http.MethodDelete:
		expected, err = scimExpectedRevision(r)
		if err != nil {
			scimFail(w, err)
			return
		}
	}
	switch r.Method {
	case http.MethodGet:
		u, err := s.uc.GetUser(r.Context(), orgID, id)
		if err != nil {
			scimFail(w, err)
			return
		}
		scimWriteJSON(w, http.StatusOK, scimProjectUser(scimUserResource(u, baseURL), r), scimETag(u.Revision))
	case http.MethodPut:
		in, err := scimDecodeBody(r, scimSchemaUser)
		if err != nil {
			scimFail(w, err)
			return
		}
		u, err := s.uc.ReplaceUser(r.Context(), orgID, id, in.userInput(), expected)
		if err != nil {
			scimFail(w, err)
			return
		}
		scimWriteJSON(w, http.StatusOK, scimUserResource(u, baseURL), scimETag(u.Revision))
	case http.MethodPatch:
		in, err := scimPatchUserInput(r)
		if err != nil {
			scimFail(w, err)
			return
		}
		in.ExpectedRevision = expected
		u, err := s.uc.PatchUser(r.Context(), orgID, id, in)
		if err != nil {
			scimFail(w, err)
			return
		}
		scimWriteJSON(w, http.StatusOK, scimUserResource(u, baseURL), scimETag(u.Revision))
	case http.MethodDelete:
		if err := s.uc.DeleteUserIfMatch(r.Context(), orgID, id, expected); err != nil {
			scimFail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		requireSCIMMethod(w, r, http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete)
	}
}

func (s *SCIMService) scimListUsers(w http.ResponseWriter, r *http.Request, orgID int64, baseURL string) {
	start, count, err := scimPaging(r)
	if err != nil {
		scimFail(w, err)
		return
	}
	userMatch, _, err := scimFilter(r.URL.Query().Get("filter"), "User")
	if err != nil {
		scimError(w, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}
	if r.URL.Query().Get("sortBy") != "" || r.URL.Query().Get("sortOrder") != "" {
		scimError(w, http.StatusBadRequest, "invalidFilter", "sortBy / sortOrder 暂不支持")
		return
	}
	items, err := s.uc.ListUsers(r.Context(), orgID)
	if err != nil {
		scimFail(w, err)
		return
	}
	filtered := make([]*biz.SCIMUser, 0, len(items))
	for _, u := range items {
		if userMatch(u) {
			filtered = append(filtered, u)
		}
	}
	resources := make([]any, 0)
	for _, u := range scimPage(filtered, start, count) {
		resources = append(resources, scimProjectUser(scimUserResource(u, baseURL), r))
	}
	scimWriteJSON(w, http.StatusOK, scimListResponse(resources, len(filtered), start), "")
}

func (s *SCIMService) scimCreateUser(w http.ResponseWriter, r *http.Request, orgID int64, baseURL string) {
	in, err := scimDecodeBody(r, scimSchemaUser)
	if err != nil {
		scimFail(w, err)
		return
	}
	u, err := s.uc.CreateUser(r.Context(), orgID, in.userInput())
	if err != nil {
		scimFail(w, err)
		return
	}
	scimWriteJSON(w, http.StatusCreated, scimUserResource(u, baseURL), scimETag(u.Revision))
}

func scimProjectUser(resource map[string]any, r *http.Request) map[string]any {
	return scimProject(resource, r, []string{"schemas", "id", "meta", "externalId", "userName", "displayName", "name", "emails", "active"})
}

func scimProjectGroup(resource map[string]any, r *http.Request) map[string]any {
	return scimProject(resource, r, []string{"schemas", "id", "meta", "externalId", "displayName", "members"})
}

func scimValidateQuery(q url.Values) error {
	for _, name := range []string{"attributes", "excludedAttributes", "filter", "startIndex", "count", "sortBy", "sortOrder"} {
		if len(q[name]) > 1 {
			return biz.Validation("查询参数不能重复")
		}
	}
	attrs, excluded := q.Get("attributes"), q.Get("excludedAttributes")
	if attrs != "" && excluded != "" {
		return biz.Validation("attributes 和 excludedAttributes 不能同时使用")
	}
	for _, raw := range []string{attrs, excluded} {
		if strings.ContainsAny(raw, ".[") {
			return biz.Validation("仅支持顶层属性投影")
		}
	}
	return nil
}

func scimProject(resource map[string]any, r *http.Request, allowed []string) map[string]any {
	q := r.URL.Query()
	attrs, excluded := q.Get("attributes"), q.Get("excludedAttributes")
	if attrs == "" && excluded == "" {
		return resource
	}
	keep := map[string]bool{}
	if attrs != "" {
		for _, field := range strings.Split(attrs, ",") {
			keep[strings.ToLower(strings.TrimSpace(field))] = true
		}
	} else {
		for _, field := range allowed {
			keep[strings.ToLower(field)] = true
		}
		for _, field := range strings.Split(excluded, ",") {
			delete(keep, strings.ToLower(strings.TrimSpace(field)))
		}
	}
	keep["schemas"], keep["id"], keep["meta"] = true, true, true
	out := map[string]any{}
	for k, v := range resource {
		if keep[strings.ToLower(k)] {
			out[k] = v
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// PATCH

type scimPatchOp struct {
	Op    string           `json:"op"`
	Path  string           `json:"path"`
	Value jsonx.RawMessage `json:"value"`
}

type scimPatchBody struct {
	Schemas    []string      `json:"schemas"`
	Operations []scimPatchOp `json:"Operations"`
}

func scimReadPatch(r *http.Request) (scimPatchBody, error) {
	var body scimPatchBody
	raw, err := readLimited(r, 1<<20)
	if err != nil {
		return body, err
	}
	if err := jsonx.Unmarshal(raw, &body); err != nil {
		return body, biz.Validation("PATCH 请求体不是合法的 SCIM JSON")
	}
	if !scimHasSchema(body.Schemas, scimSchemaPatch) {
		return body, biz.Validation("PATCH schemas 必须包含 " + scimSchemaPatch)
	}
	if len(body.Operations) == 0 {
		return body, biz.Validation("Operations 不能为空")
	}
	return body, nil
}

func scimPatchUserInput(r *http.Request) (biz.SCIMUserInput, error) {
	body, err := scimReadPatch(r)
	if err != nil {
		return biz.SCIMUserInput{}, err
	}
	out := biz.SCIMUserInput{}
	for _, op := range body.Operations {
		kind := strings.ToLower(strings.TrimSpace(op.Op))
		if kind != "add" && kind != "replace" && kind != "remove" {
			return out, biz.Validation("不支持的 PATCH op: " + op.Op)
		}
		path := strings.TrimSpace(op.Path)
		if path == "" {
			if kind == "remove" {
				return out, biz.Validation("remove 必须指定 path")
			}
			var obj scimInput
			if err := jsonx.Unmarshal(op.Value, &obj); err != nil {
				return out, biz.Validation("PATCH value 不是合法对象")
			}
			merge := obj.userInput()
			if merge.UserName != "" {
				out.UserName = merge.UserName
			}
			if merge.DisplayName != "" {
				out.DisplayName = merge.DisplayName
			}
			if merge.Email != "" {
				out.Email = merge.Email
			}
			if merge.ExternalID != "" {
				out.ExternalID = merge.ExternalID
			}
			if merge.Active != nil {
				out.Active = merge.Active
			}
			continue
		}
		switch strings.ToLower(path) {
		case "active":
			if kind == "remove" {
				v := false
				out.Active = &v
				continue
			}
			var v bool
			if err := jsonx.Unmarshal(op.Value, &v); err != nil {
				return out, biz.Validation("active 必须是布尔值")
			}
			out.Active = &v
		case "displayname", "name.formatted":
			if kind == "remove" {
				return out, biz.ErrSCIMReadOnlyProfile
			}
			var v string
			if err := jsonx.Unmarshal(op.Value, &v); err != nil || strings.TrimSpace(v) == "" {
				return out, biz.Validation("displayName 必须是字符串")
			}
			out.DisplayName = v
		case "username":
			if kind == "remove" {
				return out, biz.ErrSCIMReadOnlyProfile
			}
			var v string
			if err := jsonx.Unmarshal(op.Value, &v); err != nil || strings.TrimSpace(v) == "" {
				return out, biz.Validation("userName 必须是字符串")
			}
			out.UserName = v
		case "externalid":
			var v string
			if err := jsonx.Unmarshal(op.Value, &v); err != nil || strings.TrimSpace(v) == "" {
				return out, biz.Validation("externalId 必须是非空字符串")
			}
			out.ExternalID = v
		case "emails", "emails.value", `emails[type eq "work"].value`:
			if kind == "remove" {
				return out, biz.ErrSCIMReadOnlyProfile
			}
			email, err := scimPatchEmail(op.Value)
			if err != nil {
				return out, err
			}
			if email == "" {
				return out, biz.ErrSCIMReadOnlyProfile
			}
			out.Email = email
		default:
			return out, biz.Validation("不支持的 PATCH path: " + path)
		}
	}
	return out, nil
}

func scimPatchEmail(raw jsonx.RawMessage) (string, error) {
	var single string
	if err := jsonx.Unmarshal(raw, &single); err == nil {
		return strings.TrimSpace(single), nil
	}
	var list []scimEmail
	if err := jsonx.Unmarshal(raw, &list); err == nil {
		in := scimInput{Emails: list}
		return in.primaryEmail(), nil
	}
	var obj map[string]any
	if err := jsonx.Unmarshal(raw, &obj); err == nil {
		if v, ok := obj["value"].(string); ok {
			return strings.TrimSpace(v), nil
		}
	}
	return "", biz.Validation("emails 的 PATCH value 不合法")
}

// ---------------------------------------------------------------------------
// Groups

func (s *SCIMService) serveSCIMGroups(w http.ResponseWriter, r *http.Request, orgID int64, baseURL string) {
	id, err := scimID(r.URL.Path, "Groups")
	if err != nil {
		scimFail(w, err)
		return
	}
	if id == 0 {
		switch r.Method {
		case http.MethodGet:
			s.scimListGroups(w, r, orgID, baseURL)
		case http.MethodPost:
			s.scimCreateGroup(w, r, orgID, baseURL)
		default:
			requireSCIMMethod(w, r, http.MethodGet, http.MethodPost)
		}
		return
	}
	var expected uint64
	switch r.Method {
	case http.MethodPut, http.MethodPatch, http.MethodDelete:
		expected, err = scimExpectedRevision(r)
		if err != nil {
			scimFail(w, err)
			return
		}
	}
	switch r.Method {
	case http.MethodGet:
		g, err := s.uc.GetGroup(r.Context(), orgID, id)
		if err != nil {
			scimFail(w, err)
			return
		}
		scimWriteJSON(w, http.StatusOK, scimProjectGroup(scimGroupResource(g, baseURL), r), scimETag(g.Revision))
	case http.MethodPut:
		in, err := scimDecodeBody(r, scimSchemaGroup)
		if err != nil {
			scimFail(w, err)
			return
		}
		ids, err := in.memberIDs()
		if err != nil {
			scimFail(w, err)
			return
		}
		if strings.TrimSpace(in.DisplayName) == "" {
			scimFail(w, biz.Validation("displayName 不能为空"))
			return
		}
		g, err := s.uc.PatchGroup(r.Context(), orgID, id, biz.SCIMGroupInput{
			ExternalID: in.ExternalID, DisplayName: in.DisplayName,
			Members: []biz.SCIMGroupMemberChange{{IDs: ids, Replace: true}},
		}, expected)
		if err != nil {
			scimFail(w, err)
			return
		}
		scimWriteJSON(w, http.StatusOK, scimGroupResource(g, baseURL), scimETag(g.Revision))
	case http.MethodPatch:
		in, err := scimPatchGroupInput(r)
		if err != nil {
			scimFail(w, err)
			return
		}
		g, err := s.uc.PatchGroup(r.Context(), orgID, id, in, expected)
		if err != nil {
			scimFail(w, err)
			return
		}
		scimWriteJSON(w, http.StatusOK, scimGroupResource(g, baseURL), scimETag(g.Revision))
	case http.MethodDelete:
		if err := s.uc.DeleteGroup(r.Context(), orgID, id, expected); err != nil {
			scimFail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		requireSCIMMethod(w, r, http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete)
	}
}

func (s *SCIMService) scimListGroups(w http.ResponseWriter, r *http.Request, orgID int64, baseURL string) {
	start, count, err := scimPaging(r)
	if err != nil {
		scimFail(w, err)
		return
	}
	_, groupMatch, err := scimFilter(r.URL.Query().Get("filter"), "Group")
	if err != nil {
		scimError(w, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}
	if r.URL.Query().Get("sortBy") != "" || r.URL.Query().Get("sortOrder") != "" {
		scimError(w, http.StatusBadRequest, "invalidFilter", "sortBy / sortOrder 暂不支持")
		return
	}
	items, err := s.uc.ListGroups(r.Context(), orgID)
	if err != nil {
		scimFail(w, err)
		return
	}
	filtered := make([]*biz.SCIMGroup, 0, len(items))
	for _, g := range items {
		if groupMatch(g) {
			filtered = append(filtered, g)
		}
	}
	resources := make([]any, 0)
	for _, g := range scimPage(filtered, start, count) {
		resources = append(resources, scimProjectGroup(scimGroupResource(g, baseURL), r))
	}
	scimWriteJSON(w, http.StatusOK, scimListResponse(resources, len(filtered), start), "")
}

func (s *SCIMService) scimCreateGroup(w http.ResponseWriter, r *http.Request, orgID int64, baseURL string) {
	in, err := scimDecodeBody(r, scimSchemaGroup)
	if err != nil {
		scimFail(w, err)
		return
	}
	ids, err := in.memberIDs()
	if err != nil {
		scimFail(w, err)
		return
	}
	g, err := s.uc.CreateGroup(r.Context(), orgID, biz.SCIMGroupInput{
		ExternalID: in.ExternalID, DisplayName: in.DisplayName,
		Members: []biz.SCIMGroupMemberChange{{IDs: ids}},
	})
	if err != nil {
		scimFail(w, err)
		return
	}
	scimWriteJSON(w, http.StatusCreated, scimGroupResource(g, baseURL), scimETag(g.Revision))
}

func scimPatchGroupInput(r *http.Request) (biz.SCIMGroupInput, error) {
	body, err := scimReadPatch(r)
	if err != nil {
		return biz.SCIMGroupInput{}, err
	}
	out := biz.SCIMGroupInput{}
	for _, op := range body.Operations {
		kind := strings.ToLower(strings.TrimSpace(op.Op))
		if kind != "add" && kind != "replace" && kind != "remove" {
			return out, biz.Validation("不支持的 PATCH op: " + op.Op)
		}
		path := strings.TrimSpace(op.Path)
		if path == "" {
			if kind == "remove" {
				return out, biz.Validation("remove 必须指定 path")
			}
			var obj scimInput
			if err := jsonx.Unmarshal(op.Value, &obj); err != nil {
				return out, biz.Validation("PATCH value 不是合法对象")
			}
			if obj.DisplayName != "" {
				out.DisplayName = obj.DisplayName
			}
			if obj.ExternalID != "" {
				out.ExternalID = obj.ExternalID
			}
			if obj.Members != nil {
				ids, err := obj.memberIDs()
				if err != nil {
					return out, err
				}
				out.Members = append(out.Members, biz.SCIMGroupMemberChange{IDs: ids, Replace: kind == "replace"})
			}
			continue
		}
		switch {
		case strings.EqualFold(path, "displayName"):
			var v string
			if err := jsonx.Unmarshal(op.Value, &v); err != nil {
				return out, biz.Validation("displayName 必须是字符串")
			}
			if strings.TrimSpace(v) == "" {
				return out, biz.Validation("displayName 不能为空")
			}
			out.DisplayName = v
		case strings.EqualFold(path, "externalId"):
			if err := jsonx.Unmarshal(op.Value, &out.ExternalID); err != nil || strings.TrimSpace(out.ExternalID) == "" {
				return out, biz.Validation("externalId 必须是非空字符串")
			}
		case strings.EqualFold(path, "members"):
			if kind == "remove" && len(op.Value) == 0 {
				out.Members = append(out.Members, biz.SCIMGroupMemberChange{Replace: true})
				continue
			}
			ids, err := scimPatchMembers(op.Value)
			if err != nil {
				return out, err
			}
			out.Members = append(out.Members, biz.SCIMGroupMemberChange{
				IDs: ids, Replace: kind == "replace", Remove: kind == "remove",
			})
		case strings.HasPrefix(strings.ToLower(path), "members[value eq ") && kind == "remove":
			inner, closed := strings.CutSuffix(path[len("members[value eq "):], "]")
			var value string
			if !closed || jsonx.Unmarshal([]byte(strings.TrimSpace(inner)), &value) != nil {
				return out, biz.Validation("members 过滤值必须为带引号的用户 id")
			}
			v, err := strconv.ParseInt(value, 10, 64)
			if err != nil || v <= 0 {
				return out, biz.Validation("members 过滤值必须为用户 id")
			}
			out.Members = append(out.Members, biz.SCIMGroupMemberChange{IDs: []int64{v}, Remove: true})
		default:
			return out, biz.Validation("不支持的 PATCH path: " + path)
		}
	}
	return out, nil
}

func scimPatchMembers(raw jsonx.RawMessage) ([]int64, error) {
	var list []scimMemberRef
	if err := jsonx.Unmarshal(raw, &list); err == nil {
		in := scimInput{Members: list}
		return in.memberIDs()
	}
	var single scimMemberRef
	if err := jsonx.Unmarshal(raw, &single); err == nil && single.Value != "" {
		return scimInput{Members: []scimMemberRef{single}}.memberIDs()
	}
	return nil, biz.Validation("members 的 PATCH value 不合法")
}
