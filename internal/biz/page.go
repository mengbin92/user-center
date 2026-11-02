package biz

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/mengbin92/user-center/pkg/jsonx"
	"strconv"
	"strings"
)

// Page tokens are opaque offsets bound to the filter fingerprint. They are not
// authorization material: the query is always re-scoped server side.
func EncodePageToken(offset int, fingerprint string) string {
	if offset <= 0 {
		return ""
	}
	raw := fmt.Sprintf("%d:%s", offset, fingerprint)
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d:%s", offset, hex.EncodeToString(sum[:8]))))
}

func DecodePageToken(token, fingerprint string) (int, error) {
	if token == "" {
		return 0, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, Validation("page_token 不合法")
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return 0, Validation("page_token 不合法")
	}
	offset, err := strconv.Atoi(parts[0])
	if err != nil || offset < 0 {
		return 0, Validation("page_token 不合法")
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s", offset, fingerprint)))
	if hex.EncodeToString(sum[:8]) != parts[1] {
		return 0, Validation("page_token 不合法")
	}
	return offset, nil
}

func decodePageToken(token, fingerprint string, pageSize int) (int, error) {
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	_ = pageSize
	return DecodePageToken(token, fingerprint)
}

func fingerprint(parts ...any) string {
	b, _ := jsonx.Marshal(parts)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
