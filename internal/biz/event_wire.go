package biz

import (
	"strconv"
	"strings"

	"github.com/mengbin92/user-center/pkg/jsonx"
)

// Events share the same decimal-string identifier/version contract as HTTP.
// Decode individual raw fields so 64-bit integers never pass through float64.
func eventWirePayload(payload string) (string, error) {
	var fields map[string]jsonx.RawMessage
	if err := jsonx.Unmarshal([]byte(payload), &fields); err != nil {
		return "", err
	}
	for key, raw := range fields {
		if strings.HasSuffix(key, "_ids") {
			var values []jsonx.RawMessage
			if err := jsonx.Unmarshal(raw, &values); err != nil {
				return "", err
			}
			for i, value := range values {
				values[i] = decimalWireValue(value)
			}
			encoded, err := jsonx.Marshal(values)
			if err != nil {
				return "", err
			}
			fields[key] = encoded
		} else if key == "revision" || strings.HasSuffix(key, "_id") || strings.HasSuffix(key, "_revision") || strings.HasSuffix(key, "_version") {
			fields[key] = decimalWireValue(raw)
		}
	}
	encoded, err := jsonx.Marshal(fields)
	return string(encoded), err
}

func decimalWireValue(raw jsonx.RawMessage) jsonx.RawMessage {
	value := strings.TrimSpace(string(raw))
	if value == "" || value[0] == '"' {
		return raw
	}
	if _, err := strconv.ParseUint(value, 10, 64); err != nil {
		return raw
	}
	encoded, _ := jsonx.Marshal(value)
	return encoded
}
