package biz

import "strings"

// An omitted mask retains the full-update contract; a supplied mask is exact.
func mutationFields(mask string, allowed ...string) (map[string]bool, error) {
	fields := make(map[string]bool, len(allowed))
	if strings.TrimSpace(mask) == "" {
		for _, field := range allowed {
			fields[field] = true
		}
		return fields, nil
	}
	for _, path := range strings.Split(mask, ",") {
		field := strings.TrimSpace(path)
		found := false
		for _, candidate := range allowed {
			if candidate == field {
				found = true
				break
			}
		}
		if !found {
			return nil, Validation("不支持的 update_mask 字段: " + field)
		}
		fields[field] = true
	}
	return fields, nil
}
