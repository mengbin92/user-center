package data

import "testing"

func TestWithSQLiteBusyTimeout(t *testing.T) {
	cases := map[string]string{
		"file:/tmp/x.db?_fk=1":              "file:/tmp/x.db?_fk=1&_busy_timeout=10000",
		"file:/tmp/x.db":                    "file:/tmp/x.db?_busy_timeout=10000",
		"file:/tmp/x.db?_busy_timeout=2000": "file:/tmp/x.db?_busy_timeout=2000",
	}
	for in, want := range cases {
		if got := withSQLiteBusyTimeout(in); got != want {
			t.Fatalf("withSQLiteBusyTimeout(%q) = %q, want %q", in, got, want)
		}
	}
}
