package auth

import (
	"encoding/base64"
	"testing"
)

func header(u, p string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
}

func TestAuthenticate(t *testing.T) {
	s := NewStore(map[string]User{
		"alice": {Salt: "s1", Hash: HashPassword("s1", "correct-horse"), Group: "engineering"},
	})

	name, group, err := s.Authenticate(header("alice", "correct-horse"))
	if err != nil || name != "alice" || group != "engineering" {
		t.Fatalf("valid login failed: %v %s %s", err, name, group)
	}
	for _, h := range []string{
		header("alice", "wrong"),
		header("mallory", "correct-horse"),
		"Bearer abc",
		"Basic not-base64!!",
		"Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")),
		"",
	} {
		if _, _, err := s.Authenticate(h); err == nil {
			t.Errorf("expected failure for %q", h)
		}
	}
}
