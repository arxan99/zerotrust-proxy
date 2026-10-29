package policy

import "testing"

func testEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Config{
		Categories: map[string][]string{
			"gambling": {"*.bet365.com", "casino.example"},
			"malware":  {"evil.test"},
		},
		Groups: map[string]Group{
			"engineering": {
				DefaultAction: Block,
				Rules: []Rule{
					{Name: "block-malware", Action: Block, Categories: []string{"malware"}},
					{Name: "block-exe", Action: Block, Extensions: []string{".exe"}},
					{Name: "allow-dev", Action: Allow, Domains: []string{"*.github.com", "pypi.org"}},
				},
			},
			"guest": {
				DefaultAction: Allow,
				Rules: []Rule{
					{Name: "block-gambling", Action: Block, Categories: []string{"gambling"}},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestMatchDomain(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "github.com", true},
		{"*.github.com", "notgithub.com", false},
		{"pypi.org", "PyPI.org.", true},
		{"pypi.org", "files.pypi.org", false},
	}
	for _, c := range cases {
		if got := MatchDomain(c.pattern, c.host); got != c.want {
			t.Errorf("MatchDomain(%q,%q)=%v want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestEvaluate(t *testing.T) {
	e := testEngine(t)
	cases := []struct {
		name string
		req  Request
		want Action
		rule string
	}{
		{"allowed dev site", Request{Group: "engineering", Host: "api.github.com"}, Allow, "allow-dev"},
		{"default deny", Request{Group: "engineering", Host: "news.example"}, Block, "default"},
		{"malware first", Request{Group: "engineering", Host: "evil.test"}, Block, "block-malware"},
		{"exe on allowed host", Request{Group: "engineering", Host: "github.com", Path: "/x/setup.EXE"}, Block, "block-exe"},
		{"guest gambling", Request{Group: "guest", Host: "www.bet365.com"}, Block, "block-gambling"},
		{"guest default allow", Request{Group: "guest", Host: "news.example"}, Allow, "default"},
		{"unknown group", Request{Group: "nobody", Host: "pypi.org"}, Block, "unknown-group"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := e.Evaluate(c.req)
			if d.Action != c.want || d.Rule != c.rule {
				t.Fatalf("got %+v, want %s/%s", d, c.want, c.rule)
			}
		})
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	_, err := New(Config{Groups: map[string]Group{"g": {DefaultAction: "maybe"}}})
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
	_, err = New(Config{Groups: map[string]Group{"g": {DefaultAction: Block,
		Rules: []Rule{{Name: "r", Action: Block, Categories: []string{"nope"}}}}}})
	if err == nil {
		t.Fatal("expected error for unknown category")
	}
}
