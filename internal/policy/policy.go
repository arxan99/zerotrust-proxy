// Package policy implements a zero-trust access policy engine.
//
// Every request is evaluated against the requesting user's group. Nothing is
// trusted by default: if no rule matches, the group's default action applies
// (which should normally be "block").
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
)

// Action is the outcome of a policy decision.
type Action string

const (
	Allow Action = "allow"
	Block Action = "block"
)

// Rule matches a request by destination domain, URL category or file extension.
type Rule struct {
	Name       string   `json:"name"`
	Action     Action   `json:"action"`
	Domains    []string `json:"domains,omitempty"`    // exact or wildcard, e.g. "*.example.com"
	Categories []string `json:"categories,omitempty"` // e.g. "gambling", "malware"
	Extensions []string `json:"extensions,omitempty"` // e.g. ".exe"
}

// Group holds an ordered rule list; the first matching rule wins.
type Group struct {
	DefaultAction Action `json:"default_action"`
	Rules         []Rule `json:"rules"`
}

// Config is the full policy file.
type Config struct {
	Categories map[string][]string `json:"categories"` // category -> domain patterns
	Groups     map[string]Group    `json:"groups"`
}

// Request is the information the engine needs to make a decision.
type Request struct {
	User  string
	Group string
	Host  string // hostname without port
	Path  string // URL path, empty for CONNECT tunnels
}

// Decision explains why a request was allowed or blocked.
type Decision struct {
	Action   Action `json:"action"`
	Rule     string `json:"rule"`
	Category string `json:"category,omitempty"`
}

// Engine evaluates requests against a Config.
type Engine struct {
	cfg Config
}

// Load reads and validates a JSON policy file.
func Load(file string) (*Engine, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	return New(cfg)
}

// New validates cfg and returns an Engine.
func New(cfg Config) (*Engine, error) {
	for name, g := range cfg.Groups {
		if !validAction(g.DefaultAction) {
			return nil, fmt.Errorf("group %q: invalid default_action %q", name, g.DefaultAction)
		}
		for _, r := range g.Rules {
			if !validAction(r.Action) {
				return nil, fmt.Errorf("group %q rule %q: invalid action %q", name, r.Name, r.Action)
			}
			for _, c := range r.Categories {
				if _, ok := cfg.Categories[c]; !ok {
					return nil, fmt.Errorf("group %q rule %q: unknown category %q", name, r.Name, c)
				}
			}
		}
	}
	return &Engine{cfg: cfg}, nil
}

func validAction(a Action) bool { return a == Allow || a == Block }

// Categorize returns the first category whose patterns match host, or "".
func (e *Engine) Categorize(host string) string {
	host = normalize(host)
	for cat, patterns := range e.cfg.Categories {
		for _, p := range patterns {
			if MatchDomain(p, host) {
				return cat
			}
		}
	}
	return ""
}

// Evaluate returns the decision for req. Unknown groups are always blocked.
func (e *Engine) Evaluate(req Request) Decision {
	g, ok := e.cfg.Groups[req.Group]
	if !ok {
		return Decision{Action: Block, Rule: "unknown-group"}
	}
	host := normalize(req.Host)
	cat := e.Categorize(host)
	ext := strings.ToLower(path.Ext(req.Path))

	for _, r := range g.Rules {
		if ruleMatches(r, host, cat, ext) {
			return Decision{Action: r.Action, Rule: r.Name, Category: cat}
		}
	}
	return Decision{Action: g.DefaultAction, Rule: "default", Category: cat}
}

func ruleMatches(r Rule, host, cat, ext string) bool {
	for _, d := range r.Domains {
		if MatchDomain(d, host) {
			return true
		}
	}
	for _, c := range r.Categories {
		if c == cat {
			return true
		}
	}
	for _, x := range r.Extensions {
		if ext != "" && strings.EqualFold(x, ext) {
			return true
		}
	}
	return false
}

// MatchDomain reports whether host matches pattern. "*.example.com" matches
// any subdomain of example.com and example.com itself.
func MatchDomain(pattern, host string) bool {
	pattern, host = normalize(pattern), normalize(host)
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return host == pattern
}

func normalize(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}
