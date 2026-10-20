// Package policy is xgate's policy engine: it decides whether an agent may be
// issued a capability for a requested action, from an operator-editable config
// file. It is default-deny and I/O-free apart from Load.
//
// File format (JSON):
//
//	{
//	  "version": 1,
//	  "default_ttl_seconds": 60,
//	  "agents": {
//	    "sre-agent": {
//	      "allow": ["restart:nginx", "read:/var/log/nginx/*"],
//	      "deny":  ["restart:payments-db"],
//	      "ttl_seconds": 30
//	    }
//	  }
//	}
//
// Rules are "action:resource" (or just "shell"). A resource may be exact, or
// end in "/*" to cover everything beneath a directory (boundary-aware: "/var/log/*"
// does not match "/var/logs/x", and ".." is never allowed in a requested path).
// Deny always beats allow. An unknown agent, or no matching allow rule, is denied.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
)

const (
	Version         = 1
	MaxTTLSeconds   = 3600
	fallbackTTLSecs = 60
)

// Actions the engine understands (must match xgate-policy's capability mapping).
var knownActions = map[string]bool{
	"restart": true, "deploy": true, "read": true, "write": true, "shell": true,
}

type AgentRules struct {
	Allow      []string `json:"allow"`
	Deny       []string `json:"deny"`
	TTLSeconds int      `json:"ttl_seconds"`
}

type Policy struct {
	Version           int                   `json:"version"`
	DefaultTTLSeconds int                   `json:"default_ttl_seconds"`
	Agents            map[string]AgentRules `json:"agents"`
}

// Decision is the engine's answer, with the reason recorded in the audit log.
type Decision struct {
	Allowed bool
	Rule    string // the rule that decided (allow or deny), "" for default-deny
	Reason  string
	TTLSecs int // only meaningful when Allowed
}

// Default returns the built-in policy used when no file is supplied. It matches
// the demo identities shipped before policy files existed.
func Default() *Policy {
	return &Policy{
		Version:           Version,
		DefaultTTLSeconds: fallbackTTLSecs,
		Agents: map[string]AgentRules{
			"sre-agent":    {Allow: []string{"restart:nginx"}},
			"chatbot":      {Allow: []string{"restart:ui"}},
			"deploy-agent": {Allow: []string{"deploy:payments-service"}},
		},
	}
}

// Load reads and validates a policy file. Unknown JSON fields are an error so
// a typo like "alow" cannot silently produce an empty (deny-all) or wrong policy.
func Load(file string) (*Policy, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func Parse(b []byte) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks structure and every rule's syntax.
func (p *Policy) Validate() error {
	if p.Version != Version {
		return fmt.Errorf("policy: unsupported version %d (want %d)", p.Version, Version)
	}
	if p.DefaultTTLSeconds == 0 {
		p.DefaultTTLSeconds = fallbackTTLSecs
	}
	if err := checkTTL(p.DefaultTTLSeconds); err != nil {
		return fmt.Errorf("policy: default_ttl_seconds: %w", err)
	}
	for name, r := range p.Agents {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("policy: empty agent name")
		}
		if r.TTLSeconds != 0 {
			if err := checkTTL(r.TTLSeconds); err != nil {
				return fmt.Errorf("policy: agent %q ttl_seconds: %w", name, err)
			}
		}
		for _, rule := range append(append([]string{}, r.Allow...), r.Deny...) {
			if err := checkRule(rule); err != nil {
				return fmt.Errorf("policy: agent %q rule %q: %w", name, rule, err)
			}
		}
	}
	return nil
}

func checkTTL(s int) error {
	if s < 1 || s > MaxTTLSeconds {
		return fmt.Errorf("must be between 1 and %d seconds", MaxTTLSeconds)
	}
	return nil
}

func splitRule(rule string) (action, resource string) {
	if i := strings.IndexByte(rule, ':'); i >= 0 {
		return rule[:i], rule[i+1:]
	}
	return rule, ""
}

func checkRule(rule string) error {
	action, res := splitRule(rule)
	if !knownActions[action] {
		return fmt.Errorf("unknown action %q", action)
	}
	if action == "shell" {
		if res != "" {
			return fmt.Errorf("shell takes no resource")
		}
		return nil
	}
	if res == "" || res == "*" {
		return fmt.Errorf("resource must be explicit (a bare * is not allowed)")
	}
	if (action == "restart" || action == "deploy") && !validName(res) {
		return fmt.Errorf("%s resource must be a plain service name ([A-Za-z0-9._-])", action)
	}
	if strings.Contains(res, "..") {
		return fmt.Errorf("resource must not contain ..")
	}
	if strings.Contains(strings.TrimSuffix(res, "/*"), "*") {
		return fmt.Errorf("* is only allowed as a trailing /*")
	}
	return nil
}

// Request is "action:resource", or "shell".
func requestParts(action, resource string) string {
	if action == "shell" {
		return "shell"
	}
	return action + ":" + resource
}

// Evaluate decides a request. It never panics and fails closed.
func (p *Policy) Evaluate(agent, action, resource string) Decision {
	req := requestParts(action, resource)
	if !knownActions[action] {
		return Decision{Reason: "unknown action"}
	}
	if action != "shell" {
		if resource == "" {
			return Decision{Reason: "empty resource"}
		}
		// a requested path must already be in clean form: this closes ../ games
		// without trying to resolve against a filesystem we can't see
		if (action == "restart" || action == "deploy") && !validName(resource) {
			return Decision{Reason: "resource is not a plain service name"}
		}
		if strings.Contains(resource, "..") || (strings.HasPrefix(resource, "/") && path.Clean(resource) != resource) {
			return Decision{Reason: "resource is not a clean path"}
		}
	}
	rules, ok := p.Agents[agent]
	if !ok {
		return Decision{Reason: "unknown agent"}
	}
	for _, d := range rules.Deny {
		if matches(d, action, resource) {
			return Decision{Rule: d, Reason: "explicit deny"}
		}
	}
	for _, a := range rules.Allow {
		if matches(a, action, resource) {
			ttl := rules.TTLSeconds
			if ttl == 0 {
				ttl = p.DefaultTTLSeconds
			}
			if ttl == 0 {
				ttl = fallbackTTLSecs
			}
			return Decision{Allowed: true, Rule: a, Reason: "allowed by rule", TTLSecs: ttl}
		}
	}
	_ = req
	return Decision{Reason: "no matching allow rule (default deny)"}
}

func matches(rule, action, resource string) bool {
	ra, rr := splitRule(rule)
	if ra != action {
		return false
	}
	if action == "shell" {
		return true
	}
	if strings.HasSuffix(rr, "/*") {
		prefix := strings.TrimSuffix(rr, "/*")
		return strings.HasPrefix(resource, prefix+"/")
	}
	return rr == resource
}

// validName reports whether s is a plain service name. restart/deploy resources
// are spliced into an executable path, so slashes and traversal must never get in.
func validName(s string) bool {
	if s == "" || s == "." || strings.Contains(s, "..") {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}
