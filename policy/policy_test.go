package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mk(t *testing.T, js string) *Policy {
	t.Helper()
	p, err := Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const base = `{"version":1,"default_ttl_seconds":60,"agents":{
 "sre":{"allow":["restart:nginx","read:/var/log/nginx/*"],"deny":["restart:payments-db"],"ttl_seconds":30},
 "ops":{"allow":["restart:*"]}}}`

func TestAllowAndTTL(t *testing.T) {
	// "restart:*" must be rejected at load, so use the first agent only
	_ = base
	p := mk(t, `{"version":1,"agents":{"sre":{"allow":["restart:nginx"],"ttl_seconds":30}}}`)
	d := p.Evaluate("sre", "restart", "nginx")
	if !d.Allowed || d.TTLSecs != 30 || d.Rule != "restart:nginx" {
		t.Fatalf("%+v", d)
	}
}

func TestDefaultTTLApplied(t *testing.T) {
	p := mk(t, `{"version":1,"default_ttl_seconds":45,"agents":{"a":{"allow":["restart:x"]}}}`)
	if d := p.Evaluate("a", "restart", "x"); d.TTLSecs != 45 {
		t.Fatalf("%+v", d)
	}
}

func TestDefaultDeny(t *testing.T) {
	p := mk(t, `{"version":1,"agents":{"a":{"allow":["restart:x"]}}}`)
	for _, c := range [][3]string{
		{"a", "restart", "y"}, {"a", "write", "x"}, {"a", "shell", ""}, {"nobody", "restart", "x"},
	} {
		if d := p.Evaluate(c[0], c[1], c[2]); d.Allowed {
			t.Fatalf("%v must be denied: %+v", c, d)
		}
	}
}

func TestDenyBeatsAllow(t *testing.T) {
	p := mk(t, `{"version":1,"agents":{"a":{"allow":["read:/etc/*"],"deny":["read:/etc/shadow"]}}}`)
	if d := p.Evaluate("a", "read", "/etc/shadow"); d.Allowed || d.Reason != "explicit deny" {
		t.Fatalf("%+v", d)
	}
	if d := p.Evaluate("a", "read", "/etc/hosts"); !d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestWildcardIsBoundaryAware(t *testing.T) {
	p := mk(t, `{"version":1,"agents":{"a":{"allow":["read:/var/log/*"]}}}`)
	if !p.Evaluate("a", "read", "/var/log/nginx/error.log").Allowed {
		t.Fatal("should match beneath dir")
	}
	for _, r := range []string{"/var/logs/x", "/var/log", "/var/logfoo/x", "/var/log/../../etc/shadow", "/var//log/x", "/var/log/./x"} {
		if p.Evaluate("a", "read", r).Allowed {
			t.Fatalf("%q must not match", r)
		}
	}
}

func TestShellRule(t *testing.T) {
	p := mk(t, `{"version":1,"agents":{"admin":{"allow":["shell"]}}}`)
	if !p.Evaluate("admin", "shell", "").Allowed {
		t.Fatal("shell should be allowed")
	}
	if p.Evaluate("other", "shell", "").Allowed {
		t.Fatal("other agent must not get shell")
	}
}

func TestInvalidPoliciesRejected(t *testing.T) {
	bad := map[string]string{
		"bare wildcard":    `{"version":1,"agents":{"a":{"allow":["restart:*"]}}}`,
		"unknown action":   `{"version":1,"agents":{"a":{"allow":["delete:ui"]}}}`,
		"typo field":       `{"version":1,"agents":{"a":{"alow":["restart:x"]}}}`,
		"dotdot":           `{"version":1,"agents":{"a":{"allow":["read:/etc/../x"]}}}`,
		"mid wildcard":     `{"version":1,"agents":{"a":{"allow":["read:/va*/log"]}}}`,
		"wrong version":    `{"version":2,"agents":{}}`,
		"ttl too long":     `{"version":1,"agents":{"a":{"allow":["restart:x"],"ttl_seconds":99999}}}`,
		"negative ttl":     `{"version":1,"agents":{"a":{"allow":["restart:x"],"ttl_seconds":-1}}}`,
		"shell w/resource": `{"version":1,"agents":{"a":{"allow":["shell:bash"]}}}`,
		"not json":         `hello`,
	}
	for name, js := range bad {
		if _, err := Parse([]byte(js)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestEmptyResourceAndUnknownActionDenied(t *testing.T) {
	p := mk(t, `{"version":1,"agents":{"a":{"allow":["restart:x"]}}}`)
	if p.Evaluate("a", "restart", "").Allowed || p.Evaluate("a", "format", "disk").Allowed {
		t.Fatal("must deny")
	}
}

func TestLoadFileAndDefault(t *testing.T) {
	f := filepath.Join(t.TempDir(), "p.json")
	os.WriteFile(f, []byte(`{"version":1,"agents":{"a":{"allow":["restart:x"]}}}`), 0o600)
	if _, err := Load(f); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(f + ".nope"); err == nil {
		t.Fatal("missing file must error")
	}
	d := Default()
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if !d.Evaluate("sre-agent", "restart", "nginx").Allowed {
		t.Fatal("default must keep the demo identities working")
	}
	if d.Evaluate("sre-agent", "write", "/etc/nginx/nginx.conf").Allowed {
		t.Fatal("default must still deny the injection demo")
	}
	if d.Evaluate("chatbot", "delete", "ui").Allowed {
		t.Fatal("chatbot delete must be denied")
	}
}

func TestErrorMessagesMentionRule(t *testing.T) {
	_, err := Parse([]byte(`{"version":1,"agents":{"a":{"allow":["restart:*"]}}}`))
	if err == nil || !strings.Contains(err.Error(), "restart:*") {
		t.Fatalf("%v", err)
	}
}

func TestServiceNamesCannotInjectPaths(t *testing.T) {
	p := mk(t, `{"version":1,"agents":{"a":{"allow":["restart:nginx"]}}}`)
	for _, r := range []string{"../../bin/sh", "nginx/../sh", "ng inx", "nginx;id", "/bin/sh"} {
		if p.Evaluate("a", "restart", r).Allowed {
			t.Fatalf("%q must be denied", r)
		}
	}
	if _, err := Parse([]byte(`{"version":1,"agents":{"a":{"allow":["restart:/bin/sh"]}}}`)); err == nil {
		t.Fatal("restart rule with a path must be rejected at load")
	}
}
