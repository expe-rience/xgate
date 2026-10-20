package auditchain

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func fill(t *testing.T, path string, key ed25519.PrivateKey, n int) {
	t.Helper()
	l, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := l.Append(map[string]any{"event": "e", "i": i, "who": "agent"}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
}

func TestValidChainVerifies(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	fill(t, p, nil, 5)
	res, err := VerifyFile(p, nil)
	if err != nil || res.Records != 5 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestEditedRecordDetected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	fill(t, p, nil, 5)
	b, _ := os.ReadFile(p)
	b = []byte(strings.Replace(string(b), `"i":2`, `"i":9`, 1))
	os.WriteFile(p, b, 0o600)
	_, err := VerifyFile(p, nil)
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("want break at line 3, got %v", err)
	}
}

func TestDeletedRecordDetected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	fill(t, p, nil, 5)
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	lines = append(lines[:2], lines[3:]...) // drop record 3
	os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	if _, err := VerifyFile(p, nil); err == nil {
		t.Fatal("deleted middle record not detected")
	}
}

func TestReorderedDetected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	fill(t, p, nil, 4)
	b, _ := os.ReadFile(p)
	l := strings.Split(strings.TrimSpace(string(b)), "\n")
	l[1], l[2] = l[2], l[1]
	os.WriteFile(p, []byte(strings.Join(l, "\n")+"\n"), 0o600)
	if _, err := VerifyFile(p, nil); err == nil {
		t.Fatal("reorder not detected")
	}
}

func TestResumeAfterReopen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	fill(t, p, nil, 3)
	fill(t, p, nil, 2)
	res, err := VerifyFile(p, nil)
	if err != nil || res.Records != 5 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestOpenRefusesTamperedLog(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	fill(t, p, nil, 3)
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), `"who":"agent"`, `"who":"evil"`, 1)), 0o600)
	if _, err := Open(p, nil); err == nil {
		t.Fatal("Open must fail closed on a tampered log")
	}
}

func TestLegacyLogMovedAside(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "a.jsonl")
	os.WriteFile(p, []byte(`{"ts":"x","event":"old"}`+"\n"), 0o600)
	fill(t, p, nil, 2)
	if _, err := VerifyFile(p, nil); err != nil {
		t.Fatal(err)
	}
	m, _ := filepath.Glob(p + ".legacy-*")
	if len(m) != 1 {
		t.Fatalf("legacy file not preserved: %v", m)
	}
}

func TestSignatureStopsRecomputedChain(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	d := t.TempDir()
	p := filepath.Join(d, "a.jsonl")
	fill(t, p, priv, 3)
	if _, err := VerifyFile(p, pub); err != nil {
		t.Fatalf("honest signed log: %v", err)
	}
	// attacker without the key rewrites the whole log with a fresh, internally
	// consistent (but unsigned-by-us) chain
	q := filepath.Join(d, "b.jsonl")
	fill(t, q, nil, 3)
	if _, err := VerifyFile(q, pub); err == nil {
		t.Fatal("forged chain accepted despite signature requirement")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifyFile(p, other); err == nil {
		t.Fatal("wrong public key accepted")
	}
}

func TestConcurrentAppends(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	l, _ := Open(p, nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); l.Append(map[string]any{"i": i}) }(i)
	}
	wg.Wait()
	l.Close()
	res, err := VerifyFile(p, nil)
	if err != nil || res.Records != 50 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestTailTruncationIsUndetectedByChainAlone(t *testing.T) {
	// Documents the known limitation: this is why docs say to ship Head() out.
	p := filepath.Join(t.TempDir(), "a.jsonl")
	fill(t, p, nil, 4)
	b, _ := os.ReadFile(p)
	l := strings.Split(strings.TrimSpace(string(b)), "\n")
	os.WriteFile(p, []byte(strings.Join(l[:2], "\n")+"\n"), 0o600)
	res, err := VerifyFile(p, nil)
	if err != nil || res.Records != 2 {
		t.Fatalf("expected a valid 2-record prefix, got %+v %v", res, err)
	}
}
