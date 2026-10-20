// Package auditchain implements a tamper-evident, append-only JSONL log.
//
// Every record carries a sequence number, the hash of the previous record, and
// its own SHA-256 hash. Editing or deleting any record in the middle of the
// file breaks the chain from that point on, and Verify reports exactly where.
// If a signing key is supplied, each record hash is also signed with Ed25519,
// so an attacker who can write the file but does not hold the key cannot
// recompute a valid chain.
//
// What this does NOT protect against (see docs/limitations.md):
//   - truncating the tail of the log (the remaining prefix is still valid) —
//     ship the head hash to an external sink to catch that;
//   - an attacker who holds the signing key, or any attacker at all when no
//     key is configured, rewriting the whole file with a freshly computed chain.
//
// The package is stdlib-only and does no network I/O.
package auditchain

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Genesis is the "previous hash" of the first record in a chain.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Log is a concurrency-safe chained log writer.
type Log struct {
	mu     sync.Mutex
	f      *os.File
	seq    uint64
	head   string
	signer ed25519.PrivateKey // optional
}

// Open opens (or creates) the log at path. An existing chained log is verified
// before appending resumes; a broken chain is an error (fail closed). A
// pre-existing log that was never chained (no "hash" field on its first line)
// is moved aside to <path>.legacy-<unix> so upgrades don't brick a daemon.
// signer may be nil.
func Open(path string, signer ed25519.PrivateKey) (*Log, error) {
	l := &Log{head: Genesis, signer: signer}
	if st, err := os.Stat(path); err == nil && st.Size() > 0 {
		legacy, err := isLegacy(path)
		if err != nil {
			return nil, err
		}
		if legacy {
			dst := fmt.Sprintf("%s.legacy-%d", path, time.Now().Unix())
			if err := os.Rename(path, dst); err != nil {
				return nil, fmt.Errorf("auditchain: moving unchained log aside: %w", err)
			}
		} else {
			res, err := VerifyFile(path, nil)
			if err != nil {
				return nil, fmt.Errorf("auditchain: existing log failed verification, refusing to append: %w", err)
			}
			l.seq, l.head = res.Records, res.Head
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

// Append adds one record. Reserved keys seq, prev, hash and sig are overwritten.
func (l *Log) Append(rec map[string]any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]any, len(rec)+4)
	for k, v := range rec {
		out[k] = v
	}
	delete(out, "hash")
	delete(out, "sig")
	out["seq"] = l.seq + 1
	out["prev"] = l.head
	body, err := json.Marshal(out) // map keys are sorted => deterministic
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	h := hex.EncodeToString(sum[:])
	out["hash"] = h
	if l.signer != nil {
		out["sig"] = hex.EncodeToString(ed25519.Sign(l.signer, []byte(h)))
	}
	line, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return err
	}
	l.seq++
	l.head = h
	return nil
}

// Head returns the number of records and the current head hash.
func (l *Log) Head() (uint64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq, l.head
}

// Close closes the underlying file.
func (l *Log) Close() error { return l.f.Close() }

// Result is the outcome of a successful verification.
type Result struct {
	Records uint64
	Head    string
	Signed  bool // every record carried a signature that verified
}

// ErrBroken is returned (wrapped) when verification fails.
var ErrBroken = errors.New("audit chain broken")

// VerifyFile verifies the whole file. If pub is non-nil, every record must
// carry a valid signature by that key.
func VerifyFile(path string, pub ed25519.PublicKey) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	return Verify(f, pub)
}

// Verify verifies a log read from r.
func Verify(r io.Reader, pub ed25519.PublicKey) (Result, error) {
	res := Result{Head: Genesis, Signed: pub != nil}
	br := bufio.NewReaderSize(r, 1<<20)
	line := 0
	for {
		raw, err := br.ReadBytes('\n')
		if len(raw) > 0 {
			line++
			if err := checkLine(bytes.TrimSpace(raw), line, &res, pub); err != nil {
				return res, err
			}
		}
		if err == io.EOF {
			return res, nil
		}
		if err != nil {
			return res, err
		}
	}
}

func checkLine(raw []byte, line int, res *Result, pub ed25519.PublicKey) error {
	if len(raw) == 0 {
		return fmt.Errorf("%w: line %d: blank line", ErrBroken, line)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return fmt.Errorf("%w: line %d: not valid JSON", ErrBroken, line)
	}
	hash, _ := m["hash"].(string)
	prev, _ := m["prev"].(string)
	sig, _ := m["sig"].(string)
	seqNum, _ := m["seq"].(json.Number)
	if hash == "" || prev == "" || seqNum == "" {
		return fmt.Errorf("%w: line %d: missing seq/prev/hash", ErrBroken, line)
	}
	if want := fmt.Sprint(res.Records + 1); seqNum.String() != want {
		return fmt.Errorf("%w: line %d: sequence is %s, expected %s (record deleted, reordered or inserted)", ErrBroken, line, seqNum, want)
	}
	if prev != res.Head {
		return fmt.Errorf("%w: line %d: prev hash does not match the preceding record", ErrBroken, line)
	}
	delete(m, "hash")
	delete(m, "sig")
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("%w: line %d: %v", ErrBroken, line, err)
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != hash {
		return fmt.Errorf("%w: line %d: record contents do not match its hash (edited)", ErrBroken, line)
	}
	if pub != nil {
		sb, err := hex.DecodeString(sig)
		if err != nil || len(sb) != ed25519.SignatureSize || !ed25519.Verify(pub, []byte(hash), sb) {
			return fmt.Errorf("%w: line %d: signature missing or invalid", ErrBroken, line)
		}
	}
	res.Records++
	res.Head = hash
	return nil
}

func isLegacy(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<20)
	raw, err := br.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	var m map[string]any
	if json.Unmarshal(bytes.TrimSpace(raw), &m) != nil {
		return true, nil
	}
	_, hasHash := m["hash"]
	return !hasHash, nil
}
