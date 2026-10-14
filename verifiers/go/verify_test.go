package aileron

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aileron-sh/aileron/verifiers/go/canonical"
)

// event builds a canonical journal line for one minimal event, chaining it
// to prev. Only the fields the chain depends on are populated.
func event(t *testing.T, seq int, prev, name string) (line, hash string) {
	t.Helper()
	src := fmt.Sprintf(`{"id":"%032x","ts":"2026-01-01T00:00:00.000Z","seq":%d,"session_id":"s",`+
		`"agent":{"name":"a","framework":"f","version":null},"type":"tool_call",`+
		`"tool":{"name":%q,"arguments_digest":null,"arguments":null},"result":null,"result_digest":null,`+
		`"status":"ok","latency_ms":null,"policy":null,"meta":{},"prev_hash":%q,"hash":"%s"}`,
		seq, seq, name, prev, strings.Repeat("0", 64))
	v, err := canonical.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	hash, err = EventHash(v)
	if err != nil {
		t.Fatal(err)
	}
	v.Object["hash"] = canonical.NewString(hash)
	out, err := canonical.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out), hash
}

func writeChain(t *testing.T, path string, n int) (lines []string, hashes []string) {
	t.Helper()
	prev := GenesisPrevHash
	for i := 1; i <= n; i++ {
		line, hash := event(t, i, prev, fmt.Sprintf("tool_%d", i))
		lines = append(lines, line)
		hashes = append(hashes, hash)
		prev = hash
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return lines, hashes
}

func TestVerifyHappyPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	writeChain(t, path, 4)
	result := Verify(path)
	if !result.OK || result.Count != 4 || result.FirstBadSeq != nil || len(result.Errors) != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestVerifyMissingFileIsTamperedAtSeqNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.jsonl")
	result := Verify(path)
	if result.OK || result.Count != 0 || result.FirstBadSeq != nil {
		t.Fatalf("unexpected result: %+v", result)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"verify", path}, &out, &errOut); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "TAMPERED at seq None in ") {
		t.Fatalf("stderr: %s", errOut.String())
	}
}

func TestVerifyBoolSeqFollowsPython(t *testing.T) {
	// Python's isinstance(True, int) is true and True == 1, so a journal whose
	// first event carries "seq":true passes the continuity check in the
	// reference implementation. The Go port must agree, including in how it
	// reports a later failure's first_bad_seq.
	line, hash := event(t, 1, GenesisPrevHash, "t")
	line = strings.Replace(line, `"seq":1,`, `"seq":true,`, 1)
	v, _ := canonical.Parse(line)
	hash, _ = EventHash(v)
	v.Object["hash"] = canonical.NewString(hash)
	out, _ := canonical.Marshal(v)
	line2, _ := event(t, 2, hash, "t2")
	path := filepath.Join(t.TempDir(), "j.jsonl")
	os.WriteFile(path, []byte(string(out)+"\n"+line2+"\n"), 0o644)
	result := Verify(path)
	if !result.OK {
		t.Fatalf("want OK, got %+v", result)
	}
	// Now break the first event: first_bad_seq is Python's True, printed as 1
	// by big.Int (Python prints True; the fixtures never carry this case).
	broken := strings.Replace(string(out), `"status":"ok"`, `"status":"error"`, 1)
	os.WriteFile(path, []byte(broken+"\n"+line2+"\n"), 0o644)
	result = Verify(path)
	if result.OK || result.FirstBadSeq == nil || result.FirstBadSeq.Int64() != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestVerifyCLIUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run(nil, &out, &errOut); code != 2 {
		t.Errorf("no args: exit %d", code)
	}
	if code := Run([]string{"bogus"}, &out, &errOut); code != 2 {
		t.Errorf("unknown command: exit %d", code)
	}
	if code := Run([]string{"verify"}, &out, &errOut); code != 2 {
		t.Errorf("verify without path: exit %d", code)
	}
	if code := Run([]string{"verify", "a", "b"}, &out, &errOut); code != 2 {
		t.Errorf("verify with two paths: exit %d", code)
	}
	if code := Run([]string{"verify-checkpoint", "x", "--key"}, &out, &errOut); code != 2 {
		t.Errorf("--key without value: exit %d", code)
	}
	if code := Run([]string{"--help"}, &out, &errOut); code != 0 {
		t.Errorf("--help: exit %d", code)
	}
}

func TestCanonicalSubcommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "in.json")
	os.WriteFile(path, []byte(" {\"b\": 5.0, \"a\": \"é<>&\"} \n"), 0o644)
	var out, errOut bytes.Buffer
	if code := Run([]string{"canonical", path}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if out.String() != "{\"a\":\"\\u00e9<>&\",\"b\":5.0}\n" {
		t.Fatalf("output %q", out.String())
	}
	os.WriteFile(path, []byte("NaN"), 0o644)
	if code := Run([]string{"canonical", path}, &out, &errOut); code != 1 {
		t.Fatalf("NaN: exit %d", code)
	}
}

// --------------------------------------------------------------- checkpoints

type signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	dir  string
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	os.WriteFile(filepath.Join(dir, PublicKeyName), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644)
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	os.WriteFile(filepath.Join(dir, PrivateKeyName), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600)
	return &signer{priv: priv, pub: pub, dir: dir}
}

// checkpoint signs a checkpoint line. indexLiteral and countLiteral are JSON
// source text so tests can plant odd types.
func (s *signer) checkpoint(t *testing.T, indexLiteral, prevHash, countLiteral, tip string) (line, hash string) {
	t.Helper()
	src := fmt.Sprintf(`{"ts":"2026-01-01T00:00:00.000Z","log_path":"j.jsonl","index":%s,"prev_checkpoint_hash":%q,"count":%s,"tip_hash":%q}`,
		indexLiteral, prevHash, countLiteral, tip)
	v, err := canonical.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := SignedPayload(v)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(s.priv, payload)
	v.Keys = append(v.Keys, "signature", "pubkey_path")
	v.Object["signature"] = canonical.NewString(base64.StdEncoding.EncodeToString(sig))
	v.Object["pubkey_path"] = canonical.NewString("./" + PublicKeyName)
	out, _ := canonical.Marshal(v)
	sum := sha256.Sum256(payload)
	return string(out), hex.EncodeToString(sum[:])
}

func TestVerifyCheckpointPrefixSemantics(t *testing.T) {
	s := newSigner(t)
	log := filepath.Join(s.dir, "j.jsonl")
	lines, hashes := writeChain(t, log, 3)
	ck, _ := s.checkpoint(t, "1", GenesisPrevHash, "3", hashes[2])
	os.WriteFile(CheckpointsPath(log), []byte(ck+"\n"), 0o644)

	for _, key := range []string{filepath.Join(s.dir, PublicKeyName), filepath.Join(s.dir, PrivateKeyName), s.dir} {
		valid, err := VerifyCheckpoint(log, key)
		if err != nil || !valid {
			t.Fatalf("key %s: valid=%v err=%v", key, valid, err)
		}
	}

	// Appending keeps the checkpoint valid.
	line4, _ := event(t, 4, hashes[2], "later")
	os.WriteFile(log, []byte(strings.Join(append(lines, line4), "\n")+"\n"), 0o644)
	if valid, _ := VerifyCheckpoint(log, s.dir); !valid {
		t.Fatal("append after signing should stay valid")
	}
	// Truncating below the prefix does not.
	os.WriteFile(log, []byte(strings.Join(lines[:2], "\n")+"\n"), 0o644)
	if valid, _ := VerifyCheckpoint(log, s.dir); valid {
		t.Fatal("truncation below the signed prefix should fail")
	}
	problems, err := CheckAgainstCheckpoints(log)
	if err != nil || len(problems) != 1 || !strings.Contains(problems[0], "log has 2 events but a checkpoint attests to 3") {
		t.Fatalf("cross-check: %v %v", problems, err)
	}
}

func TestVerifyCheckpointRejectsBadSignatureAndZeroCount(t *testing.T) {
	s := newSigner(t)
	other := newSigner(t)
	log := filepath.Join(s.dir, "j.jsonl")
	_, hashes := writeChain(t, log, 2)
	ck, _ := other.checkpoint(t, "1", GenesisPrevHash, "2", hashes[1])
	os.WriteFile(CheckpointsPath(log), []byte(ck+"\n"), 0o644)
	if valid, _ := VerifyCheckpoint(log, s.dir); valid {
		t.Fatal("signature from another key accepted")
	}
	ck, _ = s.checkpoint(t, "1", GenesisPrevHash, "0", hashes[1])
	os.WriteFile(CheckpointsPath(log), []byte(ck+"\n"), 0o644)
	if valid, _ := VerifyCheckpoint(log, s.dir); valid {
		t.Fatal("a count=0 checkpoint attests to nothing and must not verify")
	}
	ck, _ = s.checkpoint(t, "1", GenesisPrevHash, "2.0", hashes[1])
	os.WriteFile(CheckpointsPath(log), []byte(ck+"\n"), 0o644)
	if valid, _ := VerifyCheckpoint(log, s.dir); valid {
		t.Fatal("a float count is not a usable count")
	}
	problems, _ := CheckAgainstCheckpoints(log)
	if len(problems) != 1 || !strings.Contains(problems[0], "unusable count (2.0)") {
		t.Fatalf("cross-check should report the float count: %v", problems)
	}
}

func TestVerifyCheckpointChainOfCheckpoints(t *testing.T) {
	s := newSigner(t)
	log := filepath.Join(s.dir, "j.jsonl")
	_, hashes := writeChain(t, log, 6)
	ck1, h1 := s.checkpoint(t, "1", GenesisPrevHash, "2", hashes[1])
	ck2, h2 := s.checkpoint(t, "2", h1, "4", hashes[3])
	ck3, _ := s.checkpoint(t, "3", h2, "6", hashes[5])
	write := func(lines ...string) {
		os.WriteFile(CheckpointsPath(log), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	}
	write(ck1, ck2, ck3)
	if valid, _ := VerifyCheckpoint(log, s.dir); !valid {
		t.Fatal("three chained checkpoints should verify")
	}
	write(ck3, ck1, ck2)
	if valid, _ := VerifyCheckpoint(log, s.dir); !valid {
		t.Fatal("file order is not meaningful")
	}
	write(ck1, ck3)
	if valid, _ := VerifyCheckpoint(log, s.dir); valid {
		t.Fatal("a deleted intermediate checkpoint must be detected")
	}
	write(ck1, ck2, ck2, ck3)
	if valid, _ := VerifyCheckpoint(log, s.dir); valid {
		t.Fatal("a duplicated checkpoint must be detected")
	}
	// Python accepts index true as 1 (bool is an int there); so do we.
	ckTrue, hTrue := s.checkpoint(t, "true", GenesisPrevHash, "2", hashes[1])
	ckNext, _ := s.checkpoint(t, "2", hTrue, "4", hashes[3])
	write(ckTrue, ckNext)
	if valid, _ := VerifyCheckpoint(log, s.dir); !valid {
		t.Fatal("index true should sort and compare as 1, matching the reference")
	}
}

func TestLoadPublicKeyErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "k.pub")
	os.WriteFile(bad, []byte("not pem"), 0o644)
	if _, err := LoadPublicKey(bad); err == nil {
		t.Error("garbage accepted")
	}
	if _, err := LoadPublicKey(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted")
	}
	if _, err := LoadPublicKey(dir); err == nil {
		t.Error("empty directory accepted")
	}
}

func TestPyBase64DecodeMatchesCPython(t *testing.T) {
	ok := map[string]string{
		"YQ==":     "a",
		"YQ===":    "a",
		"Y Q==":    "a",
		"YQ==zzz":  "a",
		"===":      "",
		"YQ==YQ==": "a",
		"=YQ==":    "a",
		"YQ=x=":    "a\x0c",
		"YWJj":     "abc",
		"YW-Jj":    "abc", // '-' is not in the standard alphabet and is discarded
	}
	for in, want := range ok {
		got, err := pyBase64Decode(in)
		if err != nil || string(got) != want {
			t.Errorf("decode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"YQ", "Y", "YQ=", "YWJ", "é"} {
		if _, err := pyBase64Decode(in); err == nil {
			t.Errorf("decode(%q) succeeded, want error", in)
		}
	}
}

func TestReadCheckpointsUniversalNewlinesAndSkips(t *testing.T) {
	log := filepath.Join(t.TempDir(), "j.jsonl")
	os.WriteFile(CheckpointsPath(log), []byte("{\"a\":1}\r\n\r\n42\rnot json\n {\"b\":2} \n"), 0o644)
	cks, err := ReadCheckpoints(log)
	if err != nil || len(cks) != 2 {
		t.Fatalf("got %d checkpoints, err %v", len(cks), err)
	}
	os.WriteFile(CheckpointsPath(log), []byte("{\"a\":\"\xff\"}\n"), 0o644)
	if _, err := ReadCheckpoints(log); err == nil {
		t.Fatal("invalid UTF-8 in the checkpoints file should be an error, as Python raises")
	}
	var out, errOut bytes.Buffer
	writeChain(t, log, 1)
	if code := Run([]string{"verify", log}, &out, &errOut); code != 1 {
		t.Fatalf("verify with an undecodable checkpoints file: exit %d, want 1", code)
	}
}
