package aileron

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aileron-sh/aileron/verifiers/go/canonical"
)

// The fixtures live in the main repository, two directories up, and are
// produced by scripts/gen_conformance.py from the Python implementation.
var fixtureRoot = filepath.Join("..", "..", "tests", "conformance")

type expectedVerify struct {
	OK          bool            `json:"ok"`
	Count       int             `json:"count"`
	FirstBadSeq json.RawMessage `json:"first_bad_seq"`
	Errors      []string        `json:"errors"`
	ExitCode    int             `json:"exit_code"`
	Verdict     string          `json:"verdict"`
}

type expectedCheckpoint struct {
	Key      string `json:"key"`
	Valid    bool   `json:"valid"`
	ExitCode int    `json:"exit_code"`
	Verdict  string `json:"verdict"`
}

type expected struct {
	Description string             `json:"description"`
	Verify      expectedVerify     `json:"verify"`
	Checkpoint  expectedCheckpoint `json:"checkpoint"`
}

func requireFixtures(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(fixtureRoot); err != nil {
		t.Fatalf("conformance fixtures not found at %s (run scripts/gen_conformance.py in the repository root): %v", fixtureRoot, err)
	}
}

func caseDirs(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(fixtureRoot, "cases"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("no conformance cases found")
	}
	return names
}

// inDir runs fn with the working directory set to dir, so paths in verdict
// lines come out exactly as the fixtures recorded them.
func inDir(t *testing.T, dir string, fn func()) {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(previous)
	fn()
}

// normalizeError trims the part of a message that carries an exception text
// from the Python runtime, which differs between Python versions (and from
// the Go wording). Everything before the marker is compared exactly.
func normalizeError(msg string) string {
	for _, marker := range []string{"invalid JSON: ", "invalid UTF-8: ", "uncanonicalizable content: "} {
		if i := strings.Index(msg, marker); i >= 0 {
			return msg[:i+len(marker)]
		}
	}
	return msg
}

func hasVerdict(out, errOut *bytes.Buffer, verdict string) bool {
	for _, line := range strings.Split(out.String()+errOut.String(), "\n") {
		if line == verdict {
			return true
		}
	}
	return false
}

func TestJournalFixtures(t *testing.T) {
	requireFixtures(t)
	for _, name := range caseDirs(t) {
		name := name
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(fixtureRoot, "cases", name)
			raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
			if err != nil {
				t.Fatal(err)
			}
			var want expected
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatal(err)
			}
			inDir(t, dir, func() {
				result, err := Verify("journal.jsonl")
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if result.OK != want.Verify.OK || result.Count != want.Verify.Count {
					t.Errorf("Verify: ok=%v count=%d, want ok=%v count=%d\n%s",
						result.OK, result.Count, want.Verify.OK, want.Verify.Count, strings.Join(result.Errors, "\n"))
				}
				wantSeq := strings.TrimSpace(string(want.Verify.FirstBadSeq))
				switch {
				case wantSeq == "null" && result.FirstBadSeq != nil:
					t.Errorf("first_bad_seq = %s, want None", result.FirstBadSeq)
				case wantSeq != "null":
					n, ok := new(big.Int).SetString(wantSeq, 10)
					if !ok {
						t.Fatalf("unreadable first_bad_seq in fixture: %s", wantSeq)
					}
					if result.FirstBadSeq == nil || result.FirstBadSeq.Cmp(n) != 0 {
						t.Errorf("first_bad_seq = %v, want %s", result.FirstBadSeq, n)
					}
				}
				if len(result.Errors) != len(want.Verify.Errors) {
					t.Errorf("errors:\n  got  %q\n  want %q", result.Errors, want.Verify.Errors)
				} else {
					for i := range result.Errors {
						if normalizeError(result.Errors[i]) != normalizeError(want.Verify.Errors[i]) {
							t.Errorf("error %d:\n  got  %q\n  want %q", i, result.Errors[i], want.Verify.Errors[i])
						}
					}
				}

				var out, errOut bytes.Buffer
				code := Run([]string{"verify", "journal.jsonl"}, &out, &errOut)
				if code != want.Verify.ExitCode {
					t.Errorf("verify exit code %d, want %d\n%s%s", code, want.Verify.ExitCode, out.String(), errOut.String())
				}
				if !hasVerdict(&out, &errOut, want.Verify.Verdict) {
					t.Errorf("verify output lacks verdict %q:\n%s%s", want.Verify.Verdict, out.String(), errOut.String())
				}

				valid, err := VerifyCheckpoint("journal.jsonl", want.Checkpoint.Key)
				if err != nil {
					t.Fatalf("VerifyCheckpoint: %v", err)
				}
				if valid != want.Checkpoint.Valid {
					t.Errorf("VerifyCheckpoint = %v, want %v", valid, want.Checkpoint.Valid)
				}
				out.Reset()
				errOut.Reset()
				code = Run([]string{"verify-checkpoint", "journal.jsonl", "--key", want.Checkpoint.Key}, &out, &errOut)
				if code != want.Checkpoint.ExitCode {
					t.Errorf("verify-checkpoint exit code %d, want %d\n%s%s", code, want.Checkpoint.ExitCode, out.String(), errOut.String())
				}
				if !hasVerdict(&out, &errOut, want.Checkpoint.Verdict) {
					t.Errorf("verify-checkpoint output lacks verdict %q:\n%s%s", want.Checkpoint.Verdict, out.String(), errOut.String())
				}
			})
		})
	}
}

func TestCanonicalCases(t *testing.T) {
	requireFixtures(t)
	raw, err := os.ReadFile(filepath.Join(fixtureRoot, "canonical_cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Parsed with our own parser: the file holds lone surrogate escapes that
	// encoding/json would turn into U+FFFD.
	cases, err := canonical.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if cases.Kind != canonical.Array || len(cases.Array) < 100 {
		t.Fatalf("expected a sizeable array of cases, got %d", len(cases.Array))
	}
	for _, c := range cases.Array {
		name := c.Get("name").Str
		source := c.Get("source").Str
		t.Run(name, func(t *testing.T) {
			v, err := canonical.Parse(source)
			if err != nil {
				t.Fatalf("Parse(%q): %v", source, err)
			}
			got, err := canonical.Marshal(v)
			if c.Has("error") {
				if err == nil {
					t.Fatalf("Marshal(%q) = %s, want refusal", source, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Marshal(%q): %v", source, err)
			}
			if want := c.Get("canonical").Str; string(got) != want {
				t.Errorf("canonical(%q)\n  got  %s\n  want %s", source, got, want)
			}
		})
	}
}
