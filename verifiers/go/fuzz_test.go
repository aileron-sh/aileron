package aileron

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzVerify verifies arbitrary bytes as a one-line journal (first) and as a
// two-line journal (first, a newline, second). Under a plain go test only the
// seed corpus runs; see canonical/fuzz_test.go for how to fuzz for longer.
//
// What must hold for any input:
//   - nothing panics;
//   - the verdict is OK, TAMPERED or an operational error, and the command
//     line prints exactly what the library found, with the matching exit code;
//   - a read that fails part way through is an operational error, never a
//     verdict, whatever the bytes before the failure were;
//   - the lenient reader finds exactly Count events, since VerifyCheckpoint
//     indexes the events it returns by the count Verify reports;
//   - adding a line never changes what was said about the lines before it.
//
// Everything stays in memory. Writing each input to a file made every run ten
// times slower, and the fuzzer reruns an interesting input thousands of times
// while it shrinks it, so it spent most of its time stalled.
func FuzzVerify(f *testing.F) {
	// Consecutive line pairs from journals the Python implementation wrote:
	// intact links, broken lines, odd encodings, non-integer seqs.
	for _, name := range []string{
		"valid_chain", "broken_lines", "non_canonical_encoding", "seq_as_bool", "seq_as_float",
		"unicode_and_numbers", "non_finite_floats", "whitespace_tolerance", "capture_content",
	} {
		data, err := os.ReadFile(filepath.Join(fixtureRoot, "cases", name, "journal.jsonl"))
		if err != nil {
			f.Fatalf("conformance fixtures not found (run scripts/gen_conformance.py in the repository root): %v", err)
		}
		lines := bytes.Split(data, []byte("\n"))
		for i := 0; i+1 < len(lines); i++ {
			f.Add(lines[i], lines[i+1])
		}
	}
	first, hash := event(f, 1, GenesisPrevHash, "seed_one")
	second, _ := event(f, 2, hash, "seed_two")
	f.Add([]byte(first), []byte(second))
	f.Add([]byte{}, []byte{})
	f.Add([]byte(" \t"), []byte(first))
	f.Add([]byte("\xef\xbb\xbf"+first), []byte(second))
	f.Add([]byte(first+"\r"), []byte("\xe2\x82"))

	// The command line cross-checks a journal against <path>.checkpoints.jsonl.
	// Nothing is ever written in this directory, so there is never one.
	path := filepath.Join(f.TempDir(), "journal.jsonl")

	f.Fuzz(func(t *testing.T, first, second []byte) {
		one := first
		two := make([]byte, 0, len(first)+1+len(second))
		two = append(append(append(two, first...), '\n'), second...)

		r1 := verdictOf(t, path, one)
		r2 := verdictOf(t, path, two)

		// Each line is judged on itself and the lines before it, so the
		// one-line journal is a prefix of the two-line one in every respect.
		// The exception text after "invalid UTF-8: " may differ, because the
		// newline after the first line can turn a truncated sequence into an
		// invalid continuation byte; Python words those two differently too.
		if r1.Count > r2.Count || (r2.OK && !r1.OK) || len(r1.Errors) > len(r2.Errors) {
			t.Fatalf("appending a line changed the verdict on the first:\n one %+v\n two %+v", r1, r2)
		}
		for i := range r1.Errors {
			if normalizeError(r1.Errors[i]) != normalizeError(r2.Errors[i]) {
				t.Fatalf("error %d changed when a line was appended:\n one %q\n two %q", i, r1.Errors[i], r2.Errors[i])
			}
		}
		if r1.FirstBadSeq != nil && (r2.FirstBadSeq == nil || r1.FirstBadSeq.Cmp(r2.FirstBadSeq) != 0) {
			t.Fatalf("first_bad_seq changed when a line was appended: %v then %v", r1.FirstBadSeq, r2.FirstBadSeq)
		}
	})
}

var errFuzzRead = errors.New("input/output error")

// verdictOf verifies journal, checks the library and the command line agree
// on it, and returns the library's result. path is only used in the verdict
// lines and to look for a checkpoints file, which never exists.
func verdictOf(t *testing.T, path string, journal []byte) VerifyResult {
	t.Helper()
	result, err := verifyReader(bytes.NewReader(journal))
	if err != nil {
		t.Fatalf("reading from memory cannot fail, but got %v", err)
	}
	if result.OK != (len(result.Errors) == 0) {
		t.Fatalf("OK is %v with errors %q", result.OK, result.Errors)
	}
	if result.OK && result.FirstBadSeq != nil {
		t.Fatalf("OK with first_bad_seq %v", result.FirstBadSeq)
	}
	if lines := bytes.Count(journal, []byte("\n")) + 1; result.Count > lines {
		t.Fatalf("%d events counted in %d lines", result.Count, lines)
	}
	events, err := readEvents(bytes.NewReader(journal))
	if err != nil || len(events) != result.Count {
		t.Fatalf("the lenient reader found %d events (%v), Verify counted %d", len(events), err, result.Count)
	}

	// OK or TAMPERED, printed exactly as the library found it.
	var out, errOut bytes.Buffer
	code := reportVerify(path, result, nil, false, &out, &errOut)
	wantOut, wantErr, wantCode := "", "", 0
	if result.OK {
		wantOut = fmt.Sprintf("OK: %d events verified in %s\n", result.Count, path)
	} else {
		var b strings.Builder
		for _, e := range result.Errors {
			b.WriteString("error: " + e + "\n")
		}
		seq := "None"
		if result.FirstBadSeq != nil {
			seq = result.FirstBadSeq.String()
		}
		fmt.Fprintf(&b, "TAMPERED at seq %s in %s\n", seq, path)
		wantErr, wantCode = b.String(), 2
	}
	if code != wantCode || out.String() != wantOut || errOut.String() != wantErr {
		t.Fatalf("exit %d, stdout %q, stderr %q\nwant exit %d, stdout %q, stderr %q",
			code, out.String(), errOut.String(), wantCode, wantOut, wantErr)
	}

	// The same bytes from a reader that fails half way through: an
	// operational error, whatever came before the failure.
	failed, err := verifyReader(&failingReader{data: journal, n: len(journal) / 2, err: errFuzzRead})
	if !errors.Is(err, errFuzzRead) || failed.OK || failed.Count != 0 || failed.Errors != nil || failed.FirstBadSeq != nil {
		t.Fatalf("a failed read gave %+v, %v; want no verdict and the read error", failed, err)
	}
	out.Reset()
	errOut.Reset()
	if code := reportVerify(path, failed, err, false, &out, &errOut); code != 1 || out.Len() != 0 ||
		errOut.String() != "error: "+errFuzzRead.Error()+"\n" {
		t.Fatalf("a failed read: exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
	return result
}
