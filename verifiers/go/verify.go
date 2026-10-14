// Package aileron is an independent verifier for Aileron journals, written
// against SPEC.md with no third party dependencies. It reimplements
// `aileron verify` and `aileron verify-checkpoint` so that the record of what
// an agent did can be checked by code its author did not write, in a language
// the recorder was not written in.
//
// Where this file says "Python does X", the reference is src/aileron in the
// main repository; the conformance fixtures under tests/conformance pin the
// two implementations to the same verdicts.
package aileron

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"unicode/utf8"

	"github.com/aileron-sh/aileron/verifiers/go/canonical"
)

// GenesisPrevHash is the prev_hash of the first event in a journal.
const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

// VerifyResult is the outcome of verifying a hash-chained journal. It mirrors
// Python's VerifyResult field for field.
type VerifyResult struct {
	// OK is true when no problem was found.
	OK bool
	// Count is the number of lines that parsed as JSON objects, whether or
	// not they chained correctly.
	Count int
	// FirstBadSeq is the seq of the first event that failed a check, or nil
	// (Python's None) when there was no failure or the failing event had no
	// integer seq. For an unreadable line it is the seq that line should
	// have carried.
	FirstBadSeq *big.Int
	// Errors lists every problem found, in journal order.
	Errors []string
}

// EventHash is sha256 of the canonical JSON of the event minus its "hash"
// member, as lowercase hex. It fails when the event cannot be canonicalized
// (a NaN or infinite float somewhere inside it).
func EventHash(event *canonical.Value) (string, error) {
	return canonical.Digest(event.Without("hash"))
}

// Verify checks the journal at path: seq continuity from 1, prev_hash links
// from the genesis value, and every hash recomputed from the stored bytes.
// It never fails with an error on the journal's contents; whatever the file
// holds, the answer is a verdict.
func Verify(path string) VerifyResult {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return VerifyResult{Errors: []string{"log file not found: " + path}}
		}
		return VerifyResult{Errors: []string{"cannot read log file: " + err.Error()}}
	}
	defer f.Close()
	return verifyReader(f)
}

// problem is one complaint together with the seq Python would attach to it.
type problem struct {
	seq *canonical.Value // nil stands for a Python int that is not a journal value
	n   *big.Int         // used when seq is nil
	msg string
}

func verifyReader(r io.Reader) VerifyResult {
	result := VerifyResult{}
	record := func(problems []problem) {
		for _, p := range problems {
			result.Errors = append(result.Errors, p.msg)
			if result.FirstBadSeq != nil {
				continue
			}
			switch {
			case p.seq == nil:
				result.FirstBadSeq = new(big.Int).Set(p.n)
			case p.seq.Kind == canonical.Int:
				// A boolean is not an integer seq, even though Python's
				// isinstance(True, int) holds; the reference uses type() is int.
				result.FirstBadSeq = p.seq.BigInt()
			}
		}
	}

	expectedSeq := big.NewInt(1)
	expectedPrev := canonical.NewString(GenesisPrevHash)
	broken := false // an earlier line was unreadable, so nothing can chain to it

	reader := bufio.NewReader(r)
	lineno := 0
	for {
		raw, readErr := reader.ReadBytes('\n')
		if len(raw) == 0 && readErr != nil {
			break
		}
		lineno++
		if !utf8.Valid(raw) {
			record([]problem{{n: expectedSeq, msg: fmt.Sprintf("line %d: invalid UTF-8: %s", lineno, utf8Error(raw))}})
			expectedSeq = new(big.Int).Add(expectedSeq, big.NewInt(1))
			broken = true
			continue
		}
		text := canonical.Strip(string(raw))
		if text == "" {
			continue // blank lines carry no event and consume no seq
		}
		event, err := canonical.Parse(text)
		if err != nil {
			record([]problem{{n: expectedSeq, msg: fmt.Sprintf("line %d: invalid JSON: %s", lineno, err)}})
			expectedSeq = new(big.Int).Add(expectedSeq, big.NewInt(1))
			broken = true
			continue
		}
		if event.Kind != canonical.Object {
			record([]problem{{n: expectedSeq, msg: fmt.Sprintf("line %d: event is not a JSON object", lineno)}})
			expectedSeq = new(big.Int).Add(expectedSeq, big.NewInt(1))
			broken = true
			continue
		}

		seq := event.Get("seq")
		// The stored bytes are authoritative: re-serializing must reproduce
		// the line exactly, or something (a duplicate key, a non-canonical
		// number) was smuggled past the parser.
		canon, err := canonical.Marshal(event)
		if err != nil {
			record([]problem{{seq: seq, msg: fmt.Sprintf("line %d: uncanonicalizable content: %s", lineno, err)}})
		} else if string(canon) != text {
			record([]problem{{seq: seq, msg: fmt.Sprintf("line %d: non-canonical encoding", lineno)}})
		}
		result.Count++

		var chain []problem
		// seq must be a JSON integer. Python's == would call 1.0 and true
		// equal to 1; the reference rejects both, so the kind is checked first.
		if seq.Kind != canonical.Int || !seq.EqualsPyInt(expectedSeq) {
			chain = append(chain, problem{seq: seq, msg: fmt.Sprintf(
				"seq discontinuity at line %d: expected %s, got %s", lineno, expectedSeq, canonical.PyStr(seq))})
		}
		if broken {
			chain = append(chain, problem{seq: seq, msg: fmt.Sprintf(
				"seq %s: unverifiable, chain broken at an earlier line", canonical.PyStr(seq))})
		} else if !canonical.Equal(event.Get("prev_hash"), expectedPrev) {
			chain = append(chain, problem{seq: seq, msg: fmt.Sprintf("prev_hash mismatch at seq %s", canonical.PyStr(seq))})
		}
		actual, err := EventHash(event)
		if err != nil || !canonical.Equal(event.Get("hash"), canonical.NewString(actual)) {
			chain = append(chain, problem{seq: seq, msg: fmt.Sprintf("hash mismatch at seq %s (content tampered)", canonical.PyStr(seq))})
		}
		record(chain)

		if seq.Kind == canonical.Int {
			expectedSeq = new(big.Int).Add(seq.BigInt(), big.NewInt(1))
		} else {
			expectedSeq = new(big.Int).Add(expectedSeq, big.NewInt(1))
		}
		if event.Has("hash") {
			expectedPrev = event.Get("hash")
		} else {
			expectedPrev = canonical.NewString(GenesisPrevHash)
		}
		broken = false

		if readErr != nil {
			break
		}
	}
	result.OK = len(result.Errors) == 0
	return result
}

// ReadEvents is the lenient reader, Python's ChainLog.read: every line that
// decodes as UTF-8, is non-blank after stripping, parses as JSON and is an
// object. Anything else is skipped, not reported; Verify is the authority on
// integrity and this reader exists for callers that already hold a verdict.
func ReadEvents(path string) ([]*canonical.Value, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var events []*canonical.Value
	reader := bufio.NewReader(f)
	for {
		raw, readErr := reader.ReadBytes('\n')
		if len(raw) == 0 && readErr != nil {
			break
		}
		if utf8.Valid(raw) {
			if text := canonical.Strip(string(raw)); text != "" {
				if v, err := canonical.Parse(text); err == nil && v.Kind == canonical.Object {
					events = append(events, v)
				}
			}
		}
		if readErr != nil {
			break
		}
	}
	return events, nil
}

// utf8Error describes the first invalid byte of raw in the shape of Python's
// UnicodeDecodeError message.
func utf8Error(raw []byte) string {
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRune(raw[i:])
		if r == utf8.RuneError && size <= 1 {
			reason := "invalid start byte"
			if raw[i] >= 0x80 && raw[i] < 0xc0 {
				reason = "invalid continuation byte"
			} else if raw[i] >= 0xc0 && i+1 >= len(raw) {
				reason = "unexpected end of data"
			}
			return fmt.Sprintf("'utf-8' codec can't decode byte 0x%02x in position %d: %s", raw[i], i, reason)
		}
		i += size
	}
	return "'utf-8' codec can't decode"
}
