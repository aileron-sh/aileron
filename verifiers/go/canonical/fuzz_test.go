package canonical

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Native Go fuzz targets live here (FuzzParse) and in the verifier package
// (FuzzVerify). Under a plain go test they run only their seed corpus, as
// ordinary tests. To fuzz for longer, from verifiers/go:
//
//	go test -run '^$' -fuzz '^FuzzParse$' -fuzztime 10m ./canonical
//	go test -run '^$' -fuzz '^FuzzVerify$' -fuzztime 10m .
//
// go test fuzzes one target in one package at a time and uses every CPU
// unless -parallel says otherwise. An input that fails is saved under
// testdata/fuzz/<target>/ in that package; commit it with the fix and go test
// replays it as a regression test from then on.

// FuzzParse checks that Parse never panics, and that whatever it accepts and
// Marshal can write comes back as the same bytes when parsed and written
// again. Canonical JSON is the hash input, so a value whose canonical form
// drifted on a second pass would be a journal whose hashes depend on how many
// times it was copied.
func FuzzParse(f *testing.F) {
	for _, source := range canonicalCaseSources(f) {
		f.Add(source)
	}
	for _, source := range []string{
		"", " ", "[", "]", "{", `{"a":`, `{"a":1,}`, "-", "-0", "01", "1e", "1E+400", "-1e-400",
		"NaN", "-Infinity", `"\ud800"`, `"\udc00\ud800"`, `"é😀"`, "\"\x7f\"", "\xef\xbb\xbf{}",
		`{"b":1,"a":2,"b":3}`, `[1,2.0,3e0,null,true,false,"x",{}]`, "\xff", "\"\xed\xa0\x80\"",
	} {
		f.Add(source)
	}
	f.Fuzz(func(t *testing.T, doc string) {
		v, err := Parse(doc)
		if err != nil {
			return
		}
		out, err := Marshal(v)
		if err != nil {
			var nonFinite *RangeError
			if !errors.As(err, &nonFinite) {
				t.Fatalf("Marshal refused %q with %v; only NaN and infinities may be refused", doc, err)
			}
			return
		}
		for i, c := range out {
			if c >= 0x80 {
				t.Fatalf("Marshal(%q) wrote non-ASCII byte 0x%02x at %d", doc, c, i)
			}
		}
		again, err := Parse(string(out))
		if err != nil {
			t.Fatalf("canonical output %q of %q does not parse: %v", out, doc, err)
		}
		out2, err := Marshal(again)
		if err != nil {
			t.Fatalf("canonical output %q of %q cannot be written again: %v", out, doc, err)
		}
		if !bytes.Equal(out, out2) {
			t.Fatalf("canonical form of %q is not stable:\n first  %q\n second %q", doc, out, out2)
		}
	})
}

// canonicalCaseSources returns the source text of every case in
// tests/conformance/canonical_cases.json, the file the Python implementation
// generates.
func canonicalCaseSources(tb testing.TB) []string {
	tb.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "conformance", "canonical_cases.json"))
	if err != nil {
		tb.Fatalf("conformance fixtures not found (run scripts/gen_conformance.py in the repository root): %v", err)
	}
	// Parsed with this package: the file holds lone surrogate escapes.
	cases, err := Parse(string(raw))
	if err != nil {
		tb.Fatal(err)
	}
	var sources []string
	for _, c := range cases.Array {
		sources = append(sources, c.Get("source").Str)
	}
	if len(sources) == 0 {
		tb.Fatal("no canonical cases found")
	}
	return sources
}
