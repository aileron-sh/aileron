package canonical

import (
	"math"
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *Value {
	t.Helper()
	v, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	return v
}

func canon(t *testing.T, src string) string {
	t.Helper()
	out, err := Marshal(mustParse(t, src))
	if err != nil {
		t.Fatalf("Marshal(%q): %v", src, err)
	}
	return string(out)
}

func TestFormatFloatMatchesPythonRepr(t *testing.T) {
	cases := map[float64]string{
		0.0:                     "0.0",
		math.Copysign(0, -1):    "-0.0",
		1.0:                     "1.0",
		5.0:                     "5.0",
		100.0:                   "100.0",
		0.1:                     "0.1",
		0.30000000000000004:     "0.30000000000000004", // what 0.1 + 0.2 gives at run time
		0.0001:                  "0.0001",              // exponent -4: positional
		0.00001:                 "1e-05",               // exponent -5: exponent form
		0.0000999:               "9.99e-05",
		1e15:                    "1000000000000000.0", // exponent 15: positional
		9999999999999998.0:      "9999999999999998.0",
		1e16:                    "1e+16", // exponent 16: exponent form
		1.5e16:                  "1.5e+16",
		123456789012345680.0:    "1.2345678901234568e+17",
		1e21:                    "1e+21",
		1e22:                    "1e+22",
		1.5e300:                 "1.5e+300",
		5e-324:                  "5e-324",
		2.2250738585072014e-308: "2.2250738585072014e-308",
		1.7976931348623157e308:  "1.7976931348623157e+308",
		-1e-7:                   "-1e-07",
		-123.456:                "-123.456",
		123456789.123456789:     "123456789.12345679",
		math.NaN():              "nan",
		math.Inf(1):             "inf",
		math.Inf(-1):            "-inf",
	}
	for f, want := range cases {
		if got := FormatFloat(f); got != want {
			t.Errorf("FormatFloat(%v) = %q, want %q", f, got, want)
		}
	}
}

func TestNumbersKeepPythonTypes(t *testing.T) {
	cases := map[string]string{
		"5":                             "5",
		"5.0":                           "5.0", // a float in the source stays a float
		"1e0":                           "1.0",
		"1E5":                           "100000.0",
		"100e-2":                        "1.0",
		"-0":                            "0", // int("-0") is 0
		"-0.0":                          "-0.0",
		"1e-400":                        "0.0", // underflow, as Python's float()
		"12345678901234567890123456789": "12345678901234567890123456789",
		"-12345678901234567890":         "-12345678901234567890",
		"[1,2.0,3e0]":                   "[1,2.0,3.0]",
	}
	for src, want := range cases {
		if got := canon(t, src); got != want {
			t.Errorf("canonical(%s) = %s, want %s", src, got, want)
		}
	}
}

func TestStringEscapingMatchesEnsureASCII(t *testing.T) {
	cases := map[string]string{
		`""`:                                   `""`,
		`"a/b"`:                                `"a/b"`, // solidus is not escaped
		`"\/"`:                                 `"/"`,   // and an escaped one is unescaped
		`"<>&"`:                                `"<>&"`, // Go would escape these; Python does not
		`"\u0000\u001f"`:                       `"\u0000\u001f"`,
		"\"\x7f\"":                             `"\u007f"`, // DEL is outside the printable range
		`"\n\r\t\b\f"`:                         `"\n\r\t\b\f"`,
		`"\u000b"`:                             `"\u000b"`,    // vertical tab has no short escape
		"\"\\u00C9\"":                          "\"\\u00c9\"", // lowercase hex
		"\"é\"":                                "\"\\u00e9\"", // raw non-ASCII becomes an escape
		"\"\U0001F600\"":                       "\"\\ud83d\\ude00\"",
		"\"\\uD83D\\uDE00\"":                   "\"\\ud83d\\ude00\"",
		"\"\U0010FFFF\"":                       "\"\\udbff\\udfff\"",
		`"\ud800"`:                             `"\ud800"`, // lone surrogates survive
		`"\udc00"`:                             `"\udc00"`,
		`"\ud800A"`:                            `"\ud800A"`,
		`"\udfff\ud800"`:                       `"\udfff\ud800"`,
		`"\ud800\ud800"`:                       `"\ud800\ud800"`,
		"\"\\ud83d\\ude00\\udc00\"":            "\"\\ud83d\\ude00\\udc00\"",
		`"say \"hi\" \\ done"`:                 `"say \"hi\" \\ done"`,
		"\"\xe2\x80\xa8\xe2\x80\xa9\xc2\xa0\"": "\"\\u2028\\u2029\\u00a0\"",
	}
	for src, want := range cases {
		if got := canon(t, src); got != want {
			t.Errorf("canonical(%s) = %s, want %s", src, got, want)
		}
	}
}

func TestObjectKeysSortByCodePoint(t *testing.T) {
	cases := map[string]string{
		`{"b":1,"a":2}`:                                `{"a":2,"b":1}`,
		`{"ab":1,"a":2,"abc":3,"b":4}`:                 `{"a":2,"ab":1,"abc":3,"b":4}`,
		`{"a":1,"B":2,"A":3,"b":4}`:                    `{"A":3,"B":2,"a":1,"b":4}`,
		`{"x":1,"":2}`:                                 `{"":2,"x":1}`,
		"{\"\\u00e9\":1,\"z\":2,\"\\ud83d\\ude00\":3}": "{\"z\":2,\"\\u00e9\":1,\"\\ud83d\\ude00\":3}",
		"{\"\\ud800\":1,\"\\ue000\":2,\"\\uffff\":3,\"\\ud83d\\ude00\":4}": "{\"\\ud800\":1,\"\\ue000\":2,\"\\uffff\":3,\"\\ud83d\\ude00\":4}",
		`{"a":1,"a":2}`:                       `{"a":2}`,
		`  { "b" : 1 , "a" : [ 1 , 2 ] }  `:   `{"a":[1,2],"b":1}`,
		`{}`:                                  `{}`,
		`[]`:                                  `[]`,
		`[[],{},[{}],[[[]]],null,true,false]`: `[[],{},[{}],[[[]]],null,true,false]`,
	}
	for src, want := range cases {
		if got := canon(t, src); got != want {
			t.Errorf("canonical(%s) = %s, want %s", src, got, want)
		}
	}
}

func TestNonFiniteFloatsAreRefused(t *testing.T) {
	for src, want := range map[string]string{
		"NaN":           "nan",
		"Infinity":      "inf",
		"-Infinity":     "-inf",
		"1e400":         "inf",
		"-1e999":        "-inf",
		`{"a":[1,NaN]}`: "nan",
	} {
		v := mustParse(t, src)
		_, err := Marshal(v)
		if err == nil {
			t.Fatalf("Marshal(%s) succeeded, want refusal", src)
		}
		wantMsg := "Out of range float values are not JSON compliant: " + want
		if err.Error() != wantMsg {
			t.Errorf("Marshal(%s) error = %q, want %q", src, err, wantMsg)
		}
	}
}

func TestParseErrorsMatchPython(t *testing.T) {
	cases := map[string]string{
		``:               "Expecting value: line 1 column 1 (char 0)",
		`{`:              "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
		`{"a":1,}`:       "Illegal trailing comma before end of object: line 1 column 7 (char 6)",
		`[1,]`:           "Illegal trailing comma before end of array: line 1 column 3 (char 2)",
		`42x`:            "Extra data: line 1 column 3 (char 2)",
		`01`:             "Extra data: line 1 column 2 (char 1)",
		`1.`:             "Extra data: line 1 column 2 (char 1)",
		`1e`:             "Extra data: line 1 column 2 (char 1)",
		`-`:              "Expecting value: line 1 column 1 (char 0)",
		`.5`:             "Expecting value: line 1 column 1 (char 0)",
		`+1`:             "Expecting value: line 1 column 1 (char 0)",
		`nul`:            "Expecting value: line 1 column 1 (char 0)",
		`{'a':1}`:        "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
		`{1:2}`:          "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
		`{"a" 1}`:        "Expecting ':' delimiter: line 1 column 6 (char 5)",
		`[1 2]`:          "Expecting ',' delimiter: line 1 column 4 (char 3)",
		`{"a":1 "b":2}`:  "Expecting ',' delimiter: line 1 column 8 (char 7)",
		"\"\x01\"":       "Invalid control character at: line 1 column 2 (char 1)",
		`"abc`:           "Unterminated string starting at: line 1 column 1 (char 0)",
		`"\x41"`:         "Invalid \\escape: line 1 column 2 (char 1)",
		`"\u12"`:         "Invalid \\uXXXX escape: line 1 column 3 (char 2)",
		"\xef\xbb\xbf{}": "Unexpected UTF-8 BOM (decode using utf-8-sig): line 1 column 1 (char 0)",
		`{}{}`:           "Extra data: line 1 column 3 (char 2)",
		`{"a":1}}`:       "Extra data: line 1 column 8 (char 7)",
		"\"éé\"x":        "Extra data: line 1 column 5 (char 4)", // positions count code points
		"[1,\n2,\n]":     "Illegal trailing comma before end of array: line 2 column 2 (char 5)",
	}
	for src, want := range cases {
		_, err := Parse(src)
		if err == nil {
			t.Errorf("Parse(%q) succeeded, want %q", src, want)
			continue
		}
		if err.Error() != want {
			t.Errorf("Parse(%q) error = %q, want %q", src, err, want)
		}
	}
}

func TestParseAcceptsWhatPythonAccepts(t *testing.T) {
	for _, src := range []string{
		`  {}  `, "\t[1]\n", `"\ud800"`, `-Infinity`, `NaN`, `Infinity`, `0`, `-0`, `1e5`, `1.5E-3`,
		`{"a":{"b":{"c":[[[]]]}}}`, "\"\x7f\"", "\"é\"",
	} {
		if _, err := Parse(src); err != nil {
			t.Errorf("Parse(%q): %v", src, err)
		}
	}
}

func TestIntegerDigitLimit(t *testing.T) {
	if _, err := Parse(strings.Repeat("9", MaxIntDigits)); err != nil {
		t.Fatalf("4300 digits should parse: %v", err)
	}
	_, err := Parse(strings.Repeat("9", MaxIntDigits+1))
	if err == nil || !strings.Contains(err.Error(), "Exceeds the limit (4300 digits)") {
		t.Fatalf("4301 digits: got %v", err)
	}
	if _, err := Parse("-" + strings.Repeat("9", MaxIntDigits)); err != nil {
		t.Fatalf("sign does not count as a digit: %v", err)
	}
}

func TestNestingLimit(t *testing.T) {
	deep := strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth)
	if _, err := Parse(deep); err != nil {
		t.Fatalf("depth %d should parse: %v", MaxDepth, err)
	}
	deeper := strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1)
	_, err := Parse(deeper)
	if err == nil || !strings.Contains(err.Error(), "maximum recursion depth exceeded") {
		t.Fatalf("depth %d: got %v", MaxDepth+1, err)
	}
}

func TestStripIsPythonStrStrip(t *testing.T) {
	cases := map[string]string{
		"  a  ":                     "a",
		"\r\n a \r\n":               "a",
		"\xc2\xa0a\xc2\xa0":         "a",             // U+00A0 no-break space
		"\xe3\x80\x80a\xe2\x80\xa8": "a",             // U+3000 and U+2028
		"\x1ca\x1f":                 "a",             // the information separators are whitespace to Python
		"\xef\xbb\xbfa":             "\xef\xbb\xbfa", // the BOM (U+FEFF) is not
		"\xe2\x80\x8ba":             "\xe2\x80\x8ba", // nor is U+200B, the zero width space
		"":                          "",
		"   ":                       "",
	}
	for in, want := range cases {
		if got := Strip(in); got != want {
			t.Errorf("Strip(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEqualFollowsPythonSemantics(t *testing.T) {
	eq := func(a, b string) bool { return Equal(mustParse(t, a), mustParse(t, b)) }
	for _, pair := range [][2]string{{"1", "1.0"}, {"true", "1"}, {"false", "0"}, {"[1,2]", "[1.0,2.0]"},
		{`{"a":1}`, `{"a":1.0}`}, {"null", "null"}, {`"x"`, `"x"`}, {"12345678901234567890", "12345678901234567890"}} {
		if !eq(pair[0], pair[1]) {
			t.Errorf("Equal(%s, %s) = false, want true", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{{"1", `"1"`}, {"NaN", "NaN"}, {"[1]", "[1,1]"}, {`{"a":1}`, `{"b":1}`},
		{"null", "0"}, {"true", "2"}, {"9007199254740993", "9007199254740992.0"}} {
		if eq(pair[0], pair[1]) {
			t.Errorf("Equal(%s, %s) = true, want false", pair[0], pair[1])
		}
	}
}

func TestPyReprAndStr(t *testing.T) {
	cases := map[string]string{
		"null":     "None",
		"true":     "True",
		"1":        "1",
		"-0":       "0",
		"8.0":      "8.0",
		`"8"`:      "'8'",
		`"a'b"`:    `"a'b"`,
		`"a\"b"`:   `'a"b'`,
		`"a'b\"c"`: `'a\'b"c'`,
		"\"\\u0000\\u007f\\u00e9\\u2028\\ud83d\\ude00\\ud800\\n\\t\\\\\"": "'\\x00\\x7f\xc3\xa9\\u2028\xf0\x9f\x98\x80\\ud800\\n\\t\\\\'",
		`[1, 2.0, null, true, "x", {"k": "v"}]`:                           "[1, 2.0, None, True, 'x', {'k': 'v'}]",
		`{"b":1,"a":2,"b":3}`:                                             "{'b': 3, 'a': 2}",
	}
	for src, want := range cases {
		if got := PyRepr(mustParse(t, src)); got != want {
			t.Errorf("PyRepr(%s) = %s, want %s", src, got, want)
		}
	}
	if got := PyStr(mustParse(t, `"8"`)); got != "8" {
		t.Errorf("PyStr of a string should be bare, got %q", got)
	}
	if got := PyStr(nil); got != "None" {
		t.Errorf("PyStr(nil) = %q", got)
	}
}

func TestWithoutDropsKeys(t *testing.T) {
	v := mustParse(t, `{"hash":"x","a":1,"signature":"s","pubkey_path":"p"}`)
	got, _ := Marshal(v.Without("hash"))
	if string(got) != `{"a":1,"pubkey_path":"p","signature":"s"}` {
		t.Errorf("Without(hash) = %s", got)
	}
	got, _ = Marshal(v.Without("signature", "pubkey_path"))
	if string(got) != `{"a":1,"hash":"x"}` {
		t.Errorf("Without(signature, pubkey_path) = %s", got)
	}
	if v.Has("signature") != true || v.Get("missing").Kind != Null {
		t.Error("Has/Get on the original changed")
	}
}
