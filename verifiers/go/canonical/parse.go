package canonical

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxDepth is the nesting depth beyond which Parse refuses a document. CPython
// raises RecursionError somewhere past a few thousand levels (the exact point
// depends on the interpreter version and how deep the stack already is), and
// its encoder has the same limit, so no journal Python wrote can be deeper
// than that. The bound here exists so hostile input cannot exhaust the stack.
const MaxDepth = 10000

// MaxIntDigits mirrors CPython's default sys.int_max_str_digits: an integer
// literal with more digits than this fails to parse there, so it fails here.
const MaxIntDigits = 4300

// SyntaxError is a parse failure, with the message and position Python's
// json module would report for the same input.
type SyntaxError struct {
	Msg string
	Pos int // offset in code points, as Python counts
	Doc string
}

func (e *SyntaxError) Error() string {
	lineno := strings.Count(e.Doc[:e.bytePos()], "\n") + 1
	last := strings.LastIndex(e.Doc[:e.bytePos()], "\n")
	var colno int
	if last < 0 {
		colno = e.Pos + 1
	} else {
		colno = e.Pos - utf8.RuneCountInString(e.Doc[:last])
	}
	return fmt.Sprintf("%s: line %d column %d (char %d)", e.Msg, lineno, colno, e.Pos)
}

// bytePos converts the code point offset back into a byte offset.
func (e *SyntaxError) bytePos() int {
	n := 0
	for i := range e.Doc {
		if n == e.Pos {
			return i
		}
		n++
	}
	return len(e.Doc)
}

// ValueError is a parse failure that CPython reports as a plain ValueError
// rather than a JSONDecodeError: an integer literal over the digit limit, or
// nesting deeper than the recursion limit.
type ValueError struct{ Msg string }

func (e *ValueError) Error() string { return e.Msg }

type parser struct {
	s     string
	i     int
	depth int
}

// Parse decodes one JSON document with the acceptance rules of Python's
// json.loads: standard JSON plus the literals NaN, Infinity and -Infinity,
// strict about control characters inside strings, last value wins for a
// duplicated key. The input must be valid UTF-8; a journal line is checked
// for that before it reaches here, exactly as Python decodes the bytes first.
func Parse(doc string) (*Value, error) {
	if !utf8.ValidString(doc) {
		return nil, &ValueError{Msg: "input is not valid UTF-8"}
	}
	p := &parser{s: doc}
	if strings.HasPrefix(doc, "\xef\xbb\xbf") { // U+FEFF, the UTF-8 byte order mark
		return nil, p.errAt("Unexpected UTF-8 BOM (decode using utf-8-sig)", 0)
	}
	p.skipWS()
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.i != len(p.s) {
		return nil, p.errAt("Extra data", p.i)
	}
	return v, nil
}

func (p *parser) errAt(msg string, bytePos int) error {
	return &SyntaxError{Msg: msg, Pos: utf8.RuneCountInString(p.s[:bytePos]), Doc: p.s}
}

// skipWS skips the four whitespace characters JSON allows between tokens.
// Unicode whitespace is not among them; Python's json module agrees.
func (p *parser) skipWS() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value() (*Value, error) {
	if p.i >= len(p.s) {
		return nil, p.errAt("Expecting value", p.i)
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"':
		p.i++
		s, err := p.stringBody(p.i - 1)
		if err != nil {
			return nil, err
		}
		return &Value{Kind: String, Str: s}, nil
	case c == 'n' && p.lit("null"):
		return &Value{Kind: Null}, nil
	case c == 't' && p.lit("true"):
		return &Value{Kind: Bool, Bool: true}, nil
	case c == 'f' && p.lit("false"):
		return &Value{Kind: Bool, Bool: false}, nil
	case c == 'N' && p.lit("NaN"):
		return &Value{Kind: Float, Float: nan()}, nil
	case c == 'I' && p.lit("Infinity"):
		return &Value{Kind: Float, Float: inf(1)}, nil
	case c == '-' && p.lit("-Infinity"):
		return &Value{Kind: Float, Float: inf(-1)}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	return nil, p.errAt("Expecting value", p.i)
}

func (p *parser) lit(word string) bool {
	if strings.HasPrefix(p.s[p.i:], word) {
		p.i += len(word)
		return true
	}
	return false
}

func (p *parser) enter(what string) error {
	p.depth++
	if p.depth > MaxDepth {
		return &ValueError{Msg: "maximum recursion depth exceeded while decoding a JSON " + what}
	}
	return nil
}

func (p *parser) object() (*Value, error) {
	if err := p.enter("object"); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	p.i++ // '{'
	v := &Value{Kind: Object, Object: map[string]*Value{}}
	p.skipWS()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return v, nil
	}
	for {
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, p.errAt("Expecting property name enclosed in double quotes", p.i)
		}
		p.i++
		key, err := p.stringBody(p.i - 1)
		if err != nil {
			return nil, err
		}
		p.skipWS()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, p.errAt("Expecting ':' delimiter", p.i)
		}
		p.i++
		p.skipWS()
		member, err := p.value()
		if err != nil {
			return nil, err
		}
		if _, dup := v.Object[key]; !dup {
			v.Keys = append(v.Keys, key)
		}
		v.Object[key] = member // last value wins, as in dict(pairs)
		p.skipWS()
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
			return v, nil
		}
		if p.i >= len(p.s) || p.s[p.i] != ',' {
			return nil, p.errAt("Expecting ',' delimiter", p.i)
		}
		comma := p.i
		p.i++
		p.skipWS()
		if p.i < len(p.s) && p.s[p.i] == '}' {
			return nil, p.errAt("Illegal trailing comma before end of object", comma)
		}
	}
}

func (p *parser) array() (*Value, error) {
	if err := p.enter("array"); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	p.i++ // '['
	v := &Value{Kind: Array, Array: []*Value{}}
	p.skipWS()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return v, nil
	}
	for {
		item, err := p.value()
		if err != nil {
			return nil, err
		}
		v.Array = append(v.Array, item)
		p.skipWS()
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.i++
			return v, nil
		}
		if p.i >= len(p.s) || p.s[p.i] != ',' {
			return nil, p.errAt("Expecting ',' delimiter", p.i)
		}
		comma := p.i
		p.i++
		p.skipWS()
		if p.i < len(p.s) && p.s[p.i] == ']' {
			return nil, p.errAt("Illegal trailing comma before end of array", comma)
		}
	}
}

// number matches Python's NUMBER_RE: (-?(?:0|[1-9]\d*))(\.\d+)?([eE][-+]?\d+)?
// A literal with a fraction or exponent is a float; anything else is an int.
func (p *parser) number() (*Value, error) {
	start := p.i
	j := p.i
	if j < len(p.s) && p.s[j] == '-' {
		j++
	}
	if j >= len(p.s) || !isDigit(p.s[j]) {
		return nil, p.errAt("Expecting value", start)
	}
	if p.s[j] == '0' {
		j++
	} else {
		for j < len(p.s) && isDigit(p.s[j]) {
			j++
		}
	}
	isFloat := false
	if j+1 < len(p.s) && p.s[j] == '.' && isDigit(p.s[j+1]) {
		isFloat = true
		j++
		for j < len(p.s) && isDigit(p.s[j]) {
			j++
		}
	}
	if j < len(p.s) && (p.s[j] == 'e' || p.s[j] == 'E') {
		k := j + 1
		if k < len(p.s) && (p.s[k] == '+' || p.s[k] == '-') {
			k++
		}
		if k < len(p.s) && isDigit(p.s[k]) {
			isFloat = true
			for k < len(p.s) && isDigit(p.s[k]) {
				k++
			}
			j = k
		}
	}
	text := p.s[start:j]
	p.i = j
	if isFloat {
		f, err := strconv.ParseFloat(text, 64)
		if err != nil {
			// Only ErrRange is possible for a literal this grammar admits.
			// Overflow gives +/-Inf, which is what Python's float() returns;
			// underflow gives 0 or a subnormal with no error, also as Python.
			if ne, ok := err.(*strconv.NumError); !ok || ne.Err != strconv.ErrRange {
				return nil, &ValueError{Msg: "could not convert string to float: " + text}
			}
		}
		return &Value{Kind: Float, Float: f}, nil
	}
	digits := len(text)
	if text[0] == '-' {
		digits--
	}
	if digits > MaxIntDigits {
		return nil, &ValueError{Msg: fmt.Sprintf(
			"Exceeds the limit (%d digits) for integer string conversion: value has %d digits; "+
				"use sys.set_int_max_str_digits() to increase the limit", MaxIntDigits, digits)}
	}
	return &Value{Kind: Int, Text: text}, nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// stringBody parses from just after the opening quote (at byte offset open)
// to the closing quote and returns the content in generalized UTF-8.
func (p *parser) stringBody(open int) (string, error) {
	var b strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", p.errAt("Unterminated string starting at", open)
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c < 0x20:
			return "", p.errAt("Invalid control character at", p.i)
		case c != '\\':
			b.WriteByte(c) // raw bytes, already known to be valid UTF-8
			p.i++
		default:
			if p.i+1 >= len(p.s) {
				return "", p.errAt("Unterminated string starting at", open)
			}
			esc := p.s[p.i+1]
			switch esc {
			case '"', '\\', '/':
				b.WriteByte(esc)
				p.i += 2
			case 'b':
				b.WriteByte('\b')
				p.i += 2
			case 'f':
				b.WriteByte('\f')
				p.i += 2
			case 'n':
				b.WriteByte('\n')
				p.i += 2
			case 'r':
				b.WriteByte('\r')
				p.i += 2
			case 't':
				b.WriteByte('\t')
				p.i += 2
			case 'u':
				cp, ok := p.hex4(p.i + 2)
				if !ok {
					return "", p.errAt("Invalid \\uXXXX escape", p.i+1)
				}
				p.i += 6
				// A high surrogate followed by a \u low surrogate escape is
				// one code point. Any other surrogate stays as it is: Python
				// keeps lone surrogates in the str and re-escapes them later.
				if cp >= 0xd800 && cp <= 0xdbff && strings.HasPrefix(p.s[p.i:], "\\u") {
					if lo, ok := p.hex4(p.i + 2); ok && lo >= 0xdc00 && lo <= 0xdfff {
						cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00)
						p.i += 6
					}
				}
				writeGeneralizedUTF8(&b, cp)
			default:
				return "", p.errAt("Invalid \\escape", p.i)
			}
		}
	}
}

func (p *parser) hex4(at int) (int, bool) {
	if at+4 > len(p.s) {
		return 0, false
	}
	n := 0
	for k := at; k < at+4; k++ {
		c := p.s[k]
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		default:
			return 0, false
		}
		n = n*16 + d
	}
	return n, true
}

// writeGeneralizedUTF8 encodes any code point in 0..0x10FFFF, surrogates
// included, with the UTF-8 bit layout. Go's utf8 package refuses surrogates,
// which is right for text but wrong for a value model that must round trip
// what Python's str holds.
func writeGeneralizedUTF8(b *strings.Builder, cp int) {
	switch {
	case cp < 0x80:
		b.WriteByte(byte(cp))
	case cp < 0x800:
		b.WriteByte(byte(0xc0 | cp>>6))
		b.WriteByte(byte(0x80 | cp&0x3f))
	case cp < 0x10000:
		b.WriteByte(byte(0xe0 | cp>>12))
		b.WriteByte(byte(0x80 | (cp>>6)&0x3f))
		b.WriteByte(byte(0x80 | cp&0x3f))
	default:
		b.WriteByte(byte(0xf0 | cp>>18))
		b.WriteByte(byte(0x80 | (cp>>12)&0x3f))
		b.WriteByte(byte(0x80 | (cp>>6)&0x3f))
		b.WriteByte(byte(0x80 | cp&0x3f))
	}
}

// decodeGeneralizedUTF8 is the inverse of writeGeneralizedUTF8 for the first
// code point of s, returning the code point and its byte length. Input is
// trusted: it only ever comes from Parse or from a Go string that was valid
// UTF-8 to begin with.
func decodeGeneralizedUTF8(s string) (int, int) {
	c := s[0]
	switch {
	case c < 0x80:
		return int(c), 1
	case c < 0xe0 && len(s) >= 2:
		return int(c&0x1f)<<6 | int(s[1]&0x3f), 2
	case c < 0xf0 && len(s) >= 3:
		return int(c&0x0f)<<12 | int(s[1]&0x3f)<<6 | int(s[2]&0x3f), 3
	case len(s) >= 4:
		return int(c&0x07)<<18 | int(s[1]&0x3f)<<12 | int(s[2]&0x3f)<<6 | int(s[3]&0x3f), 4
	}
	return 0xfffd, 1 // malformed; cannot happen for Parse output
}
