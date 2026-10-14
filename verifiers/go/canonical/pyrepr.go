package canonical

import (
	"fmt"
	"strings"
	"unicode"
)

// PyStr renders a value the way Python's str() renders the object json.loads
// would have produced: None, True, 1.0, a bare string, [1, 'a'], {'k': v}.
// Aileron's error messages interpolate journal values with f-strings, and the
// Go verifier prints the same messages, so it needs the same rendering.
func PyStr(v *Value) string {
	if v != nil && v.Kind == String {
		return v.Str
	}
	return PyRepr(v)
}

// PyRepr renders a value as Python's repr() would.
func PyRepr(v *Value) string {
	if v == nil {
		return "None"
	}
	switch v.Kind {
	case Null:
		return "None"
	case Bool:
		if v.Bool {
			return "True"
		}
		return "False"
	case Int:
		if v.Text == "-0" {
			return "0"
		}
		return v.Text
	case Float:
		return FormatFloat(v.Float)
	case String:
		return pyStrRepr(v.Str)
	case Array:
		parts := make([]string, len(v.Array))
		for i, item := range v.Array {
			parts[i] = PyRepr(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case Object:
		parts := make([]string, len(v.Keys))
		for i, k := range v.Keys {
			parts[i] = pyStrRepr(k) + ": " + PyRepr(v.Object[k])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return "?"
}

// pyStrRepr is repr() for a str: single quotes unless the text contains a
// single quote and no double quote; backslash, the chosen quote, \n, \r and
// \t escaped; other non-printable code points as \xNN, \uNNNN or \UNNNNNNNN.
// "Printable" follows Python's str.isprintable() as closely as Go's Unicode
// tables allow; the two may disagree on recently assigned code points.
func pyStrRepr(s string) string {
	quote := byte('\'')
	if strings.Contains(s, "'") && !strings.Contains(s, "\"") {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for i := 0; i < len(s); {
		cp, size := decodeGeneralizedUTF8(s[i:])
		i += size
		switch {
		case cp == int(quote), cp == '\\':
			b.WriteByte('\\')
			b.WriteByte(byte(cp))
		case cp == '\n':
			b.WriteString(`\n`)
		case cp == '\r':
			b.WriteString(`\r`)
		case cp == '\t':
			b.WriteString(`\t`)
		case cp < 0x20 || cp == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, cp)
		case cp < 0x7f:
			b.WriteByte(byte(cp))
		case cp >= 0xd800 && cp <= 0xdfff:
			fmt.Fprintf(&b, `\u%04x`, cp)
		case unicode.IsPrint(rune(cp)):
			b.WriteString(string(rune(cp)))
		case cp < 0x100:
			fmt.Fprintf(&b, `\x%02x`, cp)
		case cp < 0x10000:
			fmt.Fprintf(&b, `\u%04x`, cp)
		default:
			fmt.Fprintf(&b, `\U%08x`, cp)
		}
	}
	b.WriteByte(quote)
	return b.String()
}
