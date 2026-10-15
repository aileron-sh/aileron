package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sort"
	"strconv"
	"strings"
)

// RangeError is returned when a value cannot be serialized because Python's
// allow_nan=False would refuse it: NaN, Infinity or -Infinity.
type RangeError struct{ Float float64 }

func (e *RangeError) Error() string {
	return "Out of range float values are not JSON compliant: " + FormatFloat(e.Float)
}

// Marshal writes the canonical JSON of v: keys sorted by code point, no
// whitespace, every non-ASCII character escaped, Python number formatting.
// It fails only for non-finite floats.
func Marshal(v *Value) ([]byte, error) {
	var b bytes.Buffer
	if err := write(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Digest returns the lowercase hex SHA-256 of the canonical JSON of v, which
// is what Aileron calls digest(obj).
func Digest(v *Value) (string, error) {
	c, err := Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

func write(b *bytes.Buffer, v *Value) error {
	switch v.Kind {
	case Null:
		b.WriteString("null")
	case Bool:
		if v.Bool {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case Int:
		// JSON forbids leading zeros, so the literal is already Python's
		// repr of the int, with one exception: int("-0") is 0.
		if v.Text == "-0" {
			b.WriteString("0")
		} else {
			b.WriteString(v.Text)
		}
	case Float:
		if math.IsNaN(v.Float) || math.IsInf(v.Float, 0) {
			return &RangeError{Float: v.Float}
		}
		b.WriteString(FormatFloat(v.Float))
	case String:
		writeString(b, v.Str)
	case Array:
		b.WriteByte('[')
		for i, item := range v.Array {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := write(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case Object:
		keys := make([]string, 0, len(v.Object))
		for k := range v.Object {
			keys = append(keys, k)
		}
		// Python sorts str keys by code point. Generalized UTF-8 byte order
		// is code point order, so a plain byte sort gives the same result,
		// surrogates included.
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := write(b, v.Object[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	}
	return nil
}

const hexDigits = "0123456789abcdef"

// writeString is Python's ensure_ascii=True string encoder. Only the ASCII
// range 0x20..0x7e is written as is, minus the quote and the backslash. The
// short escapes are exactly \" \\ \n \r \t \b \f; everything else, including
// DEL (0x7f) and every non-ASCII code point, becomes lowercase \uXXXX, with a
// UTF-16 surrogate pair above U+FFFF. The solidus is never escaped and neither
// are <, > and &.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		cp, size := decodeGeneralizedUTF8(s[i:])
		i += size
		switch {
		case cp == '"':
			b.WriteString(`\"`)
		case cp == '\\':
			b.WriteString(`\\`)
		case cp == '\n':
			b.WriteString(`\n`)
		case cp == '\r':
			b.WriteString(`\r`)
		case cp == '\t':
			b.WriteString(`\t`)
		case cp == '\b':
			b.WriteString(`\b`)
		case cp == '\f':
			b.WriteString(`\f`)
		case cp >= 0x20 && cp <= 0x7e:
			b.WriteByte(byte(cp))
		case cp < 0x10000:
			writeU(b, cp)
		default:
			cp -= 0x10000
			writeU(b, 0xd800|(cp>>10))
			writeU(b, 0xdc00|(cp&0x3ff))
		}
	}
	b.WriteByte('"')
}

func writeU(b *bytes.Buffer, cp int) {
	b.WriteString(`\u`)
	b.WriteByte(hexDigits[(cp>>12)&0xf])
	b.WriteByte(hexDigits[(cp>>8)&0xf])
	b.WriteByte(hexDigits[(cp>>4)&0xf])
	b.WriteByte(hexDigits[cp&0xf])
}

// FormatFloat is Python's repr(float): the shortest digit string that reads
// back to the same double, laid out as Python lays it out.
//
// Writing the value as d.ddd x 10^exp with a single leading digit, Python
// uses exponent notation when exp < -4 or exp >= 16, and positional notation
// otherwise. Positional output always carries a decimal point (5.0, not 5).
// Exponent output has a mantissa with a point only when there is more than
// one digit, an explicit sign, and at least two exponent digits: 1e-05,
// 1e+16, 1.5e+300. Zero is 0.0 or -0.0. NaN and infinities print as nan, inf
// and -inf, which Marshal refuses; FormatFloat spells them for messages.
func FormatFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	case f == 0:
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	// Go's shortest 'e' form is "d.ddde+XX" with the same conventions
	// Python uses for its exponent form, so in that branch it is the answer.
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expText, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expText)
	if exp < -4 || exp >= 16 {
		return e
	}
	neg := strings.HasPrefix(mant, "-")
	if neg {
		mant = mant[1:]
	}
	digits := strings.Replace(mant, ".", "", 1)
	var out strings.Builder
	if neg {
		out.WriteByte('-')
	}
	if exp < 0 {
		out.WriteString("0.")
		out.WriteString(strings.Repeat("0", -exp-1))
		out.WriteString(digits)
		return out.String()
	}
	intLen := exp + 1
	if len(digits) <= intLen {
		out.WriteString(digits)
		out.WriteString(strings.Repeat("0", intLen-len(digits)))
		out.WriteString(".0")
		return out.String()
	}
	out.WriteString(digits[:intLen])
	out.WriteByte('.')
	out.WriteString(digits[intLen:])
	return out.String()
}

func nan() float64         { return math.NaN() }
func inf(sign int) float64 { return math.Inf(sign) }
