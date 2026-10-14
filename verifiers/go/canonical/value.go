// Package canonical reproduces, byte for byte, the JSON serialization that
// Aileron hashes and signs:
//
//	json.dumps(obj, sort_keys=True, separators=(",", ":"),
//	           ensure_ascii=True, allow_nan=False)
//
// It deliberately does not use encoding/json for output. Go's encoder escapes
// <, > and &, formats floats differently, and cannot tell a JSON 5.0 from a 5
// once decoded. Hashes depend on every one of those bytes, so this package
// keeps its own value model and writes the bytes itself.
//
// The parser is also hand written, for a narrower reason: Go's decoder turns
// an unpaired surrogate escape such as "\ud800" into U+FFFD, while Python's
// json module keeps the lone surrogate and writes it back out as "\ud800".
// A journal line carrying one verifies in Python and must verify here too.
package canonical

import (
	"math/big"
	"strings"
)

// Kind is the JSON type of a Value.
type Kind uint8

const (
	// Null is the JSON literal null.
	Null Kind = iota
	// Bool is true or false.
	Bool
	// Int is a number literal with no fraction and no exponent. Python parses
	// it as an arbitrary precision int; the literal text is kept in Text.
	Int
	// Float is a number literal with a fraction or exponent, or one of the
	// non-standard literals NaN, Infinity and -Infinity that Python accepts.
	Float
	// String is a JSON string. Str holds it in generalized UTF-8, in which an
	// unpaired surrogate is encoded as its own three byte sequence.
	String
	// Array is a JSON array.
	Array
	// Object is a JSON object. Keys records insertion order (with duplicates
	// collapsed to their first position, last value), as a Python dict does.
	Object
)

// Value is one parsed JSON value. Fields not relevant to Kind are zero.
type Value struct {
	Kind   Kind
	Bool   bool
	Text   string // Int: the literal as written, for example "-0" or "12345678901234567890"
	Float  float64
	Str    string // String: generalized UTF-8 (see Kind String)
	Array  []*Value
	Keys   []string          // Object: keys in first insertion order
	Object map[string]*Value // Object: key to value
}

// BigInt returns the integer value of an Int. It panics on other kinds.
func (v *Value) BigInt() *big.Int {
	if v.Kind != Int {
		panic("canonical: BigInt on a non-integer value")
	}
	n, ok := new(big.Int).SetString(v.Text, 10)
	if !ok {
		panic("canonical: malformed integer literal " + v.Text)
	}
	return n
}

// Get returns the member named key of an Object, or a Null value when the key
// is absent (the way Python's dict.get returns None). It panics on other kinds.
func (v *Value) Get(key string) *Value {
	if v.Kind != Object {
		panic("canonical: Get on a non-object value")
	}
	if m, ok := v.Object[key]; ok {
		return m
	}
	return &Value{Kind: Null}
}

// Has reports whether an Object has the key.
func (v *Value) Has(key string) bool {
	_, ok := v.Object[key]
	return ok
}

// Without returns a shallow copy of an Object with the named keys removed.
// This is how the hash input (event minus "hash") and the signed checkpoint
// payload (checkpoint minus "signature" and "pubkey_path") are formed.
func (v *Value) Without(keys ...string) *Value {
	out := &Value{Kind: Object, Object: make(map[string]*Value, len(v.Object))}
	for _, k := range v.Keys {
		drop := false
		for _, d := range keys {
			if k == d {
				drop = true
				break
			}
		}
		if drop {
			continue
		}
		out.Keys = append(out.Keys, k)
		out.Object[k] = v.Object[k]
	}
	return out
}

// IsPyInt reports whether Python would say isinstance(value, int). That is
// true for JSON integers and, because bool subclasses int in Python, for true
// and false as well. Aileron's verifier uses isinstance(seq, int) in a few
// places, so the Go port has to draw the same line.
func (v *Value) IsPyInt() bool {
	return v.Kind == Int || v.Kind == Bool
}

// PyIntValue returns the Python int value of an Int or Bool (true is 1).
func (v *Value) PyIntValue() *big.Int {
	switch v.Kind {
	case Int:
		return v.BigInt()
	case Bool:
		if v.Bool {
			return big.NewInt(1)
		}
		return big.NewInt(0)
	}
	panic("canonical: PyIntValue on a non-integer value")
}

// NewString builds a String value from ordinary UTF-8 text.
func NewString(s string) *Value { return &Value{Kind: String, Str: s} }

// NewInt builds an Int value from a decimal literal.
func NewInt(n *big.Int) *Value { return &Value{Kind: Int, Text: n.String()} }

// EqualsPyInt reports whether Python would say value == n, where n is an int.
// Python compares numbers across types exactly: 3 == 3.0 and True == 1 are
// both true, and no non-number equals an int.
func (v *Value) EqualsPyInt(n *big.Int) bool {
	switch v.Kind {
	case Int, Bool:
		return v.PyIntValue().Cmp(n) == 0
	case Float:
		return floatEqualsBig(v.Float, n)
	}
	return false
}

// Equal reports whether Python would say a == b for the two parsed values.
// Numbers compare by value across int, float and bool; containers compare
// element by element; everything else must match in kind and content.
func Equal(a, b *Value) bool {
	if a == nil {
		a = &Value{Kind: Null}
	}
	if b == nil {
		b = &Value{Kind: Null}
	}
	if isNumber(a) && isNumber(b) {
		return numbersEqual(a, b)
	}
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case Null:
		return true
	case String:
		return a.Str == b.Str
	case Array:
		if len(a.Array) != len(b.Array) {
			return false
		}
		for i := range a.Array {
			if !Equal(a.Array[i], b.Array[i]) {
				return false
			}
		}
		return true
	case Object:
		if len(a.Object) != len(b.Object) {
			return false
		}
		for k, av := range a.Object {
			bv, ok := b.Object[k]
			if !ok || !Equal(av, bv) {
				return false
			}
		}
		return true
	}
	return false
}

func isNumber(v *Value) bool {
	return v.Kind == Int || v.Kind == Float || v.Kind == Bool
}

func numbersEqual(a, b *Value) bool {
	if a.Kind == Float && b.Kind == Float {
		return a.Float == b.Float // NaN != NaN, as in Python
	}
	if a.Kind == Float {
		return floatEqualsBig(a.Float, b.PyIntValue())
	}
	if b.Kind == Float {
		return floatEqualsBig(b.Float, a.PyIntValue())
	}
	return a.PyIntValue().Cmp(b.PyIntValue()) == 0
}

// floatEqualsBig compares a float64 with an arbitrary precision integer
// exactly, which is what Python does for float == int.
func floatEqualsBig(f float64, n *big.Int) bool {
	if f != f || f > 1.7976931348623157e308 || f < -1.7976931348623157e308 {
		return false // NaN or infinite
	}
	return new(big.Float).SetInt(n).Cmp(big.NewFloat(f)) == 0
}

// Strip removes leading and trailing whitespace the way Python's str.strip()
// does with no argument: every code point for which str.isspace() is true,
// not just ASCII whitespace. Aileron strips each journal line before parsing
// it, so a verifier that stripped less would reject lines Python accepts.
func Strip(s string) string {
	return strings.TrimFunc(s, isPySpace)
}

// isPySpace is Python's str.isspace() for a single code point: bidirectional
// class WS, B or S, or general category Zs. The list is the set of code
// points for which chr(c).isspace() is true, taken from CPython 3.13.
func isPySpace(r rune) bool {
	switch {
	case r >= 0x09 && r <= 0x0d, r >= 0x1c && r <= 0x20:
		return true
	case r == 0x85, r == 0xa0, r == 0x1680:
		return true
	case r >= 0x2000 && r <= 0x200a:
		return true
	case r == 0x2028, r == 0x2029, r == 0x202f, r == 0x205f, r == 0x3000:
		return true
	}
	return false
}
