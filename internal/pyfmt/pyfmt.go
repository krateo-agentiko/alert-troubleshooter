// Package pyfmt reproduces the few Python semantics the alert provider's contracts depend on:
// truthiness, str() and json.dumps() of JSON values, str.strip(), datetime.isoformat() and
// code-point lengths. The RCA report, the comparison prompt and the HyperDX drift check were
// specified against Python's behaviour, and their outputs land in CR statuses and LLM prompts, so
// the port keeps them byte-for-byte. JSON values are decoded with json.Decoder.UseNumber, which
// keeps an integer apart from a float as Python's json module does.
package pyfmt

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Decode parses JSON as Python's json.loads would, numbers as json.Number.
func Decode(data []byte) (any, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("extra data after the JSON value")
	}
	return v, nil
}

// IsInt says a JSON number is an integer literal, which Python's json module decodes as int.
func IsInt(n json.Number) bool {
	s := string(n)
	return s != "" && !strings.ContainsAny(s, ".eE")
}

// Truthy is Python's bool() of a JSON value.
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case json.Number:
		f, err := x.Float64()
		return err != nil || f != 0
	case float64:
		return x != 0
	case int:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// Str is Python's str() of a JSON value.
func Str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil, bool, json.Number, float64, int, []any, map[string]any:
		return Repr(v)
	}
	return fmt.Sprint(v)
}

// Repr is Python's repr() of a JSON value. A dict's keys come in sorted order: Go's maps keep no
// insertion order. Only log lines show a dict this way.
func Repr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case json.Number:
		return NumberStr(x)
	case float64:
		return FloatRepr(x)
	case int:
		return strconv.Itoa(x)
	case string:
		return strRepr(x)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = Repr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		keys := sortedKeys(x)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = strRepr(k) + ": " + Repr(x[k])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return fmt.Sprint(v)
}

func strRepr(s string) string {
	quote := "'"
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		quote = `"`
	}
	var b strings.Builder
	b.WriteString(quote)
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case string(r) == quote:
			b.WriteString(`\` + quote)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteString(quote)
	return b.String()
}

// NumberStr is Python's str() of the int or float a JSON number decodes to.
func NumberStr(n json.Number) string {
	if IsInt(n) {
		s := strings.TrimPrefix(string(n), "-")
		neg := strings.HasPrefix(string(n), "-")
		s = strings.TrimLeft(s, "0")
		if s == "" {
			return "0"
		}
		if neg {
			return "-" + s
		}
		return s
	}
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil {
		return string(n)
	}
	return FloatRepr(f)
}

// FloatRepr is Python's repr() of a float: the shortest round-tripping digits, positional for
// exponents in [-4, 16), scientific otherwise.
func FloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX
	mant, expS, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expS)
	neg := strings.HasPrefix(mant, "-")
	digits := strings.Replace(strings.TrimPrefix(mant, "-"), ".", "", 1)
	sign := ""
	if neg {
		sign = "-"
	}
	if exp < -4 || exp >= 16 {
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		es := "+"
		if exp < 0 {
			es = "-"
			exp = -exp
		}
		return fmt.Sprintf("%s%se%s%02d", sign, m, es, exp)
	}
	if exp < 0 {
		return sign + "0." + strings.Repeat("0", -exp-1) + digits
	}
	if len(digits) <= exp+1 {
		return sign + digits + strings.Repeat("0", exp+1-len(digits)) + ".0"
	}
	return sign + digits[:exp+1] + "." + digits[exp+1:]
}

// Float is Python's float() of a JSON value; false where Python raises.
func Float(v any) (float64, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		return f, err == nil
	case float64:
		return x, true
	case int:
		return float64(x), true
	case string:
		s := Strip(x)
		if strings.ContainsAny(s, "xXpP_") {
			return 0, false // hex floats and digit separators: Go's syntax, not Python's
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil && !strings.Contains(err.Error(), "value out of range") {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// IsSpace is Python's str.isspace() of one character.
func IsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// Strip is Python's str.strip().
func Strip(s string) string {
	return strings.TrimFunc(s, IsSpace)
}

// Len is Python's len() of a str: its code points.
func Len(s string) int {
	return utf8.RuneCountInString(s)
}

// Cut is Python's s[:n] of a str.
func Cut(s string, n int) string {
	if n <= 0 {
		return ""
	}
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

// Upper1 is Python's s[:1].upper() + s[1:].
func Upper1(s string) string {
	r, size := utf8.DecodeRuneInString(s)
	if size == 0 {
		return s
	}
	return strings.ToUpper(string(r)) + s[size:]
}

// Isoformat is Python's datetime.isoformat() of an aware UTC datetime: microseconds, shown only
// when nonzero, and +00:00.
func Isoformat(t time.Time) string {
	t = t.UTC()
	if us := t.Nanosecond() / 1000; us != 0 {
		return t.Format("2006-01-02T15:04:05") + fmt.Sprintf(".%06d", us) + "+00:00"
	}
	return t.Format("2006-01-02T15:04:05") + "+00:00"
}

// ParseTime reads an ISO 8601 timestamp with an offset or Z, as Python's
// datetime.fromisoformat(value.replace("Z", "+00:00")) does; false for anything else.
func ParseTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999Z07", "2006-01-02 15:04:05.999999999Z07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// Dumps is Python's json.dumps() with its defaults: ", " and ": " separators, non-ASCII escaped.
// A dict's keys come in sorted order (Go maps keep none); only lengths and classifier text are
// taken from it.
func Dumps(v any) string {
	var b strings.Builder
	dumps(&b, v)
	return b.String()
}

func dumps(b *strings.Builder, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		if IsInt(x) {
			b.WriteString(NumberStr(x))
			return
		}
		f, err := strconv.ParseFloat(string(x), 64)
		switch {
		case err != nil && !strings.Contains(err.Error(), "value out of range"):
			b.WriteString(string(x))
		case math.IsInf(f, 1):
			b.WriteString("Infinity")
		case math.IsInf(f, -1):
			b.WriteString("-Infinity")
		default:
			b.WriteString(FloatRepr(f))
		}
	case float64:
		b.WriteString(FloatRepr(x))
	case int:
		b.WriteString(strconv.Itoa(x))
	case string:
		dumpString(b, x)
	case []any:
		b.WriteString("[")
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			dumps(b, e)
		}
		b.WriteString("]")
	case map[string]any:
		b.WriteString("{")
		for i, k := range sortedKeys(x) {
			if i > 0 {
				b.WriteString(", ")
			}
			dumpString(b, k)
			b.WriteString(": ")
			dumps(b, x[k])
		}
		b.WriteString("}")
	default:
		// json.dumps(default=str): anything else is its str().
		dumpString(b, fmt.Sprint(v))
	}
}

func dumpString(b *strings.Builder, s string) {
	b.WriteString(`"`)
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20 || (r >= 0x7f && r <= 0xffff):
				fmt.Fprintf(b, `\u%04x`, r)
			case r > 0xffff:
				r -= 0x10000
				fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteString(`"`)
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
