package rpcinfra

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

// TestRejectAmbiguousParams_PassesOverOtherShapes keeps the check out of the way of methods whose
// params are not a single object, including the methods that take none at all.
func TestRejectAmbiguousParams_PassesOverOtherShapes(t *testing.T) {
	for _, params := range []string{`[]`, `null`, ``, `[{"a":1},{"b":2}]`, `["x"]`, `{}`} {
		require.NoErrorf(t, rejectAmbiguousParams(json.RawMessage(params)),
			"params %q must be left to the per-method decoding", params)
	}
}

// foldCorpus mixes the ASCII spellings that occur in practice with the Unicode runes whose fold orbit
// reaches ASCII. The latter are the cases a hand-rolled lower-casing gets wrong: strings.ToLower maps
// the Kelvin sign onto "k" but leaves the long s alone, so it would miss the s/long-s collision that
// encoding/json makes.
func foldCorpus() []string {
	return []string{
		"from", "From", "FROM", "fRoM", "FrOm",
		"address", "Address", "ADDRESS", "aDdReSs",
		"nonce", "NONCE", "Nonce",
		"maxFeePerGas", "MaxFeePerGas", "MAXFEEPERGAS",
		"k", "K", "K", // ASCII k, ASCII K, KELVIN SIGN
		"s", "S", "ſ", // ASCII s, ASCII S, LATIN SMALL LETTER LONG S
		"ß", "ẞ", // sharp s, capital sharp s
		"i", "I", "ı", // ASCII i, ASCII I, DOTLESS I
		"σ", "ς", "Σ", // sigma, final sigma, capital sigma
		"_", "0", "from_", "_from", "fro", "fromm",
		"а", // CYRILLIC SMALL A, a homoglyph of ASCII a that must not fold onto it
	}
}

// TestFoldName_MatchesEncodingJSONFieldMatching is the property the whole guard rests on, checked
// against the only oracle that counts: encoding/json itself.
//
// For every ordered pair in the corpus, an object naming both keys is decoded into a struct built at
// runtime with one field tagged with the first key. If the second key's value lands in that field,
// encoding/json has resolved both names onto one field, which is exactly the collision the guard has
// to reject. foldName must agree with that verdict in both directions, so the guard neither misses a
// collision nor rejects a pair encoding/json keeps apart.
func TestFoldName_MatchesEncodingJSONFieldMatching(t *testing.T) {
	corpus := foldCorpus()
	checked := 0

	for _, first := range corpus {
		for _, second := range corpus {
			if first == second {
				continue
			}
			object := fmt.Sprintf(`{%s:%q,%s:%q}`, jsonQuote(first), "first", jsonQuote(second), "second")

			collides := encodingJSONCollides(t, object, first)
			folded := foldName(first) == foldName(second)

			require.Equalf(t, collides, folded,
				"foldName disagrees with encoding/json for %q vs %q: json collision=%v, foldName equal=%v",
				first, second, collides, folded)

			// The guard's verdict must follow the same rule.
			err := rejectAmbiguousFieldNames(json.RawMessage(object))
			require.Equalf(t, collides, err != nil,
				"guard disagrees with encoding/json for %q vs %q", first, second)

			checked++
		}
	}

	require.Greater(t, checked, 900, "corpus should exercise a meaningful number of pairs")
}

// encodingJSONCollides reports whether encoding/json resolved both keys of object onto the single
// struct field tagged with tag, which shows as the second key's value landing in that field.
func encodingJSONCollides(t *testing.T, object, tag string) bool {
	t.Helper()

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(object), &raw))
	require.Lenf(t, raw, 2, "both keys must survive the decode for the comparison to mean anything: %s", object)

	structType := reflect.StructOf([]reflect.StructField{{
		Name: "Field",
		Type: reflect.TypeOf(""),
		Tag:  reflect.StructTag(fmt.Sprintf("json:%s", jsonQuote(tag))),
	}})
	decoded := reflect.New(structType)
	require.NoError(t, json.Unmarshal([]byte(object), decoded.Interface()))

	got := decoded.Elem().Field(0).String()
	require.Containsf(t, []string{"first", "second"}, got,
		"the tagged field should have matched one of the two keys, tag %q object %s", tag, object)
	return got == "second"
}

func jsonQuote(s string) string {
	quoted, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(quoted)
}

// TestRejectAmbiguousFieldNames_IsLinearInKeyCount pins the cost of the scan rather than its output.
// Key names are caller-supplied and bounded only by the request body limit, and the scan runs inside
// the authorization middleware before the account decision, so a pairwise comparison would let one
// request burn many seconds of CPU. A pairwise version of this check took about 15 seconds on this
// payload; the linear one takes tens of milliseconds, so the bound below is loose enough for a slow
// or loaded machine and still fails decisively if the scan goes quadratic again.
func TestRejectAmbiguousFieldNames_IsLinearInKeyCount(t *testing.T) {
	const bodyLimit = 1 << 20 // defaultMaxRequestBodyBytes in deployment/cmd/signare/config

	var builder strings.Builder
	builder.WriteString(`[{`)
	keys := 0
	for builder.Len() < bodyLimit-64 {
		if keys > 0 {
			builder.WriteString(",")
		}
		fmt.Fprintf(&builder, `"k%d":1`, keys)
		keys++
	}
	builder.WriteString(`}]`)
	require.Greater(t, keys, 50000, "payload should hold enough keys for a quadratic scan to show")

	start := time.Now()
	require.NoError(t, rejectAmbiguousParams(json.RawMessage(builder.String())))
	elapsed := time.Since(start)

	require.Lessf(t, elapsed, 2*time.Second,
		"scanning %d keys took %v, which means the check is no longer linear", keys, elapsed)
}

func TestTruncateFieldName(t *testing.T) {
	require.Equal(t, "from", truncateFieldName("from"))
	require.Equal(t, "", truncateFieldName(""))

	exact := strings.Repeat("a", maxReportedFieldNameRunes)
	require.Equal(t, exact, truncateFieldName(exact))

	truncated := truncateFieldName(strings.Repeat("a", 5000))
	require.Equal(t, strings.Repeat("a", maxReportedFieldNameRunes)+"...", truncated)

	// Truncation lands on a rune boundary rather than splitting a multi-byte rune.
	require.True(t, utf8.ValidString(truncateFieldName(strings.Repeat("é", 5000))))
}

// TestRejectAmbiguousFieldNames_ErrorIsBoundedAndQuoted checks that an oversized key name carrying
// control characters cannot forge a log line or flood one. The error text reaches the server log:
// AuthorizeAccount wraps it with StatusInvalidArgument, which keeps it out of the response body.
func TestRejectAmbiguousFieldNames_ErrorIsBoundedAndQuoted(t *testing.T) {
	hostile := strings.Repeat("a", 4000) + "\n\rinjected"
	object := fmt.Sprintf(`{%s:1,%s:2}`, jsonQuote(hostile), jsonQuote(strings.ToUpper(hostile)))

	err := rejectAmbiguousFieldNames(json.RawMessage(object))
	require.Error(t, err)
	require.NotContains(t, err.Error(), "\n", "a raw newline would let a key name forge a log line")
	require.NotContains(t, err.Error(), "\r")
	require.Less(t, len(err.Error()), 300, "error text must not carry the whole key name")
}
