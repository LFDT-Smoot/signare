package pkcs11hsm

import (
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

func TestCheckPrivateKeyProtection(t *testing.T) {
	attr := func(typ uint, value bool) *pkcs11.Attribute {
		return pkcs11.NewAttribute(typ, value)
	}
	cases := []struct {
		name       string
		attributes []*pkcs11.Attribute
		problem    string
	}{
		{"sensitive and not extractable", []*pkcs11.Attribute{attr(pkcs11.CKA_SENSITIVE, true), attr(pkcs11.CKA_EXTRACTABLE, false)}, ""},
		{"order does not matter", []*pkcs11.Attribute{attr(pkcs11.CKA_EXTRACTABLE, false), attr(pkcs11.CKA_SENSITIVE, true)}, ""},
		{"not sensitive", []*pkcs11.Attribute{attr(pkcs11.CKA_SENSITIVE, false), attr(pkcs11.CKA_EXTRACTABLE, false)}, "CKA_SENSITIVE false"},
		{"extractable", []*pkcs11.Attribute{attr(pkcs11.CKA_SENSITIVE, true), attr(pkcs11.CKA_EXTRACTABLE, true)}, "CKA_EXTRACTABLE true"},
		{"sensitive not reported", []*pkcs11.Attribute{attr(pkcs11.CKA_EXTRACTABLE, false)}, "did not report CKA_SENSITIVE"},
		{"extractable not reported", []*pkcs11.Attribute{attr(pkcs11.CKA_SENSITIVE, true)}, "did not report CKA_EXTRACTABLE"},
		{"empty value counts as not reported", []*pkcs11.Attribute{{Type: pkcs11.CKA_SENSITIVE}, attr(pkcs11.CKA_EXTRACTABLE, false)}, "did not report CKA_SENSITIVE"},
		{"nil entries are skipped", []*pkcs11.Attribute{nil, attr(pkcs11.CKA_SENSITIVE, true), attr(pkcs11.CKA_EXTRACTABLE, false)}, ""},
		{"nothing", nil, "did not report CKA_SENSITIVE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			problem := checkPrivateKeyProtection(c.attributes)
			if c.problem == "" {
				require.Empty(t, problem)
				return
			}
			require.Contains(t, problem, c.problem)
		})
	}
}
