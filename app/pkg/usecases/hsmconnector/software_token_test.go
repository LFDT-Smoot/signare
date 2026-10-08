package hsmconnector_test

import (
	"errors"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/test/signaturemanagertesthelper"
)

func TestSoftwareTokenWarning(t *testing.T) {
	require.Contains(t, hsmconnector.SoftwareTokenWarning(pkcs11.Info{ManufacturerID: "SoftHSM                         "}, "/lib/softhsm.so"), "a software token")
	require.Empty(t, hsmconnector.SoftwareTokenWarning(pkcs11.Info{ManufacturerID: "Safenet, Inc."}, "/lib/vendor.so"))
	require.Empty(t, hsmconnector.SoftwareTokenWarning(pkcs11.Info{}, "/lib/vendor.so"))
}

// TestSoftHSMReportsItselfAsSoftHSM ties the warning to what the library actually returns, so a change in
// SoftHSM's manufacturer string turns this red rather than silencing the warning.
func TestSoftHSMReportsItselfAsSoftHSM(t *testing.T) {
	p := pkcs11.New(signaturemanagertesthelper.SoftHSMLib)
	require.NotNil(t, p)
	if err := p.Initialize(); err != nil {
		var pkcsErr pkcs11.Error
		require.True(t, errors.As(err, &pkcsErr) && pkcsErr == pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED, err)
	}
	info, err := p.GetInfo()
	require.NoError(t, err)
	require.NotEmpty(t, hsmconnector.SoftwareTokenWarning(info, signaturemanagertesthelper.SoftHSMLib))
}
