package pkcs11hsm

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/miekg/pkcs11"
)

// pkcsErrTranslator holds one shared *signaturemanager.Error per PKCS#11 code, so the property that
// matters is that a translated error is never the shared instance itself. These guards sit on the
// translator rather than on WithMessage so they still hold if the copy moves elsewhere.

// Two requests hitting the same PKCS#11 code must not read each other's detail, which carries the
// slot the request was made against.
func TestToSignatureManagerErr_DoesNotLeakAcrossCalls(t *testing.T) {
	first := toSignatureManagerErr(pkcs11.Error(pkcs11.CKR_PIN_INCORRECT), "slot 1")
	second := toSignatureManagerErr(pkcs11.Error(pkcs11.CKR_PIN_INCORRECT), "slot 2")

	require.Contains(t, first.Error(), "slot 1")
	require.NotContains(t, first.Error(), "slot 2")
	require.Contains(t, second.Error(), "slot 2")
}

// Concurrent requests hitting the same PKCS#11 code must not race on the shared instance.
func TestToSignatureManagerErr_IsRaceFree(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			translated := toSignatureManagerErr(pkcs11.Error(pkcs11.CKR_PIN_INCORRECT), fmt.Sprintf("slot %d", i))
			require.NotNil(t, translated)
			_ = translated.Error()
		}()
	}
	wg.Wait()

	require.Equal(t, "the pin is incorrect", pkcsErrTranslator[pkcs11.CKR_PIN_INCORRECT].Error())
}
