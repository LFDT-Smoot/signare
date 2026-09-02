package hsmconnection_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnection"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmslot"

	"github.com/stretchr/testify/require"
)

const (
	secretPin        = "s3cr3t-slot-pin"
	secretPrivateKey = "4c0883a69102937d6231471b5dbb6204fe512961708279f2e3e8a5d4b8e3e3ab"
)

func connectionWithSecrets() hsmconnection.HSMConnection {
	return hsmconnection.HSMConnection{
		Slot: hsmslot.HSMSlot{
			StandardResourceMeta: entities.StandardResourceMeta{
				StandardResource: entities.StandardResource{
					StandardID: entities.StandardID{ID: "slot-1"},
				},
			},
			ApplicationID: "app-1",
			HSMModuleID:   "module-1",
			Slot:          "0",
			Pin:           secretPin,
			Config: hsmslot.SlotConfig{
				LocalKeyVault: &hsmslot.LocalKeyVaultConfig{
					KeyStore: map[address.Address]string{
						address.MustNewFromHexString("0x970e8128ab834e8eac17ab8e3812f010678cf791"): secretPrivateKey,
					},
				},
			},
		},
		ModuleKind:                hsmconnector.SoftHSMModuleKind,
		ApplicationDefaultChainID: *entities.NewInt256FromInt(5050),
	}
}

// handlers returns the two stock slog handlers the service actually configures.
func handlers() map[string]func(*bytes.Buffer) slog.Handler {
	return map[string]func(*bytes.Buffer) slog.Handler{
		"json": func(b *bytes.Buffer) slog.Handler {
			return slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})
		},
		"text": func(b *bytes.Buffer) slog.Handler {
			return slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})
		},
	}
}

// logged renders value through a real slog handler, which is what resolves slog.LogValuer.
func logged(t *testing.T, handler func(*bytes.Buffer) slog.Handler, key string, value any) string {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(handler(&buf))
	logger.LogAttrs(context.Background(), slog.LevelDebug, "message", slog.Any(key, value))
	return buf.String()
}

// HSMConnection holds an HSMSlot as a named field, and slog does not resolve LogValuer on a struct
// field, so it carries its own guard. That guard puts the slot back in through slog.Any inside a group
// value, which relies on handlers resolving group members recursively: this test pins that, since it is
// the pattern the HSMSlot doc comment points at as the one to copy.
func TestHSMConnection_LogValueRedactsSlotCredentials(t *testing.T) {
	for name, handler := range handlers() {
		t.Run(name, func(t *testing.T) {
			output := logged(t, handler, "connection", connectionWithSecrets())

			require.NotContains(t, output, secretPin, "the slot PIN must never reach a log record")
			require.NotContains(t, output, secretPrivateKey, "Local Key Vault key material must never reach a log record")

			// The identifying fields must survive, otherwise the redaction destroys the diagnostic value.
			require.Contains(t, output, "slot-1")
			require.Contains(t, output, "app-1")
			require.Contains(t, output, "module-1")
			require.Contains(t, output, string(hsmconnector.SoftHSMModuleKind))
			require.Contains(t, output, "5050")
		})
	}
}

// A pointer to the connection must redact too.
func TestHSMConnection_LogValueRedactsThroughPointer(t *testing.T) {
	for name, handler := range handlers() {
		t.Run(name, func(t *testing.T) {
			connection := connectionWithSecrets()
			output := logged(t, handler, "connection", &connection)

			require.NotContains(t, output, secretPin)
			require.NotContains(t, output, secretPrivateKey)
			require.Contains(t, output, "slot-1")
		})
	}
}

// A zero connection must not panic: the chain ID is rendered through big.Int.String, which is promoted
// from the embedded value and is safe on the zero value.
func TestHSMConnection_LogValueHandlesZeroValue(t *testing.T) {
	require.NotPanics(t, func() {
		for name, handler := range handlers() {
			require.NotEmpty(t, logged(t, handler, "connection", hsmconnection.HSMConnection{}), name)
		}
	})
}
