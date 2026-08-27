package hsmslot_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmslot"

	"github.com/stretchr/testify/require"
)

const (
	secretPin        = "s3cr3t-slot-pin"
	secretPrivateKey = "4c0883a69102937d6231471b5dbb6204fe512961708279f2e3e8a5d4b8e3e3ab"
)

func slotWithSecrets() hsmslot.HSMSlot {
	return hsmslot.HSMSlot{
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
	}
}

// handlers returns the two stock slog handlers the service actually configures.
func handlers() map[string]func(*bytes.Buffer) slog.Handler {
	return map[string]func(*bytes.Buffer) slog.Handler{
		"json": func(b *bytes.Buffer) slog.Handler {
			return slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})
		},
		// The text handler is the one that would otherwise render the key store verbatim.
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

// TestHSMSlot_LogValueRedactsCredentials is the regression guard for a credential leak: the
// remove-account path passed the whole slot entity to the tracer, so the PIN that unlocks the signing
// keys was written to the log at debug level.
//
// The guard is on the type rather than on that one call site, because a tracer property or a wrapped
// error anywhere can put the struct in front of a handler.
func TestHSMSlot_LogValueRedactsCredentials(t *testing.T) {
	for name, handler := range handlers() {
		t.Run(name, func(t *testing.T) {
			output := logged(t, handler, "slot", slotWithSecrets())

			require.NotContains(t, output, secretPin, "the slot PIN must never reach a log record")
			require.NotContains(t, output, secretPrivateKey, "Local Key Vault key material must never reach a log record")

			// The identifying fields must survive, otherwise the redaction destroys the diagnostic value.
			require.Contains(t, output, "slot-1")
			require.Contains(t, output, "app-1")
			require.Contains(t, output, "module-1")
		})
	}
}

// A pointer to the slot must redact too. slog resolves LogValuer on a *T when the method has a value
// receiver, but pinning it stops a future change to a pointer receiver from silently reopening this.
func TestHSMSlot_LogValueRedactsThroughPointer(t *testing.T) {
	slot := slotWithSecrets()
	output := logged(t, func(b *bytes.Buffer) slog.Handler {
		return slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})
	}, "slot", &slot)

	require.NotContains(t, output, secretPin)
	require.NotContains(t, output, secretPrivateKey)
}

// SlotConfig can be logged on its own, so it carries its own guard. Both handlers, because a
// populated key store behaves differently under each.
func TestSlotConfig_LogValueRedactsKeyStore(t *testing.T) {
	for name, handler := range handlers() {
		t.Run(name, func(t *testing.T) {
			output := logged(t, handler, "config", slotWithSecrets().Config)

			require.NotContains(t, output, secretPrivateKey)
			require.Contains(t, output, "localKeyVaultEntries")
		})
	}
}

// The redaction is on the attribute value, not on values nested inside one. slog resolves LogValuer
// on what is passed to the handler and not on slice elements or struct fields, so a slot reached
// through a container is marshalled raw and its PIN is exposed.
//
// This test records that boundary rather than asserting the desired behaviour: it is why the guidance
// is to log a slot directly, and why HSMConnection carries its own LogValue. If a future Go release
// resolves LogValuer through containers this test will fail, which is the moment to relax the rule.
func TestHSMSlot_LogValueDoesNotExtendIntoContainers(t *testing.T) {
	type enclosing struct{ Slot hsmslot.HSMSlot }

	// A slot with no Local Key Vault, so the JSON handler can marshal it rather than failing on the
	// unsupported key-store map type, which would mask the leak.
	slot := slotWithSecrets()
	slot.Config = hsmslot.SlotConfig{}

	jsonHandler := func(b *bytes.Buffer) slog.Handler {
		return slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})
	}

	require.NotContains(t, logged(t, jsonHandler, "slot", slot), secretPin,
		"the direct form must stay redacted")
	require.Contains(t, logged(t, jsonHandler, "slots", []hsmslot.HSMSlot{slot}), secretPin,
		"known limitation: a slot inside a slice is marshalled raw")
	require.Contains(t, logged(t, jsonHandler, "wrapper", enclosing{Slot: slot}), secretPin,
		"known limitation: a slot inside a struct is marshalled raw")
}

// A slot with no Local Key Vault configuration must not panic on a nil pointer.
func TestSlotConfig_LogValueHandlesAbsentLocalKeyVault(t *testing.T) {
	require.NotPanics(t, func() {
		output := logged(t, func(b *bytes.Buffer) slog.Handler {
			return slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})
		}, "config", hsmslot.SlotConfig{})
		require.Contains(t, output, "localKeyVaultEntries")
	})
}
