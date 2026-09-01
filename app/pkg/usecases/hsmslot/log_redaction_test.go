package hsmslot_test

import (
	"bytes"
	"context"
	"fmt"
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

// jsonHandler is the handler the service configures outside local mode, and the one an unguarded
// struct leaks through: it marshals every exported field.
func jsonHandler(b *bytes.Buffer) slog.Handler {
	return slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})
}

// textHandler is the handler local mode configures. It renders an unguarded value through %+v, which
// is why a type carrying a key store by value, such as LocalKeyVaultConfig, leaks through it while the
// JSON handler fails to marshal the same value and hides the leak behind an !ERROR placeholder.
func textHandler(b *bytes.Buffer) slog.Handler {
	return slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})
}

// handlers returns the two stock slog handlers the service actually configures. Both are covered
// everywhere, because an unguarded value renders differently under each.
func handlers() map[string]func(*bytes.Buffer) slog.Handler {
	return map[string]func(*bytes.Buffer) slog.Handler{
		"json": jsonHandler,
		"text": textHandler,
	}
}

// renderedAttr returns how the named handler writes an integer attribute, so a count assertion checks
// the reported value and not just the presence of the key.
func renderedAttr(handlerName string, key string, value int) string {
	if handlerName == "json" {
		return fmt.Sprintf("%q:%d", key, value)
	}
	return fmt.Sprintf("%s=%d", key, value)
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
//
// The Contains assertions are what make this a guard. Without them, deleting every LogValue still
// passes: the JSON handler cannot marshal the key store's map[address.Address]string key type, so the
// record collapses to an !ERROR placeholder that contains no slot data and therefore no secret either.
func TestHSMSlot_LogValueRedactsThroughPointer(t *testing.T) {
	for name, handler := range handlers() {
		t.Run(name, func(t *testing.T) {
			slot := slotWithSecrets()
			output := logged(t, handler, "slot", &slot)

			require.NotContains(t, output, secretPin)
			require.NotContains(t, output, secretPrivateKey)

			require.Contains(t, output, "slot-1")
			require.Contains(t, output, "app-1")
			require.Contains(t, output, "module-1")
		})
	}
}

// SlotConfig can be logged on its own, so it carries its own guard. Both handlers, because a
// populated key store behaves differently under each.
func TestSlotConfig_LogValueRedactsKeyStore(t *testing.T) {
	for name, handler := range handlers() {
		t.Run(name, func(t *testing.T) {
			output := logged(t, handler, "config", slotWithSecrets().Config)

			require.NotContains(t, output, secretPrivateKey)
			// The count must be reported accurately, otherwise the redaction passes by emitting nothing.
			require.Contains(t, output, renderedAttr(name, "localKeyVaultEntries", 1))
			require.Contains(t, output, renderedAttr(name, "akvEntries", 0))
		})
	}
}

// LocalKeyVaultConfig carries the key store, and SlotConfig holds it as a pointer, so it needs a guard
// of its own: slog resolves LogValuer on the attribute value, not on a struct field. Without this the
// text handler renders the whole map, addresses and private keys, through %+v.
func TestLocalKeyVaultConfig_LogValueRedactsKeyStore(t *testing.T) {
	for name, handler := range handlers() {
		t.Run(name, func(t *testing.T) {
			config := *slotWithSecrets().Config.LocalKeyVault

			output := logged(t, handler, "localKeyVault", config)
			require.NotContains(t, output, secretPrivateKey, "key material must never reach a log record")
			require.Contains(t, output, renderedAttr(name, "entries", 1))

			pointerOutput := logged(t, handler, "localKeyVault", &config)
			require.NotContains(t, pointerOutput, secretPrivateKey)
			require.Contains(t, pointerOutput, renderedAttr(name, "entries", 1))
		})
	}
}

// A collection carries slots as slice elements, which slog does not resolve, so it needs a guard of
// its own. ListHSMSlotsByApplicationOutput and ListHSMSlotsByHSMModuleOutput embed it and inherit it.
func TestHSMSlotCollection_LogValueRedactsItems(t *testing.T) {
	for name, handler := range handlers() {
		t.Run(name, func(t *testing.T) {
			collection := hsmslot.HSMSlotCollection{
				Items:                  []hsmslot.HSMSlot{slotWithSecrets()},
				StandardCollectionPage: entities.StandardCollectionPage{Limit: 10, Offset: 0, MoreItems: false},
			}

			output := logged(t, handler, "slots", collection)
			require.NotContains(t, output, secretPin, "no slot in the page may expose its PIN")
			require.NotContains(t, output, secretPrivateKey)
			require.Contains(t, output, renderedAttr(name, "items", 1))
			require.Contains(t, output, renderedAttr(name, "limit", 10))

			embedded := hsmslot.ListHSMSlotsByApplicationOutput{HSMSlotCollection: collection}
			require.NotContains(t, logged(t, handler, "output", embedded), secretPin,
				"the embedding output type inherits the guard")
		})
	}
}

// The redaction is on the attribute value, not on values nested inside one. slog resolves LogValuer on
// what is passed to the handler and not on slice elements, so a bare slice of slots is marshalled raw
// and every PIN in it is exposed.
//
// This test records that boundary rather than asserting the desired behaviour. It is inherent to how a
// KindAny value is handed to a handler and marshalled, not a Go version detail, so the remedy is not to
// wait for it to change: log a slot directly, and give any type that carries slots its own LogValue, as
// HSMConnection and HSMSlotCollection do. Every named carrier in the repository is guarded, so this is
// reachable only by constructing an unnamed container at the call site.
func TestHSMSlot_LogValueDoesNotExtendIntoABareSlice(t *testing.T) {
	// A slot with no Local Key Vault, so the JSON handler can marshal it rather than failing on the
	// unsupported key-store map type, which would mask the leak.
	slot := slotWithSecrets()
	slot.Config = hsmslot.SlotConfig{}

	require.NotContains(t, logged(t, jsonHandler, "slot", slot), secretPin,
		"the direct form must stay redacted")
	require.Contains(t, logged(t, jsonHandler, "slots", []hsmslot.HSMSlot{slot}), secretPin,
		"known limitation: a slot inside a bare slice is marshalled raw")

	// The named carrier for the same shape is guarded, which is the supported way to log slots.
	require.NotContains(t, logged(t, jsonHandler, "slots",
		hsmslot.HSMSlotCollection{Items: []hsmslot.HSMSlot{slot}}), secretPin,
		"HSMSlotCollection must not inherit the bare-slice limitation")
}

// A slot with no Local Key Vault configuration must not panic on a nil pointer, and must report the
// count as zero rather than omitting it.
func TestSlotConfig_LogValueHandlesAbsentLocalKeyVault(t *testing.T) {
	for name, handler := range handlers() {
		t.Run(name, func(t *testing.T) {
			require.NotPanics(t, func() {
				output := logged(t, handler, "config", hsmslot.SlotConfig{})
				require.Contains(t, output, renderedAttr(name, "localKeyVaultEntries", 0))
			})
		})
	}
}
