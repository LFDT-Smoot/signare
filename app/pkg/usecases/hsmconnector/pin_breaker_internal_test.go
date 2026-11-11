package hsmconnector

import (
	"sync"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/commons/metricrecorder"

	"github.com/stretchr/testify/require"
)

// recordingGauge captures the last value set per label set, so the breaker's reporting can be asserted
// without a metrics backend.
type recordingGauge struct {
	mu     sync.Mutex
	values map[string]float64
}

func newRecordingGauge() *recordingGauge {
	return &recordingGauge{values: make(map[string]float64)}
}

func (g *recordingGauge) Set(labels map[string]string, value float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.values[labels["moduleKind"]+"/"+labels["slot"]] = value
}

func (g *recordingGauge) value(key string) (float64, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	v, ok := g.values[key]
	return v, ok
}

func (g *recordingGauge) Inc(map[string]string)                                    {}
func (g *recordingGauge) Dec(map[string]string)                                    {}
func (g *recordingGauge) Add(map[string]string, float64)                           {}
func (g *recordingGauge) Sub(map[string]string, float64)                           {}
func (g *recordingGauge) GetGaugeVectorAdapter() metricrecorder.GaugeVectorAdapter { return nil }

func TestPinBreaker(t *testing.T) {
	key := pinBreakerKey{moduleKind: SoftHSMModuleKind, slot: "0"}
	const gaugeKey = "SoftHSM/0"

	t.Run("a fresh breaker blocks nothing", func(t *testing.T) {
		breaker := newPinBreaker(nil)
		require.False(t, breaker.blocked(key, "userpin"))
	})

	t.Run("opens against the refused value only", func(t *testing.T) {
		breaker := newPinBreaker(nil)
		breaker.trip(key, "wrong")

		require.True(t, breaker.blocked(key, "wrong"), "the refused PIN must not be retried")
		require.False(t, breaker.blocked(key, "userpin"), "a corrected secret must be retried")
		require.False(t, breaker.blocked(pinBreakerKey{moduleKind: SoftHSMModuleKind, slot: "1"}, "wrong"),
			"the breaker must be scoped to one token")
	})

	t.Run("a later failure replaces the recorded value", func(t *testing.T) {
		breaker := newPinBreaker(nil)
		breaker.trip(key, "wrong")
		breaker.trip(key, "still-wrong")

		require.True(t, breaker.blocked(key, "still-wrong"))
		require.False(t, breaker.blocked(key, "wrong"), "only the most recent refusal is held")
	})

	t.Run("clear closes it", func(t *testing.T) {
		breaker := newPinBreaker(nil)
		breaker.trip(key, "wrong")
		breaker.clear(key)

		require.False(t, breaker.blocked(key, "wrong"))
	})

	t.Run("reports the open state", func(t *testing.T) {
		gauge := newRecordingGauge()
		breaker := newPinBreaker(gauge)

		_, reported := gauge.value(gaugeKey)
		require.False(t, reported, "nothing is reported before a slot has ever failed")

		breaker.trip(key, "wrong")
		value, reported := gauge.value(gaugeKey)
		require.True(t, reported)
		require.Equal(t, float64(1), value)

		breaker.clear(key)
		value, reported = gauge.value(gaugeKey)
		require.True(t, reported)
		require.Equal(t, float64(0), value)
	})

	t.Run("clearing a closed breaker does not report", func(t *testing.T) {
		gauge := newRecordingGauge()
		breaker := newPinBreaker(gauge)

		breaker.clear(key)
		_, reported := gauge.value(gaugeKey)
		require.False(t, reported, "a successful login on a slot that never failed must not emit a series")
	})

	// Login happens per operation and concurrent requests share one connector, so the breaker is
	// exercised from several goroutines at once.
	t.Run("concurrent trips leave it open", func(t *testing.T) {
		breaker := newPinBreaker(newRecordingGauge())
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				breaker.trip(key, "wrong")
				breaker.blocked(key, "wrong")
			}()
		}
		wg.Wait()

		require.True(t, breaker.blocked(key, "wrong"), "concurrent failures must still leave the slot blocked")
		require.False(t, breaker.blocked(key, "corrected"))
	})

	// The breaker bounds retries, not a simultaneous burst: pinFor checks blocked and the matching trip
	// only happens once the login returns, so requests already in flight when the first failure lands
	// all reach the HSM. Closing that needs admission control around the attempt itself, which is a
	// separate change; this pins the current bound rather than asserting a guarantee that does not hold.
	t.Run("a burst that starts before the first failure is not bounded", func(t *testing.T) {
		breaker := newPinBreaker(newRecordingGauge())

		admitted := 0
		for i := 0; i < 10; i++ {
			if !breaker.blocked(key, "wrong") {
				admitted++
			}
		}
		require.Equal(t, 10, admitted, "nothing is recorded until an attempt returns")

		breaker.trip(key, "wrong")
		require.True(t, breaker.blocked(key, "wrong"), "every later attempt is refused")
	})
}

func TestRecordLoginOutcome_IgnoresAnUnguardedSlot(t *testing.T) {
	useCase := &DefaultUseCase{breaker: newPinBreaker(nil)}

	// An AKV or Local Key Vault slot never logs in with a PIN, so there is nothing to open or close.
	require.NotPanics(t, func() {
		useCase.recordLoginOutcome(nil, nil)
		useCase.recordLoginOutcome(&slotPin{}, nil)
	})
}
