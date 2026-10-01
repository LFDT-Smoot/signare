package hsmconnector

import (
	"crypto/sha256"
	"sync"

	"github.com/lfdt-smoot/signare/app/pkg/commons/metricrecorder"
)

// pinBreakerKey identifies the token a breaker guards. A PKCS#11 lockout counter belongs to the token,
// so two applications on the same slot share one breaker.
type pinBreakerKey struct {
	moduleKind ModuleKind
	slot       string
}

// pinBreaker stops a slot being retried with a PIN the HSM already refused. Login happens per
// operation, so without it one wrong secret fails every signature and the HSM locks the user PIN. It
// holds a digest of the refused value, never the value: a different digest means the secret was
// corrected.
//
// It bounds retries, not a simultaneous burst: the check and the trip are separated by the login
// itself, so requests already in flight when the first failure lands still reach the HSM. Bounding
// those needs admission control around the attempt.
type pinBreaker struct {
	mu     sync.Mutex
	failed map[pinBreakerKey][sha256.Size]byte
	gauge  metricrecorder.GaugeVector
}

func newPinBreaker(gauge metricrecorder.GaugeVector) *pinBreaker {
	return &pinBreaker{
		failed: make(map[pinBreakerKey][sha256.Size]byte),
		gauge:  gauge,
	}
}

// blocked reports whether this exact PIN has already been refused for this token.
func (b *pinBreaker) blocked(key pinBreakerKey, pin string) bool {
	digest := sha256.Sum256([]byte(pin))
	b.mu.Lock()
	defer b.mu.Unlock()
	recorded, open := b.failed[key]
	return open && recorded == digest
}

// trip opens the breaker for this token against the PIN that was just refused.
func (b *pinBreaker) trip(key pinBreakerKey, pin string) {
	digest := sha256.Sum256([]byte(pin))
	b.mu.Lock()
	b.failed[key] = digest
	b.mu.Unlock()
	b.setGauge(key, 1)
}

// clear closes the breaker for this token.
func (b *pinBreaker) clear(key pinBreakerKey) {
	b.mu.Lock()
	_, open := b.failed[key]
	delete(b.failed, key)
	b.mu.Unlock()
	if open {
		b.setGauge(key, 0)
	}
}

func (b *pinBreaker) setGauge(key pinBreakerKey, value float64) {
	if b.gauge == nil {
		return
	}
	b.gauge.Set(map[string]string{
		"slot":       key.slot,
		"moduleKind": string(key.moduleKind),
	}, value)
}
