package akv

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"golang.org/x/sync/singleflight"

	"github.com/lfdt-smoot/signare/app/pkg/commons/logger"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
)

const (
	hsmKeyType   = string(azkeys.KeyTypeECHSM)
	signingCurve = string(azkeys.CurveNameP256K)
	// currentHSMPlatform is the hsmPlatform value Azure reports for a key on its FIPS 140-3 Level 3
	// validated HSM platform. 1 is the earlier FIPS 140-2 platform and 0 a software module.
	currentHSMPlatform = "2"
	// readErrorTTL is how long a failed key read is remembered under hardwareOnly, so an outage or a
	// missing keys/get permission costs one vault call per key version per interval, not one per request.
	readErrorTTL = 5 * time.Second
	// keyReadTimeout bounds a key read, which runs detached from the request that started it. It stays
	// below the server's 15-second write timeout, so a read cannot outlive the response it is for.
	keyReadTimeout = 10 * time.Second
)

// keyDescription is what the policy needs to know about a vault key. A field is empty when the
// vault did not report it.
type keyDescription struct {
	keyType     string
	curve       string
	hsmPlatform string
}

// keyReader fetches a key's public description from the vault. It needs the keys/get permission.
type keyReader interface {
	describeKey(ctx context.Context, name string, version string) (keyDescription, error)
}

// vaultClient is the part of azkeys.Client Signare uses. A fake stands in for it in tests.
type vaultClient interface {
	Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
	GetKey(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
}

type azkeysReader struct {
	client vaultClient
}

func (r azkeysReader) describeKey(ctx context.Context, name string, version string) (keyDescription, error) {
	resp, err := r.client.GetKey(ctx, name, version, nil)
	if err != nil {
		return keyDescription{}, err
	}
	var d keyDescription
	if resp.Key != nil {
		if resp.Key.Kty != nil {
			d.keyType = string(*resp.Key.Kty)
		}
		if resp.Key.Crv != nil {
			d.curve = string(*resp.Key.Crv)
		}
	}
	if resp.Attributes != nil && resp.Attributes.HSMPlatform != nil {
		d.hsmPlatform = *resp.Attributes.HSMPlatform
	}
	return d, nil
}

// keyProtectionProblems lists what keeps a key from being an HSM-held secp256k1 key on the current
// platform. An unreported hsmPlatform is not a problem: Azure documents the attribute as optional for
// vault keys and not at all for Managed HSM, where every key is HSM-protected.
func keyProtectionProblems(d keyDescription) []string {
	var problems []string
	switch d.keyType {
	case hsmKeyType:
	case "":
		problems = append(problems, "the vault did not report the key type")
	default:
		problems = append(problems, fmt.Sprintf("key type is %q, not %q, so the private key is software-protected", d.keyType, hsmKeyType))
	}
	switch d.curve {
	case signingCurve:
	case "":
		problems = append(problems, "the vault did not report the curve")
	default:
		problems = append(problems, fmt.Sprintf("curve is %q, not %q", d.curve, signingCurve))
	}
	if d.hsmPlatform != "" && d.hsmPlatform != currentHSMPlatform {
		problems = append(problems, fmt.Sprintf("hsmPlatform is %q, not %q, the FIPS 140-3 Level 3 platform", d.hsmPlatform, currentHSMPlatform))
	}
	return problems
}

// keyProtection checks each key version once per process, since its type, curve and platform cannot
// change. With hardwareOnly set, a key that fails the check is refused, and a key that cannot be read
// fails as unavailable for readErrorTTL before it is read again. Otherwise the finding is logged once and
// signing proceeds, so a deployment without the keys/get permission or with a software key for
// development keeps working as before. Concurrent first checks of one key version share a single read.
type keyProtection struct {
	reader       keyReader
	hardwareOnly bool
	now          func() time.Time
	flight       singleflight.Group

	mu       sync.Mutex
	verdicts map[string]verdict
}

// verdict is a cached outcome. A zero expires means it never expires.
type verdict struct {
	err     error
	expires time.Time
}

func newKeyProtection(reader keyReader, hardwareOnly bool) *keyProtection {
	return &keyProtection{
		reader:       reader,
		hardwareOnly: hardwareOnly,
		now:          time.Now,
		verdicts:     make(map[string]verdict),
	}
}

func (p *keyProtection) check(ctx context.Context, tracer logger.Tracer, name string, version string) error {
	// NUL cannot occur in a key name or version, so two different pairs never share an id.
	id := name + "\x00" + version
	if found, err := p.cached(id); found {
		return err
	}
	result, _, _ := p.flight.Do(id, func() (any, error) {
		if found, err := p.cached(id); found {
			return err, nil
		}
		return p.evaluate(ctx, tracer, name, version, id), nil
	})
	err, _ := result.(error)
	return err
}

func (p *keyProtection) evaluate(ctx context.Context, tracer logger.Tracer, name string, version string, id string) error {
	// Detached from the caller's cancellation: the result is shared with every request waiting on it.
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), keyReadTimeout)
	defer cancel()
	d, err := p.reader.describeKey(readCtx, name, version)
	if err != nil {
		if p.hardwareOnly {
			msg := fmt.Sprintf("cannot verify that key '%s' version '%s' is HSM-held: %v", name, version, err)
			tracer.Warn(msg)
			unavailable := signaturemanager.NewUnavailableError().WithMessage(msg)
			p.record(id, verdict{err: unavailable, expires: p.now().Add(readErrorTTL)})
			return unavailable
		}
		tracer.Warn(fmt.Sprintf("could not read key '%s' version '%s' to check whether it is HSM-held, which needs the keys/get permission: %v", name, version, err))
		p.record(id, verdict{})
		return nil
	}

	problems := keyProtectionProblems(d)
	if len(problems) == 0 {
		p.record(id, verdict{})
		return nil
	}
	if p.hardwareOnly {
		msg := fmt.Sprintf("key '%s' version '%s' refused, this deployment accepts HSM-held keys only: %s", name, version, strings.Join(problems, "; "))
		tracer.Warn(msg)
		refusal := signaturemanager.NewPolicyRefusedError().WithMessage(msg)
		p.record(id, verdict{err: refusal})
		return refusal
	}
	tracer.Warn(fmt.Sprintf("key '%s' version '%s' is not an HSM-held secp256k1 key on the current platform: %s", name, version, strings.Join(problems, "; ")))
	p.record(id, verdict{})
	return nil
}

// cached reports whether id has a recorded verdict that has not expired, and returns it.
func (p *keyProtection) cached(id string) (found bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.verdicts[id]
	if !ok || (!v.expires.IsZero() && !p.now().Before(v.expires)) {
		return false, nil
	}
	return true, v.err
}

func (p *keyProtection) record(id string, v verdict) {
	p.mu.Lock()
	p.verdicts[id] = v
	p.mu.Unlock()
}
