package akv

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/lfdt-smoot/signare/app/pkg/commons/logger"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
)

const (
	hsmKeyType   = string(azkeys.KeyTypeECHSM)
	signingCurve = string(azkeys.CurveNameP256K)
	// currentHSMPlatform is the hsmPlatform value Azure reports for a key on its FIPS 140-3 Level 3
	// validated HSM platform. 1 is the earlier FIPS 140-2 platform and 0 a software module.
	currentHSMPlatform = "2"
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
// platform. An unreported hsmPlatform is not counted as a problem. Which keys the service returns without
// it is not established; the pinned client always requests api-version 7.5, whose model carries the field.
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
// change. With hardwareOnly set, a key that fails the check or cannot be read is refused. Otherwise
// the finding is logged once and signing proceeds, so a deployment without the keys/get permission
// or with a software key for development keeps working as before.
type keyProtection struct {
	reader       keyReader
	hardwareOnly bool

	mu       sync.Mutex
	verdicts map[string]error
}

func newKeyProtection(reader keyReader, hardwareOnly bool) *keyProtection {
	return &keyProtection{
		reader:       reader,
		hardwareOnly: hardwareOnly,
		verdicts:     make(map[string]error),
	}
}

func (p *keyProtection) check(ctx context.Context, tracer logger.Tracer, name string, version string) error {
	id := name + "/" + version
	p.mu.Lock()
	verdict, seen := p.verdicts[id]
	p.mu.Unlock()
	if seen {
		return verdict
	}

	d, err := p.reader.describeKey(ctx, name, version)
	if err != nil {
		if p.hardwareOnly {
			// Not recorded: a transient read error must not refuse the key for the rest of the process.
			msg := fmt.Sprintf("cannot verify that key '%s' version '%s' is HSM-held: %v", name, version, err)
			tracer.Warn(msg)
			return signaturemanager.NewPolicyRefusedError().WithMessage(msg)
		}
		tracer.Warn(fmt.Sprintf("could not read key '%s' version '%s' to check whether it is HSM-held, which needs the keys/get permission: %v", name, version, err))
		p.record(id, nil)
		return nil
	}

	problems := keyProtectionProblems(d)
	if len(problems) == 0 {
		p.record(id, nil)
		return nil
	}
	if p.hardwareOnly {
		msg := fmt.Sprintf("key '%s' version '%s' refused, this deployment accepts HSM-held keys only: %s", name, version, strings.Join(problems, "; "))
		tracer.Warn(msg)
		refusal := signaturemanager.NewPolicyRefusedError().WithMessage(msg)
		p.record(id, refusal)
		return refusal
	}
	tracer.Warn(fmt.Sprintf("key '%s' version '%s' is not an HSM-held secp256k1 key on the current platform: %s", name, version, strings.Join(problems, "; ")))
	p.record(id, nil)
	return nil
}

func (p *keyProtection) record(id string, verdict error) {
	p.mu.Lock()
	p.verdicts[id] = verdict
	p.mu.Unlock()
}
