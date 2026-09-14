// Package pinsourceinfile resolves an HSM slot's PIN from a file in a statically configured directory.
package pinsourceinfile

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
)

// maxPinBytes bounds a single read. A user PIN is a handful of characters, so anything near this is a
// misconfigured source, and it is read on every signature.
const maxPinBytes = 1024

var _ hsmconnector.PinResolver = new(Resolver)

// Resolve reads the PIN named by source from the configured directory.
//
// Symlinks are followed on purpose: a Kubernetes secret projection mounts each key as a symlink into a
// timestamped directory. The guard is that source is a single name, so it cannot address anything
// outside the directory.
func (r *Resolver) Resolve(_ context.Context, source string) (string, error) {
	if len(r.directory) == 0 {
		msg := "no pin source directory is configured, set 'hsmmodules.softhsm.pinSourceDirectory'"
		return "", errors.PreconditionFailed().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
	}
	if err := hsmconnector.ValidatePinSource(source); err != nil {
		return "", err
	}

	// The wrapped error keeps the path for the log; only the human-readable message reaches the caller.
	file, err := os.Open(filepath.Join(r.directory, source))
	if err != nil {
		return "", errors.PreconditionFailedFromErr(err).
			WithMessage("could not read pin source '%s'", source).
			SetHumanReadableMessage("could not read pin source '%s'", source)
	}
	defer func() { _ = file.Close() }()

	// One byte past the cap distinguishes "exactly at the cap" from "over it".
	content, err := io.ReadAll(io.LimitReader(file, maxPinBytes+1))
	if err != nil {
		return "", errors.PreconditionFailedFromErr(err).
			WithMessage("could not read pin source '%s'", source).
			SetHumanReadableMessage("could not read pin source '%s'", source)
	}
	if len(content) > maxPinBytes {
		return "", errors.PreconditionFailed().
			WithMessage("pin source '%s' is larger than %d bytes, which is not a PIN", source, maxPinBytes).
			SetHumanReadableMessage("pin source '%s' is larger than %d bytes, which is not a PIN", source, maxPinBytes)
	}

	pin := trimOneLineEnding(string(content))
	if len(pin) == 0 {
		return "", errors.PreconditionFailed().
			WithMessage("pin source '%s' is empty", source).
			SetHumanReadableMessage("pin source '%s' is empty", source)
	}
	return pin, nil
}

// trimOneLineEnding removes a single trailing newline and nothing else. `echo pin > file` leaves one,
// and the HSM then refuses the PIN in a way that looks like a wrong secret. Trimming all whitespace
// would be wrong the other way: a PIN may end in a space.
func trimOneLineEnding(content string) string {
	trimmed := strings.TrimSuffix(content, "\n")
	return strings.TrimSuffix(trimmed, "\r")
}

// Resolver reads slot PINs from files in a single directory.
type Resolver struct {
	directory string
}

// ResolverOptions configures a Resolver.
type ResolverOptions struct {
	// Directory holds one file per PIN, each named by the source a slot records. Optional: a deployment
	// with no PKCS#11 slot has nothing to resolve, so an absent directory is reported on use rather than
	// at startup.
	Directory string
}

// NewResolver creates a Resolver with the given options, returning an error if it fails. A configured
// directory must exist at startup, so a typo fails the process rather than every signature.
func NewResolver(options ResolverOptions) (*Resolver, error) {
	if len(options.Directory) > 0 {
		if _, err := os.Stat(options.Directory); err != nil {
			return nil, errors.InvalidArgumentFromErr(err).WithMessage("pin source directory '%s' cannot be read", options.Directory)
		}
	}
	return &Resolver{
		directory: options.Directory,
	}, nil
}
