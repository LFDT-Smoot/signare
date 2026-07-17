//nolint:revive
package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// ReadAndResetCloser reads the entire reader, unmarshals it into pointer, and resets the reader so it
// can be read again. The io.ReadAll is intentionally unbounded here: callers on the request path rely
// on the entrypoint http.MaxBytesReader (see httpinfra.MaxBytesMiddleware) to cap the body upstream.
// A caller reading an untrusted body without that wrapper must bound it themselves.
func ReadAndResetCloser(reader *io.ReadCloser, pointer any) error {
	body, err := io.ReadAll(*reader)
	if err != nil {
		return fmt.Errorf("error reading body [%w]", err)
	}

	var buf bytes.Buffer
	_, err = buf.Write(body)
	if err != nil {
		return fmt.Errorf("error writing body [%w]", err)
	}

	*reader = io.NopCloser(&buf)
	err = json.Unmarshal(body, pointer)
	if err != nil {
		return fmt.Errorf("error unmarshaling body [%w]", err)
	}

	return nil
}
