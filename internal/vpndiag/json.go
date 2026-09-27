package vpndiag

import (
	"encoding/json"
	"strings"
)

// jsonUnmarshalStrict decodes one JSON value, rejecting trailing content. Log
// lines are read one per line, so anything after the object means the line was
// not what it claimed to be and is better skipped than half-read.
func jsonUnmarshalStrict(s string, v any) error {
	dec := json.NewDecoder(strings.NewReader(s))
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}
