package auth

import (
	"encoding/json"
	"io"
	"io/ioutil"

	"github.com/pkg/errors"
)

// SimpleClaims lets us parse random JSON strings as a `map[string]interface{}`
// and have the resultant JSON satisfy the `jwt.Claims` interface
type SimpleClaims map[string]interface{}

// Valid lets SimpleClaims implement `jwt.Claims`
func (c SimpleClaims) Valid() error {
	return nil
}

// FromReader loads a SimpleClaims object from an `io.Reader`
func (c *SimpleClaims) FromReader(r io.Reader) error {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return errors.Wrap(err, "error reading from reader")
	}
	return c.FromBytes(b)
}

// FromBytes loads a SimpleClaims object from `[]byte`
func (c *SimpleClaims) FromBytes(b []byte) error {
	err := json.Unmarshal(b, c)
	return errors.Wrap(err, "error unmarshaling JSON bytes to SimpleClaims")
}
