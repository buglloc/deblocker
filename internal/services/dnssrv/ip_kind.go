package dnssrv

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

var _ yaml.Unmarshaler = (*IPKind)(nil)
var _ yaml.Marshaler = (*IPKind)(nil)
var _ json.Unmarshaler = (*IPKind)(nil)
var _ json.Marshaler = (*IPKind)(nil)

type IPKind uint8

const (
	IPKindNone IPKind = iota
	IPKindV4
	IPKindV6
)

func (k IPKind) String() string {
	switch k {
	case IPKindNone:
		return "none"
	case IPKindV4:
		return "ipv4"
	case IPKindV6:
		return "ipv6"
	default:
		return fmt.Sprintf("unknown_%d", uint8(k))
	}
}

func (k *IPKind) fromString(s string) error {
	switch s {
	case "":
		*k = IPKindNone
	case "ipv4":
		*k = IPKindV4
	case "ipv6":
		*k = IPKindV6
	default:
		return fmt.Errorf("unknown IP kind: %s", s)
	}
	return nil
}

func (k IPKind) MarshalYAML() (interface{}, error) {
	return k.String(), nil
}

func (k *IPKind) UnmarshalYAML(val *yaml.Node) error {
	var s string
	if err := val.Decode(&s); err != nil {
		return err
	}

	return k.fromString(s)
}

func (k IPKind) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

func (k *IPKind) UnmarshalJSON(in []byte) error {
	var s string
	if err := json.Unmarshal(in, &s); err != nil {
		return err
	}

	return k.fromString(s)
}

func (k *IPKind) UnmarshalText(in []byte) error {
	return k.fromString(string(in))
}
