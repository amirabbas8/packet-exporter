package config

import "gopkg.in/yaml.v3"

func unmarshal(data []byte, out any) error {
	return yaml.Unmarshal(data, out)
}
