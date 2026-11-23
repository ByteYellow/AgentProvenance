package sensor

import (
	"fmt"

	"github.com/cilium/ebpf"
)

func setSensorVariable(spec *ebpf.CollectionSpec, name string, value any) error {
	v := spec.Variables[name]
	if v == nil {
		return fmt.Errorf("sensor object is missing variable %q", name)
	}
	return v.Set(value)
}
