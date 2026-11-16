package runtimeadapter

import "fmt"

// GuestIdentity is asserted by the root-owned platform launcher, after querying
// the control plane and CRI. Workload labels and guest self-identification are
// not accepted as sources for Pod/container/generation assignment.
type GuestIdentity struct {
	RuntimeClass   string `json:"runtime_class"`
	RuntimeHandler string `json:"runtime_handler"`
	PodUID         string `json:"pod_uid"`
	ContainerID    string `json:"container_id"`
	GuestBootID    string `json:"guest_boot_id"`
}

func (g GuestIdentity) Validate() error {
	for _, value := range []string{g.RuntimeClass, g.RuntimeHandler, g.PodUID, g.ContainerID, g.GuestBootID} {
		if !validIdentity(value) {
			return fmt.Errorf("guest platform binding requires runtime class, handler, Pod UID, container ID and guest boot ID")
		}
	}
	return nil
}

func (b Binding) guestIdentity() GuestIdentity {
	return GuestIdentity{b.RuntimeClass, b.RuntimeHandler, b.PodUID, b.ContainerID, b.GuestBootID}
}

func (b Binding) WithGuest(g GuestIdentity) Binding {
	b.RuntimeClass, b.RuntimeHandler, b.PodUID, b.ContainerID, b.GuestBootID = g.RuntimeClass, g.RuntimeHandler, g.PodUID, g.ContainerID, g.GuestBootID
	return b
}

// ValidateGuest compares a separately observed platform identity. The caller
// must obtain observed from its trusted control plane, not from workload input.
func (b Binding) ValidateGuest(target Target, observed GuestIdentity) error {
	if b.Mode != "guest" || b.Target != target {
		return fmt.Errorf("guest platform target or generation mismatch")
	}
	if err := b.Target.Validate(); err != nil {
		return err
	}
	if err := observed.Validate(); err != nil {
		return err
	}
	if b.guestIdentity() != observed {
		return fmt.Errorf("guest platform identity mismatch")
	}
	return nil
}
