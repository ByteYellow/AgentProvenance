package runtimeadapter

import "testing"

func TestGuestBindingRejectsChangedPlatformIdentity(t *testing.T) {
	g := GuestIdentity{RuntimeClass: "kata-qemu", RuntimeHandler: "kata-qemu-runtime-rs", PodUID: "pod-uid", ContainerID: "container-id", GuestBootID: "boot-id"}
	b := (Binding{Target: testRequest().Target, Mode: "guest"}).WithGuest(g)
	if err := b.ValidateGuest(b.Target, g); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"class", "handler", "pod", "container", "boot", "generation"} {
		t.Run(field, func(t *testing.T) {
			observed, target := g, b.Target
			switch field {
			case "class":
				observed.RuntimeClass = "other"
			case "handler":
				observed.RuntimeHandler = "other"
			case "pod":
				observed.PodUID = "other"
			case "container":
				observed.ContainerID = "other"
			case "boot":
				observed.GuestBootID = "other"
			case "generation":
				target.Generation = "restored"
			}
			if err := b.ValidateGuest(target, observed); err == nil {
				t.Fatal("accepted changed guest platform identity")
			}
		})
	}
}
