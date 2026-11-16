package handoff

import (
	"fmt"
	"path/filepath"

	"github.com/byteyellow/agentprovenance/internal/runtimeadapter"
	"github.com/byteyellow/agentprovenance/internal/seccheck"
)

type BackendConfig struct {
	Mode     string                        `json:"mode"`
	Runsc    *runtimeadapter.RunscConfig   `json:"runsc,omitempty"`
	SecCheck *SecCheckConfig               `json:"seccheck,omitempty"`
	Guest    *runtimeadapter.GuestIdentity `json:"guest,omitempty"`
}

type SecCheckConfig struct {
	Target     seccheck.Target `json:"target"`
	StatusFile string          `json:"status_file"`
	DataDir    string          `json:"data_dir,omitempty"`
}

func (c Config) validateBackendConfig() error {
	if c.Backend == nil {
		return nil
	}
	b := c.Backend
	switch b.Mode {
	case "native", "guest":
		if b.Runsc != nil || b.SecCheck != nil {
			return fmt.Errorf("native and guest execution cannot configure runsc or SecCheck")
		}
		if b.Mode == "guest" && (c.Capture == nil || c.Capture.Placement != "guest_kernel") {
			return fmt.Errorf("guest execution requires capture placement guest_kernel")
		}
		if b.Guest != nil {
			if b.Mode != "guest" {
				return fmt.Errorf("guest platform identity requires guest execution mode")
			}
			if err := b.Guest.Validate(); err != nil {
				return err
			}
		}
	case "runsc":
		if b.Guest != nil {
			return fmt.Errorf("runsc cannot configure a guest platform identity")
		}
		if c.Concurrency != 1 || c.Capture != nil || b.Runsc == nil {
			return fmt.Errorf("runsc requires concurrency=1, runsc configuration and no native host capture")
		}
		if err := b.Runsc.Validate(); err != nil {
			return err
		}
		if b.SecCheck != nil {
			s := b.SecCheck
			cfg := seccheck.CollectionConfig{SchemaVersion: seccheck.CollectionConfigSchema, RuntimeRelease: seccheck.RuntimeRelease, Targets: []seccheck.Target{s.Target}}
			if err := cfg.Validate(); err != nil {
				return err
			}
			r := s.Target.Registration
			if r.Namespace != c.Target.ProducerID || r.InstanceID != c.Target.InstanceID || r.Generation != c.Target.Generation || r.ContainerID != b.Runsc.ContainerID || r.PeerUID != 0 {
				return fmt.Errorf("SecCheck registration must match the full execution target and root launcher")
			}
			if !filepath.IsAbs(s.StatusFile) || filepath.Clean(s.StatusFile) != s.StatusFile {
				return fmt.Errorf("SecCheck status_file must be a clean absolute path")
			}
			if s.DataDir != "" && (!filepath.IsAbs(s.DataDir) || filepath.Clean(s.DataDir) != s.DataDir) {
				return fmt.Errorf("SecCheck data_dir must be a clean absolute path")
			}
		}
	default:
		return fmt.Errorf("execution backend mode must be native, guest or runsc")
	}
	return nil
}
