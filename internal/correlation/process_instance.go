package correlation

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type ProcessStore interface {
	Queryer
	bindingExecer
}

func processBindingID(instance, host string) string {
	if host != "" {
		instance = host + "\x00" + instance
	}
	return fmt.Sprintf("bind-native-%x", sha256.Sum256([]byte(instance)))
}

func validProcessInstance(instance string, pid int64) bool {
	parts := strings.Split(instance, ":")
	if len(parts) != 3 || len(parts[0]) != 36 || pid <= 0 {
		return false
	}
	boot := parts[0]
	if boot[8] != '-' || boot[13] != '-' || boot[18] != '-' || boot[23] != '-' {
		return false
	}
	if decoded, err := hex.DecodeString(strings.ReplaceAll(boot, "-", "")); err != nil || len(decoded) != 16 {
		return false
	}
	p, err := strconv.ParseInt(parts[1], 10, 64)
	ns, nerr := strconv.ParseUint(parts[2], 10, 64)
	return err == nil && nerr == nil && p == pid && ns > 0
}

// ProcessInstanceBootID returns the kernel boot identity only for a validated
// native process instance. It is shared by scope attribution and graph analysis.
func ProcessInstanceBootID(instance string, pid int64) string {
	if !validProcessInstance(instance, pid) {
		return ""
	}
	boot, _, _ := strings.Cut(instance, ":")
	return strings.ToLower(boot)
}

func CanonicalProcessInstance(instance string, pid int64) string {
	boot := ProcessInstanceBootID(instance, pid)
	if boot == "" {
		return ""
	}
	parts := strings.Split(instance, ":")
	start, _ := strconv.ParseUint(parts[2], 10, 64)
	return fmt.Sprintf("%s:%d:%d", boot, pid, start)
}

// RelatedProcessLifetime accepts validated, canonical identities only.
func RelatedProcessLifetime(parent, child string) bool {
	p, c := strings.Split(parent, ":"), strings.Split(child, ":")
	if len(p) != 3 || len(c) != 3 || p[0] != c[0] {
		return false
	}
	ps, pe := strconv.ParseUint(p[2], 10, 64)
	cs, ce := strconv.ParseUint(c[2], 10, 64)
	return pe == nil && ce == nil && ps > 0 && ps <= cs
}

func resolveProcessInstance(db Queryer, runID, instance, host string, pid int64, at string) (Match, bool, error) {
	instance = CanonicalProcessInstance(instance, pid)
	if instance == "" {
		return Match{}, false, nil
	}
	basis := "boot+pid+start"
	if host != "" {
		basis = "host+" + basis
	}
	return resolveWindow(db, runID, "kernel_process_instance", basis, "id = ? AND pid = ?", .98, at, false, processBindingID(instance, host), pid)
}

// ObserveProcessInstance retains a process-scoped anchor, never a new whole-
// cgroup binding. Only an observed cgroup/container or a kernel-identified
// parent can seed it; bare PID/PPID proximity cannot establish ancestry.
func ObserveProcessInstance(db ProcessStore, raw RawIdentity) error {
	instance := CanonicalProcessInstance(raw.ProcessInstanceID, raw.PID)
	if instance == "" {
		return nil
	}
	id := processBindingID(instance, raw.HostID)
	var existing string
	err := db.QueryRow(`SELECT id FROM execution_context_bindings WHERE id=?`, id).Scan(&existing)
	if err == nil {
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	seed, ok, err := Resolve(db, raw)
	if err != nil {
		return err
	}
	if seed.Ambiguous {
		return nil
	}
	parent := CanonicalProcessInstance(raw.ParentProcessInstanceID, raw.PPID)
	if !ok && RelatedProcessLifetime(parent, instance) && raw.PID != raw.PPID {
		seed, ok, err = resolveProcessInstance(db, raw.RunID, parent, raw.HostID, raw.PPID, raw.Timestamp)
	}
	if err != nil || !ok || seed.Ambiguous {
		return err
	}
	b := seed.Binding
	b.ID, b.PID = id, raw.PID
	b.CgroupID, b.ContainerID = "", ""
	// Preserve the root scope's source/confidence, but the method and exact
	// binding ID distinguish lifecycle evidence from polling-based matches.
	b.Confidence = seed.Confidence
	b.ConfidenceSet = true
	_, err = RecordBinding(db, b)
	return err
}

// CloseProcessInstance uses the captured lifetime identity. A delayed exit
// must not close a different process that has reused the same numeric PID.
func CloseProcessInstance(db ProcessStore, raw RawIdentity) error {
	instance := CanonicalProcessInstance(raw.ProcessInstanceID, raw.PID)
	if instance == "" {
		return nil
	}
	_, err := time.Parse(time.RFC3339Nano, raw.Timestamp)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE execution_context_bindings SET ended_at=? WHERE id=? AND ended_at=''`, raw.Timestamp, processBindingID(instance, raw.HostID))
	return err
}
