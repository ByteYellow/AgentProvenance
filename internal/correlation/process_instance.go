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

func processBindingID(instance string) string {
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

func resolveProcessInstance(db Queryer, runID, instance string, pid int64, at string) (Match, bool, error) {
	if !validProcessInstance(instance, pid) {
		return Match{}, false, nil
	}
	return resolveWindow(db, runID, "kernel_process_instance", "boot+pid+start", "id = ? AND pid = ?", .98, at, false, processBindingID(instance), pid)
}

// ObserveProcessInstance retains a process-scoped anchor, never a new whole-
// cgroup binding. Only an observed cgroup/container or a kernel-identified
// parent can seed it; bare PID/PPID proximity cannot establish ancestry.
func ObserveProcessInstance(db ProcessStore, raw RawIdentity) error {
	if !validProcessInstance(raw.ProcessInstanceID, raw.PID) {
		return nil
	}
	id := processBindingID(raw.ProcessInstanceID)
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
	if !ok && validProcessInstance(raw.ParentProcessInstanceID, raw.PPID) {
		child := strings.Split(raw.ProcessInstanceID, ":")
		parent := strings.Split(raw.ParentProcessInstanceID, ":")
		childNS, _ := strconv.ParseUint(child[2], 10, 64)
		parentNS, _ := strconv.ParseUint(parent[2], 10, 64)
		if child[0] == parent[0] && parentNS <= childNS && raw.PID != raw.PPID {
			seed, ok, err = resolveProcessInstance(db, raw.RunID, raw.ParentProcessInstanceID, raw.PPID, raw.Timestamp)
		}
	}
	if err != nil || !ok {
		return err
	}
	b := seed.Binding
	b.ID, b.PID = id, raw.PID
	b.CgroupID, b.ContainerID = "", ""
	// Preserve the root scope's source/confidence, but the method and exact
	// binding ID distinguish lifecycle evidence from polling-based matches.
	b.Confidence = seed.Confidence
	_, err = RecordBinding(db, b)
	return err
}

// CloseProcessInstance uses the captured lifetime identity. A delayed exit
// must not close a different process that has reused the same numeric PID.
func CloseProcessInstance(db ProcessStore, raw RawIdentity) error {
	if !validProcessInstance(raw.ProcessInstanceID, raw.PID) {
		return nil
	}
	_, err := time.Parse(time.RFC3339Nano, raw.Timestamp)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE execution_context_bindings SET ended_at=? WHERE id=? AND ended_at=''`, raw.Timestamp, processBindingID(raw.ProcessInstanceID))
	return err
}
