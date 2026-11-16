// Package workspace is a bounded, remote-authoritative W-01 sidecar core.
// It has no transport, command runner, model, or handoff dependency. A trusted
// adapter routes its file tools here and invokes its existing record runner in
// ObserveExecution. That callback receives the authoritative root and observed
// input revision; it must not call back into this workspace while holding the
// lease. Record snapshot IDs are carried separately from workspace observations.
//
// One operator-owned StateDir with an existing canonical parent is required per
// workspace. All adapters MUST share it and the same provenance database.
// StateDir and the evidence store must be outside the workspace, inaccessible
// to the workload.
// CurrentTarget is a trusted live identity lookup, not request-supplied identity;
// it must change generation after restore/recreation. An old binding is never
// silently rebound. The parent owns authorization, generation lifecycle, record
// execution/recovery, secret policy, and any stronger sandbox boundary.
//
// Linux and Darwin are supported. Paths are relative slash-separated names with
// exact spelling: no dot components, symlinks, hardlinks, special files, mounted
// subtrees, or case-fold collisions. Directories must already exist; rename,
// delete, and chmod operate on regular files. .git and .agentprov components are
// excluded as recorder/VCS metadata. Submodules and LFS are ordinary
// checked-out bytes; there is no git/LFS resolution or snapshot-transfer. Modes
// are permission bits only, and managed writes/chmod require owner-read to keep
// subsequent bounded observations readable. Ownership, ACLs, xattrs and special
// bits are outside scope. Writes/chmod atomically replace a file, changing its inode.
//
// The process-safe lease covers identity checks, scanning, preconditions, intent
// durability, filesystem application, evidence, and revision publication. The
// journal uses fsync plus atomic rename; provenance uses the existing content
// store, a FULL-synchronous transaction, and explicitly synced object files.
// A durable intent precedes any mutation. Restart observes an unfinished intent
// as outcome_unknown and never replays it, even if its requested bytes are now
// present. A failure after intent publication requires Inspect/reopen to recover.
//
// The lease coordinates managed tools, not external writers. Root/ancestor
// namespaces are operator-owned and must not be relocated while in use. External
// mutations between scans are recorded as external_observation. Scans are bounded
// observations, not immutable snapshots: a transient change-and-restore can escape
// polling. Unsupported or over-budget external entries fail closed until the
// operator restores the supported scope. Execution keeps the managed lease,
// but external/child writes remain possible; its input and output manifests are
// observations, never kernel/sensor claims. Existing record snapshots may provide
// additional independent evidence.
//
// UTF-8, non-NUL file contents and execution output use PutTextContent, including
// its redaction. Source SHA-256 and stored/redacted SHA-256 are distinct. Binary
// files have an explicit binary_omitted content state, while their bytes, digest,
// and mode remain in the observed manifest. No raw file bytes enter the journal.
// Defaults are 2 MiB per file, 16 MiB per scan, 1024 directory entries (including
// excluded names), and 2 MiB combined stdout/stderr. Hard maxima are 32 MiB,
// 128 MiB, 8192 entries, and 32 MiB respectively. Revisions and digests always
// describe this explicit bounded scope, not a git commit or a whole machine.
//
// A remote Harness loop lives outside ObserveExecution. Route each Read/Edit/
// Write call independently, preserving the revision/digest from the read that
// informed that edit. Wrap only the individual Bash runner in ObserveExecution;
// use its supplied root and copy record.Result IDs to RecordReference. On a CAS
// conflict, return the conflict to the tool caller instead of retrying with a
// freshly fetched revision. On ErrRecovery, Inspect/reopen observes the outcome;
// command lifecycle reconciliation remains with the existing record runner.
package workspace
