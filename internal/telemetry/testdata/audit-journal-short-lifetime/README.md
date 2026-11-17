# Short lifetimes with stale audit timestamps

These are the original synthetic runtime and kernel journal records from
[CI run 43991220944, Go 1.24](https://github.com/ByteYellow/AgentProvenance/actions/runs/43991220944).
The nominal 1 ms coarse clock plus audit decimal precision ended before the
AppArmor complain process and seccomp LOG process started. Their saved journal
receipt bounds include the actual lifetime and syscall observations.

The regression imports these bytes through the normal native/audit paths and
checks both processes, their exits and actual return observations. KILL_PROCESS
retains no syscall operation. Separate cases reject missing/invalid receipt
clocks and later births, and preserve ambiguity across reused PIDs.
