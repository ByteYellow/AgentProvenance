# Performance validation

English | [简体中文](zh-CN/performance-validation.md)

Measure the workload and environment that a report names. The telemetry pressure
profile exercises JSONL admission, spool ingestion, SQLite storage and paged
queries. Native Sensor overhead, Browser/Notebook attachment cost and browser
replay loading use their own workloads and reports.

## Measure the telemetry baseline

Use an otherwise idle test host, a fixed executable and a fresh output directory
for every run. Keep the same CPU/RAM allocation, kernel, Python version and
background services throughout the comparison. The script retains the generated
input, isolated store, daemon log and JSON report. Allow several GiB of free
space for repeated runs, plus room for the executable and build cache.

```sh
BASELINE=/absolute/path/to/baseline-agentprov
MEASUREMENTS=$(mktemp -d)
for trial in 1 2 3; do
  python3 scripts/accept_telemetry_100k_pressure.py run \
    --agentprov "$BASELINE" --events 100000 \
    --output "$MEASUREMENTS/baseline-$trial"
done
```

The daemon keeps its default bearer authentication and file-ingest confinement.
The script reads the generated private token locally, never writes it into the
report, and sends only loopback requests. Policy evaluation and background
sampling/evidence/GC workers are disabled explicitly for this ingestion profile.
No native kernel Sensor is started. The original synthetic Falco fixture remains
unchanged: 100,000 distinct process events in one queued input file.

The report records:

- Input, script and executable SHA-256, executable version, environment and flags.
- Exact processed and failed counts, bounded five-record pages and producer health.
- Drain duration and throughput; up to ten query pairs during ingestion and
  thirty pairs afterward. Latency samples and p50/p95/p99/max stay separate by
  phase; with thirty samples p99 is the sample maximum, not a tail estimate.
- Polled daemon peak CPU and RSS. Linux CPU uses process user/system time deltas
  at 100 ms intervals; macOS polls the lifetime average from `ps` at the same
  interval. The report names the method; compare only matching environments.
- Logical file bytes when queued, drained and stopped.
  Storage includes SQLite, WAL and retained spool files; it excludes the generated
  source fixture. The file inventory explains each total. Filesystem allocated
  blocks and compressed Bundle size are separate measurements.

HTTP failures fail the run. Empty timing samples stay unknown. Failed runs retain
their reports and logs. Optional `--source-commit FULL_SHA` also checks that the
executable's version output contains that source revision.

## Freeze, then check a candidate

Freeze the budget **before** running the candidate:

```sh
python3 scripts/accept_telemetry_100k_pressure.py freeze \
  --baseline "$MEASUREMENTS/baseline-1/report.json" \
  --baseline "$MEASUREMENTS/baseline-2/report.json" \
  --baseline "$MEASUREMENTS/baseline-3/report.json" \
  --allowed-regression 0.25 --budget "$MEASUREMENTS/budget.json"

python3 scripts/accept_telemetry_100k_pressure.py run \
  --agentprov /absolute/path/to/candidate-agentprov --events 100000 \
  --budget "$MEASUREMENTS/budget.json" --output "$MEASUREMENTS/candidate"
```

Budgets use the median of at least three distinct successful baseline runs.
The example allows a 25% increase in drain duration, peak RSS, stopped-store bytes
and post-ingest query p95. A fixed 1 ms allowance is added to the two query limits
to accommodate sub-millisecond timer noise. Both allowances are saved in the
budget. Environment, workload and measurement-script identities must match.
Exceeding any limit returns a nonzero exit code with the actual value and limit.
Keep failed candidate results; investigate them before changing the workload or
budget. The budget is a regression gate for the named environment, not an SLA.

## Existing shell entry

`scripts/accept_telemetry_100k_pressure.sh` forwards to the same Python measurement.
Its `AGENTPROV_ACCEPT_100K_EVENTS`, `LISTEN`, `REPORT`, `DATA_DIR` and `BIN` settings
remain available with the `AGENTPROV_ACCEPT_100K_` prefix. `DATA_DIR` is now a new,
retained output directory containing `store/`; an existing path is rejected.
`BIN`, when supplied, is an existing executable and is never rebuilt or deleted.
Without `BIN`, the script builds into its own output directory. Existing reports
and budgets are never overwritten. The detailed report schema is now `v2`.

Keep local stores, generated authentication tokens and raw logs outside public
commits. Publish only reviewed measurements and their environment/source hashes.

## Measure native Sensor overhead

Use a dedicated Linux test host with root/BPF privileges. The existing four-worker
fixture issues 40,000 file opens in a burst, then 160,000 in a paced workload.
`accept_sensor_overhead.py` runs each workload three times under each profile:

| Profile | Sensor configuration |
| --- | --- |
| `off` | No Sensor; only workload wall time and CPU are measured |
| `minimal` | Core probes; automatic TLS discovery and AppArmor/seccomp state sampling disabled |
| `default` | Core probes, automatic TLS discovery and both state samplers enabled |

These are measurement profiles, separate from basic/detailed context retention.
The runner clears Sensor library-path and automatic-TLS environment overrides and
rotates profile order between repeats. Captures retain separate ready and stopped
probe/TLS-discovery capability reports. This file workload measures the cost of the
enabled configuration; TLS traffic and attachment storage require other workloads.

```sh
MEASUREMENTS=$(mktemp -d)
sudo python3 scripts/accept_sensor_overhead.py run \
  --sensor /absolute/path/to/baseline-agentprov-sensor \
  --output "$MEASUREMENTS/baseline"
sudo python3 scripts/accept_sensor_overhead.py freeze \
  --baseline "$MEASUREMENTS/baseline/report.json" \
  --allowed-regression 0.25 --budget "$MEASUREMENTS/budget.json"
sudo python3 scripts/accept_sensor_overhead.py run \
  --sensor /absolute/path/to/candidate-agentprov-sensor \
  --budget "$MEASUREMENTS/budget.json" --output "$MEASUREMENTS/candidate"
```

All collected runs must retain the exact open/result counts and five process
exits, including immediate shutdown drain. Kernel, state-queue and TLS-discovery
queue drop counts must stay zero. Node-wide procfs state availability is reported separately from
fixture counts. `off` leaves collection metrics unknown. The original
`accept_sensor_pressure.py` also retains its forced 1 MiB overload test, which
requires reported loss rather than a zero-loss result.

Reports preserve every repeat, medians and duration relative to `off`. CPU is
waited child user/system time: workload CPU includes work charged to those
processes; Sensor CPU includes startup, discovery and shutdown drain. Peak RSS is
sampled every 20 ms. A blocking `wait4` measures workload completion without
timed-wait polling rounding up short bursts. Startup and drain have separate
timings. No policy engine or database is started.

Raw JSONL size and digest cover the whole node capture. A separate byte count
covers records with the fixture's process name. After timing, each JSONL is
compressed with gzip level 1 and retained with stderr and the capability report
in a private output directory. These are capture-file costs, not Bundle or
SQLite sizes. Root-owned captures can contain background process metadata; keep
them private and reserve several GiB of disk space.

Freeze uses the three medians per workload/profile, allowing 25% regression in
wall time, Sensor CPU, RSS and fixture JSONL bytes. A fixed 20 ms allowance applies
to wall and CPU time; it is declared in the instrument before measurement and
saved in the budget. The `off` wall-time gate also detects a changed host baseline.
Node-wide output bytes and compression size are reported, not used as fixed
fixture limits. Environment, compiler, workload and instrument hashes must
match. Both successful and failed results remain on disk; exceeding any limit
returns nonzero. Rebaseline explicitly when the environment or instrument changes.

Optional `--source-commit FULL_SHA` records the build revision supplied by the
operator. Sensor has no version query; retain the build command and source
archive digest alongside the executable hash when establishing source provenance.
