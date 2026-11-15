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
