# bpftrace helper compatibility

poortrace runs native userspace handlers, without loading BPF. The helpers below
extend its tracing language; they do not imply complete bpftrace language, C type,
or kernel-context compatibility.

## Maps and aggregation

- `has_key(@map, key)`, `len(@map)`, and boolean `delete(@map, key)`
  distinguish missing keys from zero. Tuple keys use `("name", 1)`.
- `find(@map, key, $value)` returns a boolean, updates an **already initialized**
  local on success, and leaves it unchanged on failure.
- `zero(@map)` retains keys and clears values, histogram buckets, and series.
- `stats(value)` records count, average, and total for integers or floats.
- `hist(value, k)` subdivides integer power-of-two buckets with constant
  precision `k=0..5`.
- `tseries(value, interval, capacity[, "aggregation"])` stores integer event-time
  bins. The interval and capacity are positive constants; capacity is at most
  4096. Aggregation is `last` (default), `sum`, `avg`, `min`, or `max`.
  For example: `@requests=tseries(1, 1s, 60, "sum")`.
  A state permits at most 1,048,576 series bins across all map entries.
- `print(@map[, top[, div]])` prints the highest values first without changing
  the map. Zero top means all entries; div must be positive.
  Scalar `print(value)` remains supported.

JSON rows expose optional `stats` and `series` fields. Reports cannot use these
compound aggregates as profile weights or apply scalar comparison/rate operations
to them.

## Strings, networking, and time

`strerror(errno)`, `strstr(text, needle)` (byte offset, or -1),
`strncmp(a,b,count)`, `memcmp(a,b,count)`, `strcap(text)`,
`join(argv[, separator])`, and `strftime(format, timestamp)` are supported.
`strcap` returns the actual UTF-8 byte length in this language's string model.
Comparisons accept strings or target addresses and read at most 4096 bytes;
`join` reads at most 256 native 64-bit argument pointers, each at most 4096 bytes,
with a combined output limit of 64 KiB. `join` prints its result.

`pton(text)`, `ntop([family,] address)`, and `macaddr(address)` support IPv4,
IPv6, and MAC formatting. Since poortrace has no C byte-array value type,
`pton` returns space-separated hexadecimal bytes, matching `buf` output.
`ntop` accepts that representation or a native integer IPv4 value;
`macaddr` accepts six hexadecimal bytes or a target address. `AF_INET` and
`AF_INET6` are constants.

`nsecs` and `nsecs(monotonic)` retain monotonic **event** timestamps.
`nsecs(boot|tai|sw_tai)` translates that timestamp using a processing-time
clock offset. `elapsed` is nanoseconds since the first handler invocation.
`strftime` translates a monotonic timestamp to local wall time, with
`%f` for six-digit microseconds. Output is bounded to 4095 bytes.
`time([format])` directly prints local wall-clock time.

## Identity, symbols, registers, and stacks

Supported metadata helpers also work as bare names when they take no arguments:

- `uid`, `gid`, `username([uid])`, `ppid`, `pcomm`, `leader_comm`,
  `leader_tid`, `cpid`, `has_cpid`, and `comm([pid])`.
  `cpid` requires a launched command; `has_cpid` can test availability.
  Parent helpers resolve the actual parent thread through procfs.
- `func`, `probetype`, `ncpus`, and `numaid`.
- `uaddr(symbol)` resolves one unambiguous loaded function, checking image
  device/inode identity. `kaddr(symbol)` requires an accessible nonzero address
  in kallsyms. These return numeric addresses.
- `reg(name)` reads captured registers, including architecture-specific general
  registers and `sp`, `ip/pc`, `fp`, and AArch64 `lr`. Missing registers
  produce an error rather than a fabricated zero. Register capture is requested
  only for scripts that use it.
- `ustack([raw|perf|bpftrace[, depth]])` and the corresponding `kstack`
  formatting support depths 1..127. `len(stack)` counts rendered frames.
  `dw_ustack` selects DWARF unwinding for the whole session, including other
  user-stack calls in the same script.
- `cgroup`, `cgroupid(path)`, and `cgroup_path(id[, "unified"])` support
  cgroup v2. Path lookup is bounded to 4096 directories and depth 64.
- `kfunc_exist(name)` checks for a kernel BTF FUNC entry, requiring readable BTF;
  it does not establish BPF registration or attachment policy.

Procfs, symbol, account, cgroup, and CPU-topology queries observe processing-time
state. Target metadata queries require a registered process start identity
(an attached PID, launched command, or verified ptrace target), and check it
around the lookup. Explicit `comm(pid)` establishes an identity for that query.
Unavailable permissions, exited processes, and unsupported metadata produce
errors. They are not equivalent to kernel event-time snapshots.

## Utilities and diagnostics

`rand()` obtains a 32-bit random value. `bswap(value[, bits])` supports
8/16/32/64 bits; explicit casts such as `bswap(u16(value))` select their width.
`uptr(address)` preserves a numeric address.
`syscall_name(number)` and `signal_name(number)` return names;
standard Linux `SIG*` constants are available.

`getopt(name[, default[, description]])` reads repeated CLI arguments
`--script-arg name=value`. A string default selects string output; otherwise
the result is numeric. Description is accepted for compatibility. There are at
most 256 arguments, each at most 4096 bytes. These arguments are separate from
the command launched after `--`.

`assert(condition[, message])` fails the current run when false.
`static_assert(condition[, message])` checks constant expressions at compilation.
`fail(format[, values...])` reports a compile-time error, and
`errorf(format[, values...])` / `warnf(format[, values...])` print diagnostics
to stderr. `cat(format[, values...])` prints a UTF-8 file up to 64 KiB.
Formats are literal printf-style strings.
`exit([status])` requests termination with status 0..255; END still runs.

Native primitive `sizeof(int)`, `sizeof(unsigned long)`, and bounded arrays
such as `sizeof(char[16])` use the supported Linux LP64 layout.
Scalar expressions use poortrace's 64-bit value model, not a complete C type
system. Named structures and `offsetof(struct name, field)` use validated
DWARF layouts; existing string descriptor forms remain supported.
Type predicates describe this limited value model.

## Explicit effects

`system(format[, values...])`, `signal(number)`, `signal_thread(number)`,
and `write_user(address, source, count)` require `--unsafe`.

`system` runs an explicit shell command in its own process group, captures
UTF-8 stdout up to 64 KiB, and limits execution to five seconds. Its stderr is
discarded. Cleanup terminates that helper process group. A waitable SIGCHLD
disposition is required.

Signals and writes additionally require `--reliable`, a verified stopped
external target, and a handler with captured registers; BEGIN/END cannot issue
them. Signals are queued against pidfds and delivered after safe breakpoint
rearming or detach. Thread signals require kernel support for thread pidfds
(Linux 6.9+). A successful helper return means the request was queued;
delivery failures are reported by the backend. Requests are canceled on a
handler error. Explicit SIGKILL may of course terminate an attached target.

`write_user` writes at most 4096 bytes, returns one for a complete write and
zero for failure or a partial write. Partial writes are not rolled back.
Sources use text or the hexadecimal byte representation; text includes its
terminating NUL when the requested count includes it. This is an explicit
exception to the otherwise read-only target memory helpers.

`unwatch(address)` removes this session's matching watchpoint streams, including
future refresh attachments; it does not change another tracer's watchpoints. The retained address set is bounded
by `--max-map-entries`.

## Replay and unavailable kernel helpers

Recorded helper descriptors contain argument values and string contents rather
than transient pointers. Replay validates result types and uses captured results
for target/host lookups and effects. It never reruns commands, sends signals,
writes target memory, or opens current target images to reconstruct results.
Alternate scripts can recompute deterministic string/numeric helpers; other calls
need matching captured descriptors. Missing or conflicting captures fail explicitly.

The following names produce specific compile-time capability errors:
`override`, `skboutput`, `socket_cookie`, `path`, `curtask`, `jiffies`,
`usermode`, `kptr`, `percpu_kaddr`, and `kfunc_allowed`.
Their kernel context or BPF policy cannot be provided faithfully by poortrace's
no-BPF backend.
