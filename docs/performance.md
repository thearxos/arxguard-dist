# ARXGuard native performance architecture

This branch ports the useful performance model from Tirith into ARXGuard without copying Tirith source code.

## Runtime path

1. **Shell boundary:** the Bash DEBUG trap identifies a new history line and deduplicates pipeline stages.
2. **Native detection:** `arxguard_scan` is a Bash loadable builtin, so detection stays in the already-running shell process.
3. **Tier 0:** raw-byte sentinels catch terminal escape/control sequences and security-sensitive Unicode byte sequences.
4. **Tier 1:** allocation-light substring and command-boundary checks cover remote-shell execution, decoded payloads, destructive disk operations, package verification bypasses, credential access, persistence, unsafe transport, and homograph candidates.
5. **Future Tier 2/3:** a Rust core can perform full shell tokenization, URL/IDN parsing, Unicode confusable analysis, and local threat-intelligence lookups only when Tier 0/1 requires deeper analysis.

## Latency rules

- No Python, Perl, Ruby, Node, grep, sed, awk, regex subprocess, network request, or filesystem read is performed by the detector.
- No process is spawned for each command.
- The scanner receives an existing in-memory command buffer.
- The fast engine performs one linear byte pass plus a bounded set of targeted searches.
- Threat intelligence is intentionally not consulted in the hot path. If added, it must be preloaded and immutable in memory.
- Shell hook output is produced only after a finding; clean commands avoid diagnostic formatting.

## Build

`make` builds the native CLI, static library, and Bash loadable builtin. The builtin is the production fast path for Bash.

For benchmarking, compare the native builtin/CLI against the previous shell scanner using a fixed corpus and report p50/p95/p99, CPU cycles, allocations, and false-positive/false-negative counts. Do not claim absolute latency without measurements on the target machine.
