# Dangerous Sink Catalog

What each flagged sink implies and how to confirm it is actually reachable. A
sink hit is a **lead**: it only becomes a finding when attacker-controlled data
demonstrably reaches it. Confirm the taint path in Ghidra, then reproduce in
emulation.

## Command execution (highest value — often pre-auth RCE)
| Sink | Implication | Confirm by |
|------|-------------|-----------|
| `system`, `popen` | Arg passed to `/bin/sh -c` | Trace arg back to an untrusted source (query string, POST body, NVRAM, header). Any shell metacharacter that survives = injection. |
| `execl/execv/execve*` | Direct exec (no shell) | Injection needs argument-boundary control; still dangerous if a path/arg is attacker-set. |
| `doSystem`, `CsteSystem`, `twSystem`, `bcm_system` | Vendor `system()` wrappers common in SOHO firmware | Same as `system`; often formatted with `sprintf` first — check the format string. |

## Memory-corruption sinks
| Sink | Implication | Confirm by |
|------|-------------|-----------|
| `gets` | Never safe; unbounded stack read | Any use is a bug; check buffer + reachability. |
| `strcpy`, `stpcpy`, `strcat` | Overflow if source longer than dest | Find the dest buffer size and whether source length is attacker-controlled. |
| `sprintf`, `vsprintf` | Overflow via `%s`/large conversions; also format-string if the format itself is tainted | Check the format string and each `%s` source. |
| `sscanf`/`scanf` with `%s` | Unbounded field read into buffer | Look for width-less `%s`. |
| `memcpy` | Overflow when the **length** is attacker-controlled | Trace the length arg; ignore fixed-length copies (low signal). |
| `strncpy`, `strncat` | Bounded but off-by-one / missing NUL termination | Check for `n == sizeof(dst)` mistakes. |

## Untrusted-input sources (taint origins)
`getenv` (CGI `QUERY_STRING`/`REQUEST_METHOD`), `recv`/`recvfrom`, `read`,
`fgets`, and vendor accessors (`nvram_get`, `websGetVar`, `webGetVar`,
`httpd_get`). A source in the same binary as a high-value sink is why
`sink_scan.py` sets `reachable_hint=yes`.

## Scoring rationale (as implemented in sink_scan.py)
Command execution and `gets` score highest (direct to RCE); string-copy/format
sinks are mid; `memcpy`/`strncpy` are low-signal because they are ubiquitous and
usually bounded. A script that contains **both** a command sink and an untrusted
source gets a bonus — that pairing is the classic CGI command-injection shape.
