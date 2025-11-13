# AI Coding Agent Guide for Networking_Project_2

Concise project-specific rules to get productive fast. Focus on existing patterns—do not invent new architectures.

## Overview
This is a minimal FTP-like server/client in C++20. The server (`server.cpp`) accepts TCP connections, authenticates a single anonymous user, and then dispatches text commands (PWD, CWD, CDUP, PASV, LIST, RETR, QUIT) via logic embedded in `client_handler.cpp`. Passive data transfers (LIST/RETR) use a one-shot PASV listener stored in a per-control-socket map. Tests in `ftp_tests.cpp` exercise protocol behaviors including error codes and path jail constraints.

## Build & Run
Use the provided `Makefile` targets:
- `make server` (compiles only `server.cpp`; other .cpp files are included via `#include` not linked separately)
- `make run` → `./server server.conf` (config file supplies `PORT=<num>`). Example `server.conf`: `PORT=3490`.
- `make client` / `make clientrun` → connects to host passed as arg.
- `make test` + `make test_run` → builds & runs `ftp_tests` against 127.0.1.1:3490.
Recompile after changes in any included handler file; no separate object build currently.

## Architecture & Flow
Main accept loop (`server.cpp`) spawns a detached `std::jthread` per connection calling `handle_client`. That function performs a simple USER gate and hands off to `client_handle_client` for the FTP command loop. Command loop lowercases input (`string_to_lowercase` in `helper_commands.cpp`) then branches by exact match or prefix (`rfind("list",0) == 0`). Multi-phase commands (LIST, RETR) require active PASV state.

## Command Handling Pattern
1. Normalize input to lowercase early.
2. Validate sequencing (USER must precede any other command; anonymous only).
3. For data commands: ensure PASV session exists, accept data socket, send preliminary `150` (or `125`), perform transfer, then send `226` and tear down PASV.
4. Use `send_back(int pid, int code)` for numeric replies; map lives in `codes.cpp`.
5. Use `send_back(int pid, std::string msg)` only for custom text like formatted 227 and 257 responses.

## Passive Mode (PASV)
`enter_pasv` (in `client_handler.cpp`) binds an ephemeral port (sets sin_port=0), stores `{listen_socket, port}` in `pasv_map` keyed by control fd, and returns a properly formatted `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).` Only one active PASV listener per control fd—subsequent PASV replaces the previous (tests assert prior port becomes invalid).

## Data Transfer
- LIST: validate jail + argument before accepting data; reject absolute paths, traversal (`..`), and outside-of-root. Build listing lines with UNIX-like perms; aggregate peer directories at root if available.
- RETR: similar flow; check PASV, path traversal (`..`), file existence; stream in 8KB chunks using `send_all`.
- Always close data_fd and remove PASV entry after one transfer (tests depend on needing a new PASV for the next LIST/RETR).

## Path Jail & Security
Root jail is `db/` (current working directory + `/db/`). CWD validates each path segment; moving above jail resets to parent and returns 550. LIST and RETR block arguments containing `..` or starting with `/`. Maintain this behavior for new commands manipulating paths.

## Concurrency & Shared State
Threads are detached; no explicit join. PASV sessions stored in `pasv_map` (unordered_map) without mutex—scope is per control socket; avoid cross-thread reuse. Peer aggregation uses `peer_root_listing` and `peer_mutex` (extern in `client_handler.cpp`; define them if extending peer features). Protect any shared additions with the existing mutex pattern.

## Peer Scanning (Distributed Extension)
`peer_scanner.cpp` iterates an IPv4 CIDR-like range, opens sessions, logs in anonymously, enters PASV, issues LIST, and (intended) aggregates results. LIST at server root optionally merges remote directory lines (those starting with 'd'). Keep remote merges restricted to root to avoid confusion.

## Testing Conventions
`ftp_tests.cpp` uses a lightweight registration macro `TEST(name)` and socket helpers similar (but not identical) to runtime code. Tests assert reply codes strictly (e.g., USER → 230 or 530). When adding behavior, either preserve current codes or update tests accordingly. Data commands must produce code sequence: 227 (PASV), then 150/125, then 226 (success) or proper error (425/450/550/553). Traversal and invalid sequences should yield existing error codes (425 no PASV, 550 path issues, 530 auth, 553 invalid filename).

## Adding New Commands Example
To add STOR:
- Lowercase input; match prefix `"stor"`.
- Require PASV; if missing send 425.
- Accept data, send 150, write file inside jail (validate name: no `..`, no leading `/`).
- On success send 226; on failure send 550/451.
- Close data socket and clear PASV state.

## Gotchas / Tips
- Because handler .cpp files are included via `#include`, circular includes will break compilation—prefer forward declarations if expanding.
- Always strip CRLF (`buf[strcspn(buf, "\r\n")] = '\0';`) before parsing.
- Maintain one-shot PASV semantics or tests will fail (LIST must need new PASV after completion).
- Keep replies newline-terminated; current pattern appends `"\n"` (not CRLF) for numeric codes—tests accept this. 227 and listings embed `\r\n` explicitly; follow existing style.

## When Unsure
Mirror patterns from LIST/RETR. Re-run `make server && make test_run` to validate protocol behavior quickly.

Please review: Are peer aggregation and config assumptions clear enough? Which areas need deeper detail? Reply with clarifications and I can refine.
