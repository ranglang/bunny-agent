# 2026-05-21 Daemon Sandbox Process Endpoint

- Added `GET /api/sandbox/processes` to the daemon so sandbox clients can inspect running processes that own listening ports.
- Wired the endpoint to `ps-list` for process enumeration and a listening-socket lookup so each result includes the owning process and its non-excluded ports.
- Filtered out ports `3080` and `9002` so callers can distinguish other active dev servers from reserved sandbox ports.
- Added daemon integration coverage for the endpoint, including the excluded-port behavior.