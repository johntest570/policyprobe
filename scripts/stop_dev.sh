#!/bin/bash
#
# PolicyProbe Development Server Stop Script
#
# This script stops both the frontend and backend servers.
# Run from anywhere: ./scripts/stop_dev.sh
#

printf '==========================================\n'
printf '  Stopping PolicyProbe Servers\n'
printf '==========================================\n'
printf '\n'

# Helper: gracefully stop a process on a given port
stop_port() {
    local port="$1"
    local label="$2"
    local pid
    pid=$(lsof -i :"${port}" -t 2>/dev/null)
    if [ -n "${pid}" ]; then
        # Send SIGTERM first; escalate to SIGKILL only if process persists
        kill -TERM "${pid}" 2>/dev/null
        sleep 1
        if kill -0 "${pid}" 2>/dev/null; then
            kill -KILL "${pid}" 2>/dev/null
        fi
        printf '\u2713 %s stopped (port %s)\n' "${label}" "${port}"
    else
        printf '- %s was not running\n' "${label}"
    fi
}

# Stop backend on port 5500
stop_port 5500 "Backend"

# Stop frontend on port 5001
stop_port 5001 "Frontend"

printf '\n'
printf '==========================================\n'
printf '  All servers stopped\n'
printf '==========================================\n'
