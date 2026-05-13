#!/bin/bash
#
# Python Version Detection Helper
#
# This script finds a suitable Python interpreter (3.10+) and exports PYTHON_CMD.
# Source this script from other scripts: source "$(dirname "${BASH_SOURCE[0]}")/python_helper.sh"
#
# Override with: PYTHON_PATH=/path/to/python ./scripts/setup_env.sh
#

# Minimum required Python version
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=10

# Function to check if a Python version meets minimum requirements
check_python_version() {
    local python_cmd="$1"

    # Check if command exists
    if ! type -P "$python_cmd" > /dev/null 2>&1; then
        return 1
    fi

    # Get version and validate
    local version_output
    version_output=$("$python_cmd" --version 2>&1) || return 1

    # Parse version (e.g., "Python 3.12.1" -> "3.12.1")
    local version
    version=$(printf '%s' "$version_output" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)

    if [ -z "$version" ]; then
        return 1
    fi

    # Extract major and minor versions
    local major minor
    major=$(printf '%s' "$version" | cut -d. -f1)
    minor=$(printf '%s' "$version" | cut -d. -f2)

    # Check if version meets minimum
    if [ "$major" -gt "$PYTHON_MIN_MAJOR" ]; then
        return 0
    elif [ "$major" -eq "$PYTHON_MIN_MAJOR" ] && [ "$minor" -ge "$PYTHON_MIN_MINOR" ]; then
        return 0
    fi

    return 1
}

# Function to find a suitable Python interpreter
find_python() {
    # Allow override via environment variable
    if [ -n "$PYTHON_PATH" ]; then
        if check_python_version "$PYTHON_PATH"; then
            echo "$PYTHON_PATH"
            return 0
        else
            printf 'ERROR: PYTHON_PATH (%s) does not meet minimum version requirement (Python %s.%s+)\n' "$PYTHON_PATH" "$PYTHON_MIN_MAJOR" "$PYTHON_MIN_MINOR" >&2
            return 1
        fi
    fi

    # List of Python commands to try (prefer newer versions)
    local python_candidates=(
        "python3"
        "python3.14"
        "python3.13"
        "python3.12"
        "python3.11"
        "python3.10"
        "python"
    )

    for cmd in "${python_candidates[@]}"; do
        if check_python_version "$cmd"; then
            echo "$cmd"
            return 0
        fi
    done

    return 1
}

# Main: Find and # HITL approval gate: require human confirmation before exporting PYTHON_CMD
# Skip interactive prompt only when PYTHON_HELPER_AUTO_APPROVE=1 is explicitly set
if [ "${PYTHON_HELPER_AUTO_APPROVE:-0}" != "1" ]; then
    PYTHON_VERSION_PREVIEW=$("$PYTHON_CMD" --version 2>&1)
    echo "========================================="
    echo "  HITL Approval Required"
    echo "========================================="
    echo "  The following Python interpreter will be exported into your environment:"
    echo "    Command : $PYTHON_CMD"
    echo "    Version : $PYTHON_VERSION_PREVIEW"
    echo ""
    printf "  Approve exporting PYTHON_CMD? [y/N]: "
    read -r HITL_RESPONSE </dev/tty
    case "$HITL_RESPONSE" in
        [yY][eE][sS]|[yY])
            : # approved — continue
            ;;
        *)
            echo "  Operation cancelled by user. PYTHON_CMD will NOT be exported." >&2
            return 1 2>/dev/null || exit 1
            ;;
    esac
fi

export PYTHON_CMD

# Display found Python version (only if not being sourced silently)
if [ "${PYTHON_HELPER_QUIET:-0}" != "1" ]; then
    PYTHON_VERSION=$("$PYTHON_CMD" --version 2>&1)
    echo "Using: $PYTHON_VERSION ($PYTHON_CMD)"
find_python)

if [ -z "$PYTHON_CMD" ]; then
    printf '==========================================\n' >&2
    printf '  ERROR: No suitable Python found!\n' >&2
    printf '==========================================\n' >&2
    printf '\n' >&2
    printf '  This project requires Python %s.%s or newer.\n' "$PYTHON_MIN_MAJOR" "$PYTHON_MIN_MINOR" >&2
    printf '\n' >&2
    printf '  Options:\n' >&2
    printf '    1. Install Python %s.%s+ from https://python.org\n' "$PYTHON_MIN_MAJOR" "$PYTHON_MIN_MINOR" >&2
    printf '    2. Use pyenv: pyenv install 3.12\n' >&2
    printf '    3. Specify a Python path: PYTHON_PATH=/path/to/python ./scripts/setup_env.sh\n' >&2
    printf '\n' >&2
    printf '==========================================\n' >&2
    return 1 2>/dev/null || exit 1
fi

export PYTHON_CMD

# Display found Python version (only if not being sourced silently)
if [ "${PYTHON_HELPER_QUIET:-0}" != "1" ]; then
    PYTHON_VERSION=$("$PYTHON_CMD" --version 2>&1)
    printf 'Using: %s (%s)\n' "$PYTHON_VERSION" "$PYTHON_CMD"
fi
