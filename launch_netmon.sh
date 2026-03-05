#!/bin/bash
# NETMON PRO v2.1 Launcher
# Ensures the script runs with root privileges

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

# Try to use pkexec for a GUI sudo prompt, fallback to terminal sudo
if command -v pkexec >/dev/null 2>&1; then
    pkexec env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY python3 netmonv2.1.py
else
    x-terminal-emulator -e "sudo python3 netmonv2.1.py"
fi
