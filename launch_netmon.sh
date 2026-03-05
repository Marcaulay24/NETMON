#!/bin/bash
# 🛡️ NETMON PRO v2.1 Launcher - Robust GUI Edition

# Get absolute path of the script directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

# Ensure X11 environment is preserved
export DISPLAY="${DISPLAY:-:0}"
export XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}"

# Ask for password graphically
PASSWORD=$(zenity --password --title="🛡️ NetMon PRO Security Authorization" --text="Enter sudo password to enable advanced monitoring:")

if [ $? -eq 0 ] && [ -n "$PASSWORD" ]; then
    # Launch with sudo -S (stdin) and -E (preserve env for GUI)
    echo "$PASSWORD" | sudo -S -E python3 netmonv2.1.py
else
    # User cancelled or empty password
    zenity --error --text="Authorization failed or cancelled. Application cannot start without root privileges." --title="Error"
    exit 1
fi
