#!/bin/bash
# Archives softhsm-gsm.log under a timestamped name instead of
# letting it be truncated/lost. Run by softhsm2-gsm.service as
# ExecStopPost= on every stop (manual stop, restart, or crash-restart).
# StandardOutput/StandardError use append: mode, which creates a fresh
# file at the original path the next time the service starts.
set -euo pipefail

LOG_FILE=/opt/softhsm2/logs/softhsm-gsm.log

if [ -s "$LOG_FILE" ]; then
    mv "$LOG_FILE" "${LOG_FILE%.log}-$(date +%Y%m%dT%H%M%S).log"
fi
