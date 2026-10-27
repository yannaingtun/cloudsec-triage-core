#!/usr/bin/env bash
# Stop a container before the hardware stops the machine.
#
# This is a mitigation for a cooling fault, not a fix. GB10 exposes no power
# limit and no nvpmodel, so nothing here reduces heat; it only ends the load
# earlier and more gracefully than a firmware thermal trip, which cuts power
# with no chance to flush a write.
#
#   scripts/thermal_watch.sh cloudsec-serve
#   STOP_AT=82 RESUME_AT=60 scripts/thermal_watch.sh cloudsec-serve
#
# Hysteresis is wide on purpose: stopping at 85 and restarting at 65 avoids a
# cycle where the container restarts into the same heat and trips again.
set -euo pipefail

CONTAINER="${1:?usage: thermal_watch.sh <container> [--no-resume]}"
STOP_AT="${STOP_AT:-85}"
RESUME_AT="${RESUME_AT:-65}"
INTERVAL="${INTERVAL:-10}"
OVER_SAMPLES="${OVER_SAMPLES:-3}"      # ~30s hot before acting, to ignore spikes
COOL_SAMPLES="${COOL_SAMPLES:-30}"     # ~5min cool before restarting
RESUME=1
[ "${2:-}" = "--no-resume" ] && RESUME=0

log() { printf '%s  %s\n' "$(date '+%F %T')" "$*"; }

temp() { nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader | head -1; }

log "watching $CONTAINER: stop>=${STOP_AT}C resume<=${RESUME_AT}C every ${INTERVAL}s"
over=0; cool=0; stopped_by_us=0

while true; do
  t="$(temp || echo "")"
  if [ -z "$t" ]; then
    log "cannot read temperature; not acting"
    sleep "$INTERVAL"; continue
  fi

  if docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
    cool=0
    if [ "$t" -ge "$STOP_AT" ]; then
      over=$((over + 1))
      log "${t}C over limit (${over}/${OVER_SAMPLES})"
      if [ "$over" -ge "$OVER_SAMPLES" ]; then
        log "stopping $CONTAINER at ${t}C"
        docker stop "$CONTAINER" >/dev/null && stopped_by_us=1
        over=0
      fi
    else
      over=0
    fi
  else
    over=0
    if [ "$RESUME" -eq 1 ] && [ "$stopped_by_us" -eq 1 ]; then
      if [ "$t" -le "$RESUME_AT" ]; then
        cool=$((cool + 1))
        [ $((cool % 6)) -eq 0 ] && log "${t}C cool (${cool}/${COOL_SAMPLES})"
        if [ "$cool" -ge "$COOL_SAMPLES" ]; then
          log "restarting $CONTAINER at ${t}C"
          docker start "$CONTAINER" >/dev/null && stopped_by_us=0
          cool=0
        fi
      else
        cool=0
      fi
    fi
  fi
  sleep "$INTERVAL"
done
