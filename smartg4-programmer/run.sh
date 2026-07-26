#!/usr/bin/with-contenv bashio
# Read add-on options and launch the ingress server.
export SMARTG4_GATEWAY="$(bashio::config 'gateway')"
export SMARTG4_SUBNET="$(bashio::config 'bus_subnet')"
export SMARTG4_DEVICE="$(bashio::config 'bus_device')"
export SMARTG4_BACKUP_DIR="/share/smartg4"
export SMARTG4_ENABLE_FLASH_WRITE="$(bashio::config 'enable_flash_write')"

bashio::log.info "Starting Smart-G4 Builder (gateway ${SMARTG4_GATEWAY})"
exec python3 /app/server.py
