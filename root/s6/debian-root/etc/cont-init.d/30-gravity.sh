#!/usr/bin/with-contenv bash

# Update gravity block lists
bash -eu pihole -g

# s6 doesn't like it when pihole-FTL is running when s6 services start
kill -9 $(pgrep pihole-FTL) || echo "pihole-FTL not already running"

# Print version number
pihole -v
