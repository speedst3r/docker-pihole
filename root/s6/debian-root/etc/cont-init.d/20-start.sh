#!/usr/bin/with-contenv bash
set -eux

# Write config from ENV to config files
perl -W /startup.pl
bash -eu pihole -g

# s6 doesn't like it when pihole-FTL is running when s6 services start
kill -9 $(pgrep pihole-FTL) || true

# Print version number
pihole -v
