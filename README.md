# Docker Pi-hole

<p align="center">
<a href="https://pi-hole.net"><img src="https://pi-hole.github.io/graphics/Vortex/Vortex_with_text.png" width="150" height="255" alt="Pi-hole"></a><br/>
</p>


## Overview

A [Docker project](https://www.docker.com/what-docker) to make a lightweight x86 or ARM container with [Pi-hole](https://pi-hole.net/) functinnality.

[![build status](https://github.com/rndnoise/docker-pi-hole/workflows/buildx/badge.svg)](https://github.com/rndnoise/docker-pi-hole/actions?query=workflow%3Abuildx)

## Quick start

Here's an example `docker-compose.yml`:

```yaml
version: "3"

services:
  pihole:
    container_name: pihole
    image: example/pihole:latest
    ports:
      - "80:80/tcp"
      - "53:53/tcp"
      - "53:53/udp"
    restart: unless-stopped
    environment:
      TZ: America/Chicago
      PUID: 999
      PGID: 999
      PIHOLE_IPV4_ADDRESS: "0.0.0.0"
      PIHOLE_IPV6_ADDRESS: "::"
      PIHOLE_WEB_PASSWORD: "the password is password"
      PIHOLE_WEB_HOSTNAME: "pi.hole"
      PIHOLE_DNS_UPSTREAM_1: 1.1.1.1
      PIHOLE_DNS_UPSTREAM_2: 1.0.0.1
      PIHOLE_DNS_UPSTREAM_3: 8.8.8.8
      PIHOLE_DNS_UPSTREAM_4: 9.9.9.9
    volumes:
      - ./pihole/var-log:/var/log
      - ./pihole/etc-pihole:/etc/pihole
      - ./pihole/etc-dnsmasq.d:/etc/dnsmasq.d
```

Here's an equivalent `docker run` command:

```sh
docker run \
  --detach \
  --name pihole \
  --restart=unless-stopped \
  --publish 53:53/udp \
  --publish 53:53/tcp \
  --publish 80:80/tcp \
  --env "TZ=America/Chicago" \
  --env "PUID=999" \
  --env "PGID=999" \
  --env "PIHOLE_IPV4_ADDRESS=0.0.0.0" \
  --env "PIHOLE_IPV6_ADDRESS=::" \
  --env "PIHOLE_WEB_PASSWORD=the password is password" \
  --env "PIHOLE_WEB_HOSTNAME=pi.hole" \
  --env "PIHOLE_DNS_UPSTREAM_1=1.1.1.1" \
  --env "PIHOLE_DNS_UPSTREAM_2=1.0.0.1" \
  --env "PIHOLE_DNS_UPSTREAM_3=8.8.8.8" \
  --env "PIHOLE_DNS_UPSTREAM_4=9.9.9.9" \
  --volume "$(pwd)/pihole/var-log:/var/log" \
  --volume "$(pwd)/pihole/etc-pihole:/etc/pihole" \
  --volume "$(pwd)/pihole/etc-dnsmasq.d:/etc/dnsmasq.d"
  example/pihole:latest
```

## Environment variables

| Environment variable name     | Required | Default | Values      | Description |
| ----------------------------- | -------- | ------- | ----------- | ----------- |
| `PIHOLE_ADMIN_EMAIL`            | No       |         |             | Set an administrative contact address on the block page
| `PIHOLE_DNS_BLOCKING_MODE`      | No       | `NULL`    | [See docs](https://docs.pi-hole.net/ftldns/blockingmode/)    | Method used to block queries
| `PIHOLE_DNS_BOGUS_PRIV`         | No       | `true`    | `true`, `false` | Forward reverse lookups on private ranges to upstream servers
| `PIHOLE_DNS_CNAME_INSPECT`      | No       | `true`    | `true`, `false` | Enable or disable deep CNAME inspection. See [PR #663](https://github.com/pi-hole/FTL/pull/663)
| `PIHOLE_DNS_DNSSEC`             | No       | `false`   | `true`, `false` | Enable or disable DNSSEC
| `PIHOLE_DNS_FQDN_REQUIRED`      | No       | `true`    | `true`, `false` | Forward queries on non-FQDNs to upstream servers
| `PIHOLE_DNS_IGNORE_LOCALHOST`   | No       | `false`   | `true`, `false` | Ignore queries originating from the local machine
| `PIHOLE_DNS_LAN_DOMAIN`         | No       |         |             | When LAN forwarding is enabled, forward queries for this domain to upstream LAN DNS server
| `PIHOLE_DNS_LAN_ENABLE`         | No       | `false`   | `true`, `false` | Enable or disable forwarding queries for LAN to a separate DNS server
| `PIHOLE_DNS_LAN_NETWORK`        | No       |         | CIDR IPv4 or IPv6   | When LAN forwarding is enabled, forward reverse queries for this network range to upstream LAN DNS server
| `PIHOLE_DNS_LAN_UPSTREAM`       | No       |         |             | When LAN forwarding is enabled, use this DNS server to resolve LAN queries
| `PIHOLE_DNS_PRIVACY_LVL`        | No       | `0`       | [See docs](https://docs.pi-hole.net/ftldns/privacylevels/)    | Specifies level of detail given in Pi-hole statistics.
| `PIHOLE_DNS_UPSTREAM_1`         | Yes      | `0.0.0.0` | IPv4/6 addr | Primary upstream DNS server
| `PIHOLE_DNS_UPSTREAM_2`         | No       |         | IPv4/6 addr | Secondary upstream DNS server
| `PIHOLE_DNS_UPSTREAM_3`         | No       |         | IPv4/6 addr | Tertiary upstream DNS server
| `PIHOLE_DNS_UPSTREAM_4`         | No       |         | IPv4/6 addr | Quaternary upstream DNS server
| `PIHOLE_DNS_USER`               | No       | `pihole`  |             | User which runs `pihole-FTL` (can be `root`)
| `PIHOLE_IPV4_ADDRESS`           | No       | `0.0.0.0`, `auto`, IPv4 addr | Your Pi-hole's address, used to redirect/block requests
| `PIHOLE_IPV6_ADDRESS`           | No       | `::`, `auto`, IPv6 addr   | Your Pi-hole's address, used to redirect/block requests
| `PIHOLE_LISTEN`                 | No       | `all`     | `all`, `iface`, `local` | 
| `PIHOLE_INTERFACE`              | No       |         |             | When `PIHOLE_LISTEN` is `iface`, specifies the interface used to listen for DNS queries and HTTP requests
| `PIHOLE_TEMPERATURE_UNIT`       | No       | `F`       | `F`, `C`, `K`     |
| `PIHOLE_WEB_HOSTNAME`           | No       | `\`hostname -f\`` |     | The hostname used to access the Pi-hole admin page
| `PIHOLE_WEB_PASSWORD`           | No       | randomized |          | The password required to access the Pi-hole admin page. See `pihole logs pihole` to find the randomized password
| `PIHOLE_WEB_PASSWORD_FILE`      | No       |         |             | Filename containing password, will override `PIHOLE_PASSWORD` if it's set.
| `PIHOLE_WEB_PORT`               | No       | `80`      |             | Which port the admin page is listening on
| `PIHOLE_WEB_UI`                 | No       | `boxed`   | `boxed`, `traditional` | | Which layout is used for the admin page

## Tips and tricks

## Docker tags and versioning

## Upgrading

## Upgrade notices

## Running DHCP from Docker Pi-hole

This docker image doesn't support configuring FTLDNS as a DHCP server. Instead, you can either use `PIHOLE_DNS_LAN_...` configuration to forward LAN traffic to your DHCP server/router, or write a script to export data from your DHCP server to a host file and drop a config file in `/etc/dnsmasq.d/` to tell FTLDNS about that file. Changes to that file will auttomatically be detected without restarting FTLDNS.

```
local=/lan/                   # answer queries from this domain using host files
hostsdir=/etc/dnsmasq.d/lan   # files in thtis directory will be used as host files
```
