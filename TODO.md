* [x] Detect when UID and GID match between host and container, skip reown process
* [x] Disable CHAOS TXT records in .bind, .ftl, and .pihole domains (patch submitted to upstream repo)
* [ ] Write `$PIHOLE_WEB_HOSTNAME` to /etc/pihole/custom.list
* [ ] Fix cron issues, logrotate
* [ ] Further restrict /etc/sudoers.d/pihole 
* [ ] Reduce image size where possible
* [ ] Script to synchronize gravity.db across containers
* [ ] Test docker builds on GitHub before publishing
* [ ] Implement LAN forwarding
* [ ] Example script to export DHCP lease information from dhcpd3 server
* [ ] Support for DNS-over-TLS
* [ ] Support for DNS-over-HTTPS
* [ ] Block page issues
  * [ ] Support HTTPS for admin and blocked pages
  * [ ] Admin page listen on separate port than block page
