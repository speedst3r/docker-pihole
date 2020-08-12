#!/bin/bash -ex
#
# Download web installer script, prepare environment for unattended install, and run it
#
mkdir -p /etc/pihole
mkdir -p /var/run/pihole

# Without this, debconf will try to talk to us
ln -s `which echo` /usr/local/bin/whiptail

# debconf-apt-progress seems to hang so get rid of it too
mv -f "$(which debconf-apt-progress)"{,.disabled}

# curl in armhf-buster's image has SSL issues. Running c_rehash fixes it.
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=923479
c_rehash

case "$TARGETPLATFORM" in
  *386)    S6_ARCH=x86     ;;
  *arm64)  S6_ARCH=aarch64 ;;
  *arm)    S6_ARCH=arm     ;; # armhf
  *arm/v7) S6_ARCH=arm     ;; # armhf
  *arm/v6) S6_ARCH=arm     ;; # armel
  *amd64)  S6_ARCH=amd64   ;;
  *) >&2 echo "unhandled case: ${TARGETPLATFORM}"; exit 1 ;;
esac

S6OVERLAY_RELEASE="https://github.com/just-containers/s6-overlay/releases/download/${S6_VERSION}/s6-overlay-${S6_ARCH}.tar.gz"
curl -4 -L -s $S6OVERLAY_RELEASE | tar xvzf - -C /
mv /init /s6-init

# Get the install functions
curl -o /install.sh \
  "https://raw.githubusercontent.com/pi-hole/pi-hole/${PIHOLE_CORE_VERSION}/automated%20install/basic-install.sh"

# This defines a bunch of crap in our namespace
# PH_TEST=true . /install.sh

{ echo "PIHOLE_INTERFACE=eth0"
  echo "IPV4_ADDRESS=0.0.0.0"
  echo "IPV6_ADDRESS=0:0:0:0:0:0"
  echo "PIHOLE_DNS_1=8.8.8.8"
  echo "PIHOLE_DNS_2=8.8.4.4"
  echo "QUERY_LOGGING=true"
  echo "INSTALL_WEB_SERVER=true"
  echo "INSTALL_WEB_INTERFACE=true"
  echo "LIGHTTPD_ENABLED=true"
} >> /etc/pihole/setupVars.conf
source /etc/pihole/setupVars.conf

# Fix permission denied to resolvconf post-inst /etc/resolv.conf moby/moby issue #1297
echo resolvconf resolvconf/linkify-resolvconf boolean false | debconf-set-selections

# Pretend we have systemd
echo "${PIHOLE_FTL_VERSION}" > /etc/pihole/ftlbranch

# FIRE IN THE HOLE
bash -ex /install.sh --unattended

# fetch_release_metadata() {
#     local directory="$1"
#     local version="$2"
#     pushd "$directory"
#     git fetch -t
#     git remote set-branches origin '*'
#     git fetch --depth 1
#     git checkout master
#     git reset --hard "$version"
#     popd
# }

# Web installer script fetches from master, so we'll switch to the specified version
# fetch_release_metadata /etc/.pihole        "${PIHOLE_CORE_VERSION}"
# fetch_release_metadata /var/www/html/admin "${PIHOLE_WEB_VERSION}"

sed -i 's/readonly //g' /opt/pihole/webpage.sh
sed -i '/^WEBPASSWORD/d' /etc/pihole/setupVars.conf

# Replace the call to `updatePiholeFunc` in arg parse with new `unsupportedFunc`
sed -i $'s/helpFunc() {/unsupportedFunc() {\\\n  echo "Function not supported in Docker images"\\\n  exit 0\\\n}\\\n\\\nhelpFunc() {/g' /usr/local/bin/pihole
sed -i $'s/)\s*updatePiholeFunc/) unsupportedFunc/g' /usr/local/bin/pihole

touch /.piholeFirstBoot
echo Docker install successful
