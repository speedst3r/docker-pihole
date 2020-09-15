#!/bin/bash
set -eu

# reown <user|group> [NAME] [NEW ID]
function reown {
    kind="$1"
    name="$2"
    new="$3"

    case "$kind" in
        user)
            old=$(getent passwd "$name" | cut -d: -f3)
            own="chown"
            mod="usermod -o -u"
            ;;
        group)
            old=$(getent group "$name" | cut -d: -f3)
            own="chgrp"
            mod="groupmod -o -g"
            ;;
        *)
            echo "bad argument" >/dev/stderr
            exit 1
            ;;
    esac

    if [ $old -eq $new ]; then
        echo "not changing id of $kind $name, it already matches host"
        return
    fi

    echo "changing id of $kind $name from $old to $new"
    $mod $new $name

    for path in $(find / "-$kind" "$old" 2>/dev/null); do
        echo "fixing ownership of $path"
        $own "$name" "$path"
    done
}

[[ -n ${WWWDATA_UID+x} ]] || WWWDATA_UID=$(getent passwd www-data | cut -d: -f3)
[[ -n ${PIHOLE_UID+x}  ]] || PIHOLE_UID=$(getent passwd pihole    | cut -d: -f3)
if [[ "$WWWDATA_UID" -eq "$PIHOLE_UID" ]]; then
    echo "www-data uid must be different from pihole uid ($PIHOLE_UID)"
    exit 1
fi

reown user  www-data ${WWWDATA_UID}
reown group www-data ${WWWDATA_GID}

reown user  pihole ${PIHOLE_UID}
reown group pihole ${PIHOLE_GID}

