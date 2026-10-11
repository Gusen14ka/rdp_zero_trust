#!/bin/bash
set -e
# убрать pid-файлы от прошлых запусков, иначе службы откажутся стартовать
rm -f /run/dbus/pid /var/run/xrdp/*.pid
mkdir -p /run/dbus
dbus-daemon --system --fork      # системная шина сообщений, нужна xrdp и XFCE
/usr/sbin/xrdp-sesman            # менеджер сессий: создаёт X-сервер при входе
exec /usr/sbin/xrdp --nodaemon   # сам RDP-сервер, на переднем плане