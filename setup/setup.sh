#!/bin/sh

# Upgrade of an installation made before the OptiRadar rename (/opt/traccar, traccar.service):
# move it as a whole, so its configuration, H2 database (data/) and logs come along unchanged.
if [ -d /opt/traccar ] && [ ! -e /opt/optiradar ]
then
    systemctl stop traccar.service 2>/dev/null
    systemctl disable traccar.service 2>/dev/null
    rm -f /etc/systemd/system/traccar.service
    mv /opt/traccar /opt/optiradar
    if [ -f /opt/optiradar/conf/traccar.xml ] && [ ! -f /opt/optiradar/conf/optiradar.xml ]
    then
        mv /opt/optiradar/conf/traccar.xml /opt/optiradar/conf/optiradar.xml
    fi
fi

PRESERVECONFIG=0
if [ -f /opt/optiradar/conf/optiradar.xml ]
then
    cp /opt/optiradar/conf/optiradar.xml /opt/optiradar/conf/optiradar.xml.saved
    PRESERVECONFIG=1
fi

mkdir -p /opt/optiradar
cp -r * /opt/optiradar
chmod -R go+rX /opt/optiradar

if [ ${PRESERVECONFIG} -eq 1 ] && [ -f /opt/optiradar/conf/optiradar.xml.saved ]
then
    mv -f /opt/optiradar/conf/optiradar.xml.saved /opt/optiradar/conf/optiradar.xml
fi

mv /opt/optiradar/optiradar.service /etc/systemd/system
chmod 664 /etc/systemd/system/optiradar.service

systemctl daemon-reload
systemctl enable optiradar.service

rm /opt/optiradar/setup.sh
rm -r ../out
