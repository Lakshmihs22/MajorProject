#!/bin/sh
mkdir -p /var/log/suricata
suricata -c /etc/suricata/suricata.yaml -i eth0 -D --pidfile /var/run/suricata.pid
sleep 2
exec python -u src/sensor_agent.py