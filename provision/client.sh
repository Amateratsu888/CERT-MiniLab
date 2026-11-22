#!/usr/bin/env bash
# Machines du LAN : tout leur trafic (Internet, DNS) passe par le routeur.
# La carte NAT Vagrant reste pour `vagrant ssh` mais ne sert plus de route ni de DNS.
set -euo pipefail

ping -c1 -W3 192.168.10.1 >/dev/null || { echo "Le routeur doit être démarré (vagrant up router)"; exit 1; }

iface() { ip -o -4 addr show | awk -v ip="$1/" 'index($4, ip) == 1 {print $2}'; }
NATIF=$(iface 10.0.2.15)
LANIF=$(ip -o -4 addr show | awk '$4 ~ /^192\.168\.10\./ {print $2}')

cat > /etc/netplan/60-lab.yaml <<EOF
network:
  version: 2
  ethernets:
    $NATIF:
      dhcp4-overrides: { use-routes: false, use-dns: false }
    $LANIF:
      routes: [{ to: default, via: 192.168.10.1 }]
      nameservers: { addresses: [1.1.1.1] }
EOF
chmod 600 /etc/netplan/60-lab.yaml
ip route replace default via 192.168.10.1
netplan apply
echo "Route par défaut et DNS via le routeur ($LANIF)"
