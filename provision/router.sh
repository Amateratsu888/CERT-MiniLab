#!/usr/bin/env bash
# Routeur : routage, NAT vers la carte NAT Vagrant (vrai Internet), DNAT 22/80 vers pc1, pare-feu nftables.
set -euo pipefail

# Interface qui porte l'IP $1 (les noms enp0s… varient selon la box).
iface() { ip -o -4 addr show | awk -v ip="$1/" 'index($4, ip) == 1 {print $2}'; }
NATIF=$(iface 10.0.2.15)
WAN=$(iface 203.0.113.1)
LAN=$(iface 192.168.10.1)

echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-lab.conf
sysctl -q -p /etc/sysctl.d/99-lab.conf

command -v nft >/dev/null || { apt-get update -q; apt-get install -yq nftables; }
cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet lab {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    iifname != "$WAN" accept
    log prefix "FW-DROP " drop
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "$LAN" accept
    iifname "$WAN" ip daddr 192.168.10.11 tcp dport { 22, 80 } ct status dnat accept
    log prefix "FW-DROP " drop
  }
}

table ip labnat {
  chain prerouting {
    type nat hook prerouting priority -100;
    iifname "$WAN" ip daddr 203.0.113.1 tcp dport { 22, 80 } dnat to 192.168.10.11
  }
  chain postrouting {
    type nat hook postrouting priority 100;
    oifname "$NATIF" masquerade
  }
}
EOF
systemctl enable -q nftables
nft -f /etc/nftables.conf

# ---- Suricata : IDS réseau sur les deux interfaces (WAN = attaques, LAN = trafic des postes) ----
if ! command -v suricata >/dev/null; then
  apt-get update -q
  apt-get install -yq suricata
fi

# HOME_NET : l'IP publique du routeur doit être DANS le réseau surveillé, sinon les règles
# $EXTERNAL_NET -> $HOME_NET ne matchent pas les scans de l'attaquant. On édite la ligne
# active en place (sed ciblé) pour préserver le reste de vars (port-groups, autres groupes).
sed -i 's|^    HOME_NET:.*|    HOME_NET: "[192.168.10.0/24,203.0.113.1/32]"|' /etc/suricata/suricata.yaml

# Surcouche appliquée via `include` (en dernier = prioritaire). On n'y met QUE af-packet et
# outputs : l'include remplace le sous-arbre entier, donc redéfinir `vars` effacerait les
# port-groups par défaut. Suricata exige l'en-tête %YAML sur un fichier inclus.
cat > /etc/suricata/lab.yaml <<EOF
%YAML 1.1
---
af-packet:
  # checksum-checks: no — sous VirtualBox l'offload réseau produit de faux checksums
  # que Suricata rejetterait sinon. cluster-id distinct par interface.
  - interface: $WAN
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    checksum-checks: no
  - interface: $LAN
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
    checksum-checks: no

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - ssh
        - flow
EOF

grep -qxF 'include: /etc/suricata/lab.yaml' /etc/suricata/suricata.yaml \
  || echo 'include: /etc/suricata/lab.yaml' >> /etc/suricata/suricata.yaml

suricata-update --no-test 2>/dev/null || suricata-update

# Valider la config avant de (re)démarrer.
suricata -T -c /etc/suricata/suricata.yaml >/dev/null
systemctl enable -q suricata
systemctl restart suricata

echo "Routeur prêt : WAN=$WAN LAN=$LAN sortie=$NATIF (+ Suricata)"
