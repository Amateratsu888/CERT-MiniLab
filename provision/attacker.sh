#!/usr/bin/env bash
# Attaquant externe : outils de scan et de brute force + petite wordlist.
set -euo pipefail

apt-get update -q
apt-get install -yq nmap hydra nikto sshpass

# admin123 en dernier : au moins 8 échecs avant le succès, pour déclencher la règle « brute force » de Wazuh.
cat > /home/vagrant/wordlist.txt <<'EOF'
123456
password
123456789
12345678
qwerty
azerty
111111
letmein
welcome
monkey
dragon
football
iloveyou
admin
root
toor
changeme
password1
P@ssw0rd
admin123
EOF
chown vagrant: /home/vagrant/wordlist.txt
echo "attacker prêt : nmap, hydra, nikto, ~/wordlist.txt"
