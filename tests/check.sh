#!/usr/bin/env bash
# Vérifie le lab depuis l'hôte.
# Usage : tests/check.sh [network|pc1|wazuh|agents|suricata|demo|all] ...
set -u
cd "$(dirname "$0")/.."
fail=0

# on <vm> <commande> : exécute dans la VM, sortie sans \r, code de retour de la commande.
on() { vagrant ssh "$1" -c "$2" 2>/dev/null | tr -d '\r'; return "${PIPESTATUS[0]}"; }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then echo "OK   $d"; else echo "FAIL $d"; fail=1; fi; }
has() { grep -q -- "$2" <<<"$1"; }
hasF() { grep -qF -- "$2" <<<"$1"; }          # motif littéral (crochets, points…)
not() { ! "$@"; }
# ID de règle Wazuh déclenché par un événement JSON passé à wazuh-logtest (via stdin, sans imbrication de quotes).
# wazuh-logtest écrit son résultat sur stderr -> on le fusionne côté distant. sed ancré pour ignorer flow_id.
logtest_id() { printf '%s\n' "$1" | vagrant ssh wazuh -c 'sudo /var/ossec/bin/wazuh-logtest 2>&1' 2>/dev/null | tr -d '\r' | sed -nE "s/^[[:space:]]*id: '([0-9]+)'.*/\1/p" | tail -1; }
# wait_count <desc> <requête lucene> : vrai si lab-count > 0 dans les 90 s (sondage toutes les 5 s).
wait_count() {
  local d=$1 q=$2 i n
  for i in $(seq 1 18); do
    n=$(on wazuh "sudo lab-count '$q'")
    [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -gt 0 ] && { echo "OK   $d ($n)"; return 0; }
    sleep 5
  done
  echo "FAIL $d (dernier: ${n:-?})"; fail=1; return 1
}

network() {
  check "router : ip_forward actif" test "$(on router 'sysctl -n net.ipv4.ip_forward')" = 1
  for vm in pc2 wazuh; do
    check "$vm : route par défaut via le routeur" has "$(on $vm 'ip route get 1.1.1.1')" 'via 192.168.10.1'
  done
  local dns; dns=$(on pc2 'resolvectl dns')
  check "pc2 : DNS 1.1.1.1" has "$dns" 1.1.1.1
  check "pc2 : pas de DNS NAT 10.0.2.3" not has "$dns" 10.0.2.3
  check "pc2 : Internet via le routeur" test "$(on pc2 "curl -s -o /dev/null -w '%{http_code}' https://example.com")" = 200
  check "attacker : 203.0.113.1:22 ouvert (DNAT pc1)" on attacker 'nc -z -w3 203.0.113.1 22'
  check "attacker : 203.0.113.1:443 bloqué" not on attacker 'nc -z -w3 203.0.113.1 443'
  check "router : drop journalisé (FW-DROP)" on router "sudo grep -q 'FW-DROP.*SRC=203.0.113.66' /var/log/kern.log"
  check "attacker : LAN injoignable" not on attacker 'nc -z -w3 192.168.10.11 22'
  check "router : une seule règle dnat" test "$(on router "sudo nft list ruleset | grep -c 'dnat to'")" = 1
}

pc1() {
  check "attacker : site web de pc1 via 203.0.113.1" has "$(on attacker 'curl -s http://203.0.113.1')" LAB-PC1
  check "attacker : SSH admin/admin123 aboutit sur pc1" test "$(on attacker 'sshpass -p admin123 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@203.0.113.1 hostname')" = pc1
  check "attacker : outils installés" on attacker 'command -v nmap hydra nikto sshpass'
  check "attacker : admin123 en dernier dans la wordlist" test "$(on attacker 'tail -1 /home/vagrant/wordlist.txt')" = admin123
  check "attacker : wordlist de 20 mots" test "$(on attacker 'wc -l < /home/vagrant/wordlist.txt')" = 20
}

wazuh() {
  check "wazuh : 3 services actifs" test "$(on wazuh 'systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard' | grep -cx active)" = 3
  check "hôte : dashboard sur https://localhost:8443" test "$(curl -skL -o /dev/null -w '%{http_code}' https://localhost:8443/app/login)" = 200
  check "wazuh : lab-count renvoie un entier" bash -c '[[ "$(vagrant ssh wazuh -c "sudo lab-count \"*\"" 2>/dev/null | tr -d "\r")" =~ ^[0-9]+$ ]]'
}

agents() {
  local l; l=$(on wazuh 'sudo /var/ossec/bin/agent_control -l')
  for n in router pc1 pc2; do
    check "wazuh : agent $n actif" grep -Eq "Name: $n,.*Active" <<<"$l"
  done
  check "router : eve.json surveillé une fois" test "$(on router "sudo grep -c '/var/log/suricata/eve.json' /var/ossec/etc/ossec.conf")" = 1
  check "pc1 : access.log nginx surveillé une fois" test "$(on pc1 "sudo grep -c '/var/log/nginx/access.log' /var/ossec/etc/ossec.conf")" = 1
}

suricata() {
  check "router : suricata actif" test "$(on router 'systemctl is-active suricata')" = active
  check "router : HOME_NET correct" hasF "$(on router 'sudo suricata --dump-config 2>/dev/null')" 'vars.address-groups.HOME_NET = [192.168.10.0/24,203.0.113.1/32]'
  local flow dns
  flow='{"timestamp":"2026-11-21T10:00:00.000000+0000","flow_id":1,"event_type":"flow","src_ip":"192.168.10.12","src_port":40000,"dest_ip":"1.1.1.1","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":1}}'
  dns='{"timestamp":"2026-11-21T10:00:00.000000+0000","flow_id":2,"event_type":"dns","src_ip":"192.168.10.12","dest_ip":"1.1.1.1","proto":"UDP","dns":{"type":"query","rrname":"example.com"}}'
  check "wazuh : règle flow 100101 niveau 3" test "$(logtest_id "$flow")" = 100101
  check "wazuh : règle dns 100100 niveau 3" test "$(logtest_id "$dns")" = 100100
  # Trafic normal (DNS indexé via 100100) + une alerte Suricata déterministe : un User-Agent APT
  # déclenche la règle ET INFO côté WAN ; l'agent du routeur lit eve.json en continu (nouvelles lignes).
  on pc2 'curl -s -m10 https://example.com' >/dev/null 2>&1
  on attacker 'curl -s -m10 http://203.0.113.1/uid' >/dev/null 2>&1
  wait_count "trafic DNS indexé" 'agent.name:router AND rule.id:100100 AND data.event_type:dns'
  wait_count "alerte Suricata de bout en bout" 'agent.name:router AND rule.id:86601'
}

demo() {
  echo "-- scan nmap --"
  on attacker 'sudo nmap -sS -sV -sC -p 22,80,443,1433,3306,3389 203.0.113.1' >/dev/null 2>&1
  wait_count "scan détecté (Suricata)" 'rule.id:86601 AND data.src_ip:203.0.113.66'
  check "router : scan journalisé par le pare-feu" on router "sudo grep -q 'FW-DROP.*SRC=203.0.113.66' /var/log/kern.log"

  echo "-- brute force SSH (hydra) --"
  on attacker 'hydra -l admin -P /home/vagrant/wordlist.txt -t 4 -f ssh://203.0.113.1' >/dev/null 2>&1
  wait_count "échecs SSH (pc1)" 'agent.name:pc1 AND rule.groups:authentication_failed AND data.srcip:203.0.113.66'
  wait_count "brute force détecté (pc1)" 'agent.name:pc1 AND rule.groups:authentication_failures'
  # Succès après brute force : la règle composite 40112 (if_group authentication_success +
  # if_matched_group authentication_failures) remplace le simple 5715 et porte l'IP de l'attaquant.
  wait_count "connexion réussie après brute force (pc1)" 'agent.name:pc1 AND rule.id:40112 AND data.srcip:203.0.113.66'

  echo "-- scan web (nikto) --"
  on attacker 'nikto -h http://203.0.113.1 -maxtime 60s' >/dev/null 2>&1
  wait_count "attaque web vue par pc1" 'agent.name:pc1 AND rule.groups:web AND data.srcip:203.0.113.66'
  wait_count "attaque web vue par Suricata" 'agent.name:router AND rule.id:86601 AND data.dest_port:80'
}

set -- "${@:-all}"
[ "$1" = all ] && set -- network pc1 wazuh agents suricata demo
for s in "$@"; do echo "== $s"; "$s"; done
exit $fail
