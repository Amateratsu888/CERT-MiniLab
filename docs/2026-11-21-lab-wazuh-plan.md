# Lab réseau d'entreprise + Wazuh — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** un `vagrant up` monte 5 VMs ARM sur VirtualBox (routeur + Suricata, serveur Wazuh, 2 postes, attaquant externe), et l'attaque est visible dans le dashboard Wazuh sur `https://localhost:8443`.

**Architecture :** un `Vagrantfile` unique et des scripts shell de provisioning, un par rôle. Deux réseaux internes VirtualBox (`wan`, `lan`). Le routeur Ubuntu fait le NAT, le DNAT et le pare-feu avec nftables, et fait tourner Suricata. Wazuh est installé all-in-one par le script officiel. Les tests sont un script hôte `tests/check.sh`, découpé en sections, qui interroge les VMs via `vagrant ssh`. Chaque tâche écrit d'abord sa section de test (qui échoue), puis le provisioning qui la fait passer.

**Tech Stack :** Vagrant 2.4.9, VirtualBox 7.2.22 (hôte Apple Silicon), box `bento/ubuntu-24.04` arm64, nftables, Suricata (paquet Ubuntu), Wazuh 4.14.10, bash.

**Spec :** `docs/2026-11-21-lab-wazuh-design.md`

## Global Constraints

- Box `bento/ubuntu-24.04`, `config.vm.box_architecture = "arm64"`, provider VirtualBox, pour les 5 VMs.
- Wazuh 4.14.10 : script `https://packages.wazuh.com/4.14/wazuh-install.sh`, agent épinglé `wazuh-agent=4.14.10-1` (dépôt `https://packages.wazuh.com/4.x/apt/ stable main`).
- Réseaux internes VirtualBox (`virtualbox__intnet`) : `wan` = 203.0.113.0/24, `lan` = 192.168.10.0/24.
- IPs : router WAN 203.0.113.1 / LAN 192.168.10.1, wazuh 192.168.10.10, pc1 192.168.10.11, pc2 192.168.10.12, attacker 203.0.113.66.
- RAM/CPU : router 1 Go/1, wazuh 6 Go/2, pc1 1 Go/1, pc2 1 Go/1, attacker 1 Go/1.
- Ordre de définition dans le `Vagrantfile` : router, wazuh, pc1, pc2, attacker.
- Dashboard : port invité 443 → hôte 8443, sans `auto_correct` (l'URL ne doit pas changer).
- DNS des VMs du LAN : 1.1.1.1. Le DNS DHCP de la carte NAT (10.0.2.3) est ignoré.
- pc1 : compte `admin` / `admin123`, `PasswordAuthentication yes`.
- Préfixe de log du pare-feu : `FW-DROP `.
- Dossier synchronisé `/vagrant` désactivé.
- Les noms d'interfaces sont toujours détectés par IP (`ip -o -4 addr`), jamais codés en dur.
- Chaque script de provisioning est idempotent : on doit pouvoir le relancer sans erreur ni doublon.
- Les messages des scripts et le README sont en français.
- Le dossier n'est pas un dépôt git : pas d'étape de commit (l'utilisateur committe s'il le demande).

## Review Focus

1. **Relancer `vagrant provision`** (ou un `vagrant up` après un échec) : aucun doublon de règle nft ni de `localfile`, et pas de réinstallation de Wazuh. Tests : Task 1 step 5, Task 3 step 5, Task 4 step 4.
2. **Redémarrer les VMs** (`vagrant halt` puis `vagrant up`, ou un reboot du Mac) : routes, DNS, nftables, `ip_forward` et Suricata reviennent seuls. Tests : Task 1 step 6, Task 5 step 5.
3. **Agent du routeur provisionné avant que le manager existe** (le routeur démarre en premier) : il s'enrôle tout seul une fois wazuh démarré. Test : Task 4 step 3.
4. **Poste provisionné alors que le routeur est éteint** : le provisioning échoue tout de suite avec `Le routeur doit être démarré (vagrant up router)`, au lieu d'un échec apt obscur. Test : Task 1 step 7.
5. **Service Wazuh arrêté** (crash, reboot raté) : `vagrant provision wazuh` le relance sans réinstaller et sans changer le mot de passe. Test : Task 3 step 6.

---

### Task 1 : réseau (Vagrantfile, routeur, postes)

**Files :**
- Create : `Vagrantfile`, `provision/router.sh`, `provision/client.sh`
- Test : `tests/check.sh` (sections `network`, helpers)

**Interfaces :**
- Produces :
  - les VMs `router`, `wazuh`, `pc1`, `pc2`, `attacker`, avec les ressources et IPs des Global Constraints.
  - Provisioners shell nommés (pour `--provision-with`) : `router` (sur router), `client` (sur wazuh, pc1, pc2).
  - `tests/check.sh [network|pc1|wazuh|agents|suricata|demo|all]`, avec les helpers `on <vm> <cmd>` (= `vagrant ssh <vm> -c <cmd>`, stderr ignoré), `check <desc> <cmd...>` (affiche `OK`/`FAIL`, met `fail=1`) et `wait_count <desc> <requête lucene>` (défini en Task 3). Code de sortie : 0 si tout passe.
  - Dans `router.sh`, les variables `NATIF`, `WAN`, `LAN`, détectées par IP (10.0.2.15, 203.0.113.1, 192.168.10.1).

- [ ] **Step 1 : écrire `tests/check.sh` avec la section `network`**

  Assertions :
  - `on router 'sysctl -n net.ipv4.ip_forward'` = `1`
  - `on pc2 'ip route get 1.1.1.1'` contient `via 192.168.10.1` (idem `wazuh`)
  - `on pc2 'resolvectl dns'` contient `1.1.1.1` et ne contient pas `10.0.2.3`
  - `on pc2 "curl -s -o /dev/null -w '%{http_code}' https://example.com"` = `200`
  - `on attacker 'nc -z -w3 203.0.113.1 22'` réussit (DNAT vers le sshd de pc1)
  - `on attacker 'nc -z -w3 203.0.113.1 443'` échoue, puis `on router "sudo grep -q 'FW-DROP.*SRC=203.0.113.66' /var/log/kern.log"` réussit
  - `on attacker 'nc -z -w3 192.168.10.11 22'` échoue (l'attaquant ne voit pas le LAN)
  - `on router 'sudo nft list ruleset | grep -c dnat'` = `1`

- [ ] **Step 2 : lancer `tests/check.sh network`.** Attendu : FAIL (aucune VM).

- [ ] **Step 3 : écrire `Vagrantfile`, `provision/router.sh` et `provision/client.sh`**

  `Vagrantfile` : boucle ou définitions simples, `vb.memory`/`vb.cpus`, `config.vm.hostname`, `private_network` avec `virtualbox__intnet` (le routeur a les deux), `synced_folder ".", "/vagrant", disabled: true`. Le port forward 443→8443 est déjà présent sur wazuh.

  `router.sh` : `net.ipv4.ip_forward=1` dans `/etc/sysctl.d/99-lab.conf`, et `/etc/nftables.conf` généré avec les interfaces détectées (réécrit à chaque run, ce qui le rend idempotent), puis `systemctl enable --now nftables` et `nft -f`. Ruleset attendu :

  ```
  table inet lab {
    chain input   { type filter hook input priority 0; policy drop;
                    iif lo accept; ct state established,related accept
                    iifname != "$WAN" accept
                    log prefix "FW-DROP " drop }
    chain forward { type filter hook forward priority 0; policy drop;
                    ct state established,related accept
                    iifname "$LAN" accept
                    iifname "$WAN" ip daddr 192.168.10.11 tcp dport {22,80} ct status dnat accept
                    log prefix "FW-DROP " drop }
  }
  table ip labnat {
    chain prerouting  { type nat hook prerouting priority -100;
                        iifname "$WAN" ip daddr 203.0.113.1 tcp dport {22,80} dnat to 192.168.10.11 }
    chain postrouting { type nat hook postrouting priority 100; oifname "$NATIF" masquerade }
  }
  ```
  `nftables.conf` commence par `flush ruleset`.

  `client.sh` : d'abord `ping -c1 -W3 192.168.10.1`, sinon `echo "Le routeur doit être démarré (vagrant up router)"` et `exit 1`. Ensuite, écrire `/etc/netplan/60-lab.yaml` (chmod 600) et lancer `netplan apply` :
  ```yaml
  network:
    version: 2
    ethernets:
      <NATIF>: { dhcp4-overrides: { use-routes: false, use-dns: false } }
      <LANIF>: { routes: [{ to: default, via: 192.168.10.1 }], nameservers: { addresses: [1.1.1.1] } }
  ```
  Si `netplan apply` coupe la session `vagrant ssh`, appliquer en plus `ip route replace default via 192.168.10.1` avant.

- [ ] **Step 4 : `vagrant up`, puis `tests/check.sh network`.** Attendu : tout OK.

- [ ] **Step 5 (idempotence) : `vagrant provision router pc2`, puis `tests/check.sh network`.** Attendu : tout OK, nombre de `dnat` toujours égal à 1.

- [ ] **Step 6 (reboot) : `vagrant reload router pc2`, puis `tests/check.sh network`.** Attendu : tout OK.

- [ ] **Step 7 (routeur absent) : `vagrant halt router && vagrant provision pc2 --provision-with client`.** Attendu : code non nul, et la sortie contient `Le routeur doit être démarré (vagrant up router)`. Terminer avec `vagrant up router`.

---

### Task 2 : services de pc1 et outils de l'attaquant

**Files :**
- Create : `provision/pc1.sh`, `provision/attacker.sh`
- Modify : `Vagrantfile` (provisioners `pc1` et `attacker`, après `client` pour pc1)
- Test : `tests/check.sh` (section `pc1`)

**Interfaces :**
- Consumes : les VMs et le DNAT de la Task 1.
- Produces : nginx sur pc1, avec une page contenant `LAB-PC1`. L'utilisateur `admin` (`admin123`) sur pc1. Sur l'attaquant : `nmap`, `hydra`, `nikto`, `sshpass`, et `/home/vagrant/wordlist.txt` (20 mots de passe, `admin123` en **dernier**, pour que la règle brute force de Wazuh, déclenchée à 8 échecs, se déclenche avant le succès).

- [ ] **Step 1 : section `pc1` de `check.sh`**
  - `on attacker 'curl -s http://203.0.113.1'` contient `LAB-PC1`
  - `on attacker 'sshpass -p admin123 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@203.0.113.1 hostname'` = `pc1`
  - `on attacker 'command -v nmap hydra nikto sshpass'` réussit
  - `on attacker 'tail -1 /home/vagrant/wordlist.txt'` = `admin123`, et `wc -l` = 20

- [ ] **Step 2 : `tests/check.sh pc1`.** Attendu : FAIL.

- [ ] **Step 3 : écrire `pc1.sh` et `attacker.sh`**

  `pc1.sh` : `apt-get install -y nginx`, `index.html` contenant `LAB-PC1`, `id admin || useradd -m -s /bin/bash admin`, `chpasswd`, `/etc/ssh/sshd_config.d/00-lab.conf` contenant `PasswordAuthentication yes` (le préfixe `00-` gagne sur `50-cloud-init.conf`), puis `systemctl reload ssh`.

  `attacker.sh` : apt (activer `multiverse` si `nikto` est introuvable) et écriture de la wordlist.

- [ ] **Step 4 : `vagrant provision pc1 attacker`, puis `tests/check.sh pc1`.** Attendu : tout OK.

---

### Task 3 : serveur Wazuh

**Files :**
- Create : `provision/wazuh.sh`
- Modify : `Vagrantfile` (provisioner `wazuh` sur la VM wazuh, après `client`)
- Test : `tests/check.sh` (section `wazuh` et helper `wait_count`)

**Interfaces :**
- Consumes : le provisioner `client` (Task 1).
- Produces :
  - `/usr/local/bin/lab-count '<requête lucene>' [minutes=10]`, sur wazuh, à lancer avec sudo : affiche un **entier**, le nombre de documents `wazuh-alerts-*` qui correspondent à `(<requête>) AND timestamp:[now-<minutes>m TO now]`. Il interroge `https://localhost:9200/.../_count` avec le mot de passe admin lu dans `/root/wazuh-install-files.tar`.
  - `wait_count <desc> <requête>` dans `check.sh` : interroge `on wazuh "sudo lab-count '<requête>'"` toutes les 5 s pendant 90 s maximum. OK si le compte est > 0.
  - En fin de provisioning, la ligne `Mot de passe admin : <pw>`.

- [ ] **Step 1 : section `wazuh` de `check.sh`**
  - `on wazuh 'systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard'` = trois lignes `active`
  - Depuis l'hôte, `curl -skL -o /dev/null -w '%{http_code}' https://localhost:8443/app/login` = `200`
  - `on wazuh "sudo lab-count '*'"` correspond à `^[0-9]+$`

- [ ] **Step 2 : `tests/check.sh wazuh`.** Attendu : FAIL.

- [ ] **Step 3 : écrire `wazuh.sh`**

  Logique d'idempotence : si `/root/wazuh-install-files.tar` existe et que `dpkg -s` voit `wazuh-manager`, `wazuh-indexer` et `wazuh-dashboard`, on ne réinstalle pas. On fait juste `systemctl start` sur les trois. Sinon, `cd /root && curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && bash wazuh-install.sh -a -o` (le `-o` écrase une installation partielle ; ajouter `-i` seulement si la vérification matérielle bloque avec 6 Go/2 CPU). Ensuite, installer `lab-count`, puis afficher le mot de passe admin (ligne qui suit `indexer_username: 'admin'` dans `wazuh-install-files/wazuh-passwords.txt`).

- [ ] **Step 4 : `vagrant provision wazuh`, puis `tests/check.sh wazuh`.** Attendu : tout OK. Compter 10 à 20 min la première fois.

- [ ] **Step 5 (idempotence) : `vagrant provision wazuh | grep 'Mot de passe admin'`.** Attendu : la ligne est présente, avec le même mot de passe, sans réinstallation (le run doit durer moins d'une minute).

- [ ] **Step 6 (service arrêté) : `on wazuh 'sudo systemctl stop wazuh-dashboard'`, puis `vagrant provision wazuh` et `tests/check.sh wazuh`.** Attendu : tout OK, mot de passe inchangé.

---

### Task 4 : agents Wazuh (router, pc1, pc2)

**Files :**
- Create : `provision/agent.sh`
- Modify : `Vagrantfile` (provisioner `agent` sur router, pc1 et pc2, en dernier sur chaque VM)
- Test : `tests/check.sh` (section `agents`)

**Interfaces :**
- Consumes : le manager joignable sur 192.168.10.10 (Task 3).
- Produces : `agent.sh [<chemin>:<format> ...]`. Il installe `wazuh-agent=4.14.10-1` avec `WAZUH_MANAGER=192.168.10.10 WAZUH_AGENT_NAME=$(hostname)`, puis, pour chaque argument, ajoute à `/var/ossec/etc/ossec.conf` un bloc `<localfile><log_format>FORMAT</log_format><location>CHEMIN</location></localfile>`, **uniquement si** `CHEMIN` n'y figure pas déjà. Il finit par `systemctl enable --now wazuh-agent` (restart si la conf a changé).
  - router : `agent.sh /var/log/suricata/eve.json:json /var/log/kern.log:syslog`
  - pc1 : `agent.sh /var/log/nginx/access.log:apache /var/log/nginx/error.log:apache`
  - pc2 : `agent.sh`

- [ ] **Step 1 : section `agents` de `check.sh`**
  - pour `n` dans router, pc1, pc2 : `on wazuh 'sudo /var/ossec/bin/agent_control -l'` correspond à `Name: $n,.*Active`
  - `on router "sudo grep -c '/var/log/suricata/eve.json' /var/ossec/etc/ossec.conf"` = `1`
  - `on pc1 "sudo grep -c '/var/log/nginx/access.log' /var/ossec/etc/ossec.conf"` = `1`

- [ ] **Step 2 : `tests/check.sh agents`.** Attendu : FAIL.

- [ ] **Step 3 (enrôlement tardif du routeur) : `vagrant destroy -f && vagrant up` (montée complète, dans l'ordre), puis `tests/check.sh agents`.** Attendu : tout OK, router compris (son agent a été installé avant le manager et s'est enrôlé seul). Si le routeur reste `Never connected` après 2 min, regarder `/var/ossec/logs/ossec.log` sur le routeur. Corriger dans `agent.sh` (par ex. relancer l'enrôlement si `client.keys` est vide) **sans** casser l'idempotence.

- [ ] **Step 4 (idempotence) : `vagrant provision router pc1 --provision-with agent`, puis `tests/check.sh agents`.** Attendu : tout OK, chaque `localfile` présent une seule fois.

---

### Task 5 : Suricata sur le routeur + trafic visible dans Wazuh

**Files :**
- Modify : `provision/router.sh` (section Suricata à la fin), `provision/wazuh.sh` (règles locales)
- Test : `tests/check.sh` (section `suricata`)

**Interfaces :**
- Consumes : `WAN` et `LAN` (router.sh, Task 1), l'agent du routeur qui lit `eve.json` (Task 4), `lab-count`/`wait_count` (Task 3).
- Produces : les règles `100100` et `100101` dans `/var/ossec/etc/rules/lab_suricata.xml` sur wazuh.

- [ ] **Step 1 : section `suricata` de `check.sh`**
  - `on router 'systemctl is-active suricata'` = `active`
  - `on router 'sudo suricata --dump-config'` contient `HOME_NET = [192.168.10.0/24,203.0.113.1/32]`
  - règle flow : `echo '{"timestamp":"2026-11-21T10:00:00.000000+0000","flow_id":1,"event_type":"flow","src_ip":"192.168.10.12","src_port":40000,"dest_ip":"1.1.1.1","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":1}}' | vagrant ssh wazuh -c 'sudo /var/ossec/bin/wazuh-logtest'` contient `id: '100101'` et `level: '3'`
  - règle dns : même chose avec `"event_type":"dns"` et `"dns":{"type":"query","rrname":"example.com"}`. La sortie contient `id: '100100'`
  - bout en bout : `on pc2 'curl -s http://testmynids.org/uid/index.html'`, puis `wait_count "alerte Suricata" 'agent.name:router AND rule.id:86601 AND data.alert.signature_id:2100498'`
  - trafic : `wait_count "trafic DNS" 'agent.name:router AND rule.id:100100 AND data.event_type:dns'`

- [ ] **Step 2 : `tests/check.sh suricata`.** Attendu : FAIL.

- [ ] **Step 3 : implémenter**

  `router.sh` : `apt-get install -y suricata suricata-update`. Écrire `/etc/suricata/lab.yaml`, et ajouter une seule fois `include: /etc/suricata/lab.yaml` à la fin de `suricata.yaml`. Valeurs de `lab.yaml` :
  - `vars.address-groups.HOME_NET: "[192.168.10.0/24,203.0.113.1/32]"`. **Indispensable** : sinon l'IP publique du routeur est « externe » et les règles ET SCAN `$EXTERNAL_NET -> $HOME_NET` ne matchent pas.
  - `af-packet` : `$WAN` (cluster-id 99) et `$LAN` (cluster-id 98), `cluster-type: cluster_flow`, `defrag: yes`, `checksum-checks: no`. **Indispensable** sous VirtualBox : l'offload produit de faux checksums, et Suricata ignorerait les paquets.
  - `default-rule-path: /var/lib/suricata/rules`, `rule-files: [suricata.rules]`
  - `outputs` : un seul `eve-log` vers `/var/log/suricata/eve.json`, avec les types `alert`, `http`, `dns`, `tls`, `ssh` et `flow`.

  Puis `suricata-update`, `suricata -T -c /etc/suricata/suricata.yaml` (doit passer), et `systemctl enable --now suricata` + `systemctl restart suricata`. Si `include` ne remplace pas bien les listes (à vérifier avec `--dump-config`), éditer directement `suricata.yaml`.

  `wazuh.sh` : écrire `/var/ossec/etc/rules/lab_suricata.xml`. D'abord, vérifier que les parents `86600` (tous les événements Suricata), `86602` (http), `86603` (dns) et `86604` (tls) sont bien ceux de `/var/ossec/ruleset/rules/*suricata*`.
  - `100100` : `if_sid 86602, 86603, 86604`, level 3, description `Suricata $(event_type) : $(src_ip) -> $(dest_ip)`
  - `100101` : `if_sid 86600`, `<field name="event_type">^flow$|^ssh$</field>`, level 3, même description
  Puis `systemctl restart wazuh-manager`.

- [ ] **Step 4 : `vagrant provision router wazuh`, puis `tests/check.sh suricata`.** Attendu : tout OK.

- [ ] **Step 5 (reboot) : `vagrant reload router`, puis `tests/check.sh network suricata`.** Attendu : tout OK.

---

### Task 6 : scénarios de démo + README

**Files :**
- Create : `README.md`
- Test : `tests/check.sh` (section `demo`)

**Interfaces :**
- Consumes : tout ce qui précède.
- Produces : les commandes de démo, identiques dans le README et dans `check.sh demo`.

- [ ] **Step 1 : section `demo` de `check.sh`.** Elle lance les attaques puis vérifie leur trace :
  1. Scan : `on attacker 'sudo nmap -sS -sV -sC -p 22,80,443,1433,3306,3389 203.0.113.1'`, puis :
     - `wait_count "scan détecté" 'rule.id:86601 AND data.src_ip:203.0.113.66'`
     - `on router "sudo grep -q 'FW-DROP.*SRC=203.0.113.66' /var/log/kern.log"`
  2. Brute force : `on attacker 'hydra -l admin -P /home/vagrant/wordlist.txt -t 4 ssh://203.0.113.1'`, puis :
     - `wait_count "échecs SSH" 'agent.name:pc1 AND rule.groups:authentication_failed AND data.srcip:203.0.113.66'`
     - `wait_count "brute force" 'agent.name:pc1 AND rule.groups:authentication_failures'`
     - `wait_count "connexion réussie" 'agent.name:pc1 AND rule.groups:authentication_success AND data.srcip:203.0.113.66'`
  3. Scan web : `on attacker 'nikto -h http://203.0.113.1 -maxtime 60s'`, puis :
     - `wait_count "attaque web (pc1)" 'agent.name:pc1 AND rule.groups:web AND data.srcip:203.0.113.66'`
     - `wait_count "attaque web (Suricata)" 'agent.name:router AND rule.id:86601 AND data.dest_port:80'`
  4. Trafic normal : déjà couvert par la section `suricata`. `all` enchaîne `network pc1 wazuh agents suricata demo`.

- [ ] **Step 2 : `tests/check.sh demo`.** Si une assertion échoue, ajuster les options d'attaque (et pas les seuils) jusqu'à ce que chaque scénario laisse une trace réelle. Attendu final : tout OK.

- [ ] **Step 3 : écrire `README.md`.** Il contient :
  - les prérequis (Mac Apple Silicon, VirtualBox 7.2, Vagrant 2.4, environ 10 Go de RAM libre) ;
  - `vagrant up` (20 à 40 min la première fois) ;
  - l'URL `https://localhost:8443` (accepter le certificat autosigné) et l'utilisateur `admin` ;
  - la récupération du mot de passe : `vagrant ssh wazuh -c "sudo tar -O -xf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt"` ;
  - le schéma de la topologie (repris du design) ;
  - les 3 attaques à copier-coller, et pour chacune le filtre à taper dans le dashboard (Threat Hunting / Discover : `agent.name:router and rule.groups:suricata`, `agent.name:pc1 and rule.groups:authentication_failures`, etc.) ;
  - la mention que le compte `admin/admin123` de pc1 est une faille **volontaire** ;
  - `vagrant halt` et `vagrant destroy -f`, et `tests/check.sh all` pour tout vérifier.

- [ ] **Step 4 : vérification finale : `vagrant destroy -f && vagrant up && tests/check.sh all`.** Attendu : tout OK, code de sortie 0.
