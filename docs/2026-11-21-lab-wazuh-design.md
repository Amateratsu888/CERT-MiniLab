# Lab réseau d'entreprise + Wazuh — design

## Intention

Monter une infra d'entreprise minimale (2 postes, un switch, un routeur), entièrement décrite en code avec Vagrant et lancée sur VirtualBox, supervisée par Wazuh.
La finalité est une démo : ouvrir le dashboard Wazuh depuis le Mac, voir en temps réel le trafic et les événements de l'infra, puis lancer une attaque depuis une machine externe et la voir apparaître dans Wazuh.

## Objectifs

- `vagrant up` monte toute l'infra, Wazuh compris, sans étape manuelle (à part lire le mot de passe admin affiché).
- Dashboard Wazuh accessible depuis le Mac : `https://localhost:8443`.
- Trafic réseau visible dans Wazuh quasi en temps réel (Suricata sur le routeur → agent Wazuh).
- Un attaquant placé côté Internet : scan, brute force SSH, scan web, tous visibles dans Wazuh.

## Non-objectifs

- Pas de Windows ni de pfSense/OPNsense (pas disponibles en ARM pour VirtualBox).
- Pas de Wazuh multi-nœuds, pas de haute dispo, pas de certificats TLS personnalisés.
- Pas de blocage automatique (Active Response) dans cette v1. Faisable ensuite.
- Pas de durcissement des postes : ce sont les cibles.

## Anti-objectifs (échec même si « ça marche »)

- Des postes qui sortent sur Internet sans passer par le routeur : Suricata ne verrait rien, la démo serait fausse.
- Une infra qui demande une série de commandes manuelles après `vagrant up`.
- Dépasser ~10 Go de RAM au total (le Mac en a 16).

## Contraintes (vérifiées le 2026-11-21)

- Mac Apple Silicon (arm64), 16 Go RAM, 10 cœurs. VirtualBox 7.2.22, Vagrant 2.4.9, aucun plugin.
- VMs ARM uniquement. Box `bento/ubuntu-24.04`, existe en `virtualbox/arm64`.
- Wazuh 4.14.10 : paquets arm64 présents pour indexer, manager, dashboard et agent. Script `https://packages.wazuh.com/4.14/wazuh-install.sh` disponible.
- La box `kalilinux/rolling` n'existe qu'en amd64 → l'attaquant est une Ubuntu avec les outils installés.
- Chaque VM Vagrant garde une carte NAT (carte 1) pour `vagrant ssh`. On ne peut pas la retirer, on la neutralise pour le routage (voir Postes).

## Approches considérées

| Sujet | Retenu | Écarté | Pourquoi |
|---|---|---|---|
| Installation de Wazuh | Script officiel `wazuh-install.sh -a` lancé par le provisioning Vagrant (choix de Claude) | Docker compose single-node dans la VM | Docker ajoute une couche dans une VM déjà virtualisée, consomme plus de RAM, et ses images arm64 sont moins sûres. Le script installe des services systemd, comme sur un vrai serveur. |
| Position de l'attaquant | Dehors, côté Internet (ton choix) | Dans le LAN | Une attaque externe traverse le routeur, donc le pare-feu et Suricata la voient. |
| Visibilité réseau | Suricata sur le routeur (choix de Claude) | VM sonde dédiée en écoute sur le switch ; Wazuh seul | Tout le trafic Internet↔LAN passe par le routeur. La sonde dédiée verrait aussi le trafic PC↔PC, mais coûte une VM et ne sert pas avec un attaquant externe. Wazuh seul ne voit pas le réseau. |

## Topologie

```
                         carte NAT Vagrant (vrai Internet, pour apt)
                                   │
[attacker] ── (intnet "wan") ── [router + Suricata + agent] ── (intnet "lan" = le switch) ──┬── wazuh
203.0.113.66   203.0.113.0/24     WAN 203.0.113.1                 192.168.10.0/24           ├── pc1 (SSH + web exposés)
                                  LAN 192.168.10.1                                          └── pc2
```

Le réseau `wan` est un Internet simulé (203.0.113.0/24, plage réservée à la documentation, RFC 5737).
Les vrais accès Internet (apt, téléchargements) des VMs du LAN sortent par la carte NAT du routeur, donc ils passent eux aussi par le routeur.

| VM | Rôle | IP | RAM | CPU |
|---|---|---|---|---|
| router | Routeur/pare-feu nftables, NAT, Suricata, agent Wazuh | 203.0.113.1 / 192.168.10.1 | 1 Go | 1 |
| wazuh | Wazuh all-in-one (indexer + manager + dashboard) | 192.168.10.10 | 6 Go | 2 |
| pc1 | Poste avec SSH et site web exposés via le routeur, agent | 192.168.10.11 | 1 Go | 1 |
| pc2 | Poste, agent | 192.168.10.12 | 1 Go | 1 |
| attacker | Attaquant externe (nmap, hydra, nikto) | 203.0.113.66 | 1 Go | 1 |

Total : 10 Go. Ordre de démarrage = ordre dans le `Vagrantfile` : router, wazuh, pc1, pc2, attacker. Le routeur doit être prêt avant les autres (leur Internet passe par lui), et le manager Wazuh avant les agents.

## Comportement

### Routeur

- `net.ipv4.ip_forward=1`, persistant.
- nftables :
  - masquerade du LAN vers la carte NAT Vagrant (sortie Internet réelle) ;
  - DNAT : `203.0.113.1` tcp/22 et tcp/80, reçus sur l'interface WAN uniquement → pc1. Le SSH Vagrant du routeur arrive par la carte NAT et n'est pas touché ;
  - forward : LAN → partout accepté ; WAN → pc1:22 et pc1:80 accepté ; established/related accepté ; le reste est refusé et journalisé (préfixe `FW-DROP`).
- Suricata (paquet Ubuntu) en af-packet sur les interfaces WAN et LAN, règles ET Open via `suricata-update`. `eve.json` contient les types alert, http, dns, tls, ssh et flow. Les deux interfaces sont nécessaires : le WAN voit les scans bloqués par le pare-feu, le LAN voit la sortie Internet des postes. Le trafic autorisé de l'attaquant vers pc1 apparaîtra donc en double, c'est accepté (choix de Claude).
- Agent Wazuh qui lit `/var/log/suricata/eve.json` (format json) et les logs noyau du pare-feu.

### Postes (pc1, pc2) et serveur wazuh

- Route par défaut → `192.168.10.1`, à la place de celle de la carte NAT, de façon persistante (netplan). La carte NAT reste pour `vagrant ssh` et le port redirigé du dashboard : les réponses partent par la route connectée 10.0.2.0/24, ça fonctionne.
- DNS : un résolveur public (1.1.1.1), joint via le routeur. On ignore le DNS fourni par le DHCP NAT (10.0.2.3), sinon les requêtes DNS contourneraient le routeur.
- Agent Wazuh 4.14.10, `WAZUH_MANAGER=192.168.10.10`, nom de l'agent = hostname.
- pc1 : nginx avec une page simple. `sshd` avec `PasswordAuthentication yes` et un compte volontairement faible `admin` / `admin123` pour que le brute force aboutisse en démo (**vulnérabilité volontaire, choix de Claude**). nginx est installé avant l'agent, ou son `access.log` est ajouté explicitement dans `ossec.conf`.

### Wazuh

- `bash wazuh-install.sh -a` (branche 4.14), avec la même règle de routage que les postes.
- Port redirigé : invité 443 → hôte 8443.
- À la fin du provisioning, le mot de passe `admin` est affiché (extrait de `wazuh-install-files.tar`).
- Règle locale `local_rules.xml` : les événements Suricata non-alerte (http, dns, tls, flow) passent au niveau 3, pour être indexés et visibles dans le dashboard. Par défaut ils sont au niveau 0 et seules les alertes s'affichent. Les IDs exacts des règles parentes sont à relever dans `/var/ossec/ruleset/rules/*suricata*`.

### Attaquant

- Ubuntu avec nmap, hydra, nikto et une petite wordlist qui contient `admin123`.
- Aucune route vers 192.168.10.0/24 : il ne connaît que l'IP publique `203.0.113.1`, comme un vrai attaquant externe. Sa carte NAT ne sert qu'à apt.

## Scénarios de démo (critères de succès)

1. **Trafic normal** : sur pc2, `curl https://example.com` → événements DNS et TLS (agent router) visibles dans le dashboard en moins d'une minute.
2. **Scan** : depuis l'attaquant, un `nmap` sur `203.0.113.1` → alertes Suricata (ET SCAN) et/ou drops du pare-feu visibles. Le builder choisit des options nmap qui déclenchent effectivement des règles (par ex. `-sV` ou des scripts NSE http).
3. **Brute force SSH** : `hydra` → `203.0.113.1:22` → alertes sshd sur l'agent pc1 (échecs d'authentification, brute force), puis connexion réussie.
4. **Scan web** : `nikto -h http://203.0.113.1` → alertes Suricata (agent router) et alertes web issues des logs nginx (agent pc1).

## Fichiers

- `Vagrantfile`
- `provision/router.sh`, `provision/wazuh.sh`, `provision/agent.sh` (commun aux postes et au routeur), `provision/pc1.sh`, `provision/attacker.sh`
- `README.md` : lancer, récupérer le mot de passe, rejouer les scénarios.

Le dossier synchronisé `/vagrant` est désactivé : Vagrant envoie les scripts de provisioning lui-même, et ça évite de dépendre des Guest Additions sur ARM.

## Laissé au builder

- Les noms d'interfaces sur la box arm64 (enp0s…) : à détecter par IP plutôt qu'à coder en dur.
- La syntaxe netplan exacte pour neutraliser la route et le DNS de la carte NAT.
- Le réglage de la RAM du serveur Wazuh (descendre à 4 Go si le Mac rame, avec un heap de l'indexer réduit).
