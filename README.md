# Lab réseau d'entreprise + Wazuh

Petite infra d'entreprise décrite avec **Vagrant** et lancée sur **VirtualBox** : deux postes,
un switch, un routeur, un serveur **Wazuh**, et une machine attaquante externe. On ouvre le
dashboard Wazuh dans le navigateur, on lance une attaque depuis l'extérieur, et on la voit
apparaître en temps réel.

## Topologie

```
                        carte NAT Vagrant (vrai Internet, pour apt)
                                  │
[attacker] ─(wan)─ [router + Suricata] ─(lan = le switch)─┬─ wazuh   192.168.10.10
203.0.113.66       WAN 203.0.113.1                        ├─ pc1     192.168.10.11
                   LAN 192.168.10.1                        ├─ pc2     192.168.10.12
                                                           └─ pc3     192.168.10.13
```

Le « switch » est un réseau interne VirtualBox (`lan`). Le réseau `wan` est un Internet simulé.
Tout le trafic des postes vers Internet passe par le routeur, donc Suricata le voit.

Les 3 postes sont identiques, mais le routeur dirige un service différent vers chacun, ce qui
**répartit les attaques** (une par poste, visible séparément dans Wazuh) :

| Port exposé (sur 203.0.113.1) | Poste ciblé | Attaque |
|---|---|---|
| `22` (SSH) | **pc1** | brute force SSH + post-exploitation |
| `80` (web) | **pc2** | scan web (nikto) |
| `2222` (SSH) | **pc3** | dépôt de malware (EICAR) |

| VM | Rôle | RAM |
|----|------|-----|
| router | Routeur/pare-feu nftables + NAT + Suricata + agent Wazuh | 1 Go |
| wazuh | Wazuh all-in-one (indexer + manager + dashboard) | 6 Go |
| pc1 / pc2 / pc3 | Postes vulnérables (nginx + SSH faible + FIM), agent Wazuh | 1 Go ×3 |
| attacker | Attaquant externe (nmap, hydra, nikto) | 1 Go |

Total ≈ 11 Go de RAM. Prévois une machine avec au moins 16 Go.

## Prérequis (Windows, Linux ou macOS)

1. **VirtualBox** 7.x — https://www.virtualbox.org/wiki/Downloads
2. **Vagrant** 2.4.x — https://developer.hashicorp.com/vagrant/install

La box `bento/ubuntu-24.04` existe en **amd64** (PC Windows/Linux x86) et en **arm64**
(Mac Apple Silicon) ; le `Vagrantfile` choisit l'architecture de l'hôte automatiquement.

- **Windows** : installe VirtualBox et Vagrant (ou `winget install HashiCorp.Vagrant Oracle.VirtualBox`),
  puis utilise PowerShell. La virtualisation (VT-x/AMD-V) doit être activée dans le BIOS, et
  Hyper-V / WSL2 désactivés (ils bloquent VirtualBox).
- **Linux** : installe les paquets `virtualbox` et `vagrant` de ta distribution, ou ceux de HashiCorp.
- **macOS Apple Silicon** : VirtualBox 7.1+ (support ARM). Le `Vagrantfile` contient un petit
  contournement, actif uniquement sur macOS, pour un bug de détection de ports de Vagrant.

### Alternative : VMware

Le `Vagrantfile` supporte aussi **VMware** (Workstation sur Windows/Linux, Fusion sur Mac).
Le plugin [`vagrant-vmware-desktop`](https://developer.hashicorp.com/vagrant/docs/providers/vmware)
est **open source et gratuit** (licence MPL). Mise en place, en une fois :

1. Installer le **Vagrant VMware Utility** (paquet système à télécharger :
   https://developer.hashicorp.com/vagrant/downloads/vmware).
2. Installer le plugin : `vagrant plugin install vagrant-vmware-desktop`
3. Avoir VMware Fusion / Workstation (gratuit pour un usage perso).

Puis :

```bash
vagrant up --provider vmware_desktop
```

> Non testé par l'auteur (pas de VMware sous la main) — à valider côté équipe. Les deux réseaux
> isolés (`wan` 203.0.113.0/24, `lan` 192.168.10.0/24) sont séparés par sous-réseau sous VMware ;
> la clé `virtualbox__intnet` du `Vagrantfile` est simplement ignorée par le provider VMware.

## Démarrage

```bash
vagrant up
```

Le premier lancement télécharge la box et installe Wazuh : compte **20 à 40 min**. L'installation
de Wazuh tourne en tâche de fond sur la VM et résiste à une coupure SSH. Si l'installation du
serveur échoue en cours de route (réseau, VM mise en veille…), repars d'une VM propre :

```bash
vagrant destroy -f wazuh && vagrant up wazuh
```

> Sur un portable, empêche la mise en veille pendant `vagrant up` : VirtualBox met sinon les
> VMs en pause (« host power management ») et l'installation échoue. Sur macOS : `caffeinate -dimsu`.

## Accéder au dashboard

Dans le navigateur de ta machine hôte : **https://localhost:8443**
(accepte le certificat autosigné).

- Utilisateur : **`admin`**
- Mot de passe : **`Passer123-`**

Le mot de passe est fixé par le provisioning (Wazuh exige une majuscule, une minuscule, un
chiffre et un symbole). Il est aussi rappelé à la fin de `vagrant up` / `vagrant provision wazuh`.
Pour le changer, modifie `ADMIN_PW` dans `provision/wazuh.sh` puis `vagrant provision wazuh`.

## Scénarios d'attaque (depuis la machine attaquante)

```bash
vagrant ssh attacker
```

Chaque attaque vise un poste différent (via le port exposé), donc on la retrouve sur l'agent
correspondant dans Wazuh.

| # | Cible | Attaque | Commande | Filtre dashboard (`agent.name:`) |
|---|---|---------|----------|----------------------------------|
| 1 | router | Scan de ports | `sudo nmap -sS -sV -p 22,80,443,2222 203.0.113.1` | `data.src_ip:203.0.113.66` |
| 2 | **pc1** | Brute force SSH | `hydra -l admin -P ~/wordlist.txt -t 4 ssh://203.0.113.1` | `agent.name:pc1 and rule.groups:authentication_failures` |
| 3 | **pc2** | Scan web | `nikto -h http://203.0.113.1 -maxtime 60s` | `agent.name:pc2 and rule.groups:web` |
| 4 | **pc1** | Post-exploitation | `ssh admin@203.0.113.1` → `sudo useradd -m backdoor` + webshell | `agent.name:pc1 and (rule.id:5902 or rule.id:5402 or rule.id:5403 or rule.id:554)` |
| 5 | **pc3** | Dépôt de malware (EICAR) | `ssh -p 2222 admin@203.0.113.1` → déposer le fichier EICAR | `agent.name:pc3 and rule.id:554 and syscheck.path:*eicar*` |

Le brute force (#2) **réussit** : le compte `admin` / `admin123` (présent sur chaque poste) est
une **faille volontaire**. Les scénarios 4 et 5 enchaînent dessus : `admin` peut passer **root
sans mot de passe** (autre misconfig volontaire), et Wazuh détecte l'escalade, le nouveau compte
et les fichiers déposés grâce à la **surveillance d'intégrité (FIM) en temps réel** sur les postes.

> 📸 **Démonstration pas à pas avec captures d'écran du dashboard :**
> [`docs/scenario-demo-attaque.md`](docs/scenario-demo-attaque.md) — runbook reproductible
> (lancer les attaques + les retrouver dans Wazuh, filtre par filtre).

Pour voir le **trafic normal** (pas seulement les alertes), filtre sur
`agent.name:router and rule.groups:suricata` après avoir navigué depuis un poste
(`vagrant ssh pc2 -c 'curl -s https://example.com'`).

## Vérifier que tout marche

```bash
tests/check.sh all
```

Lance les 5 scénarios et vérifie leurs traces dans Wazuh (sous Windows : via Git Bash / WSL).

## Arrêter / supprimer

```bash
vagrant halt        # éteindre (garde l'état)
vagrant up          # redémarrer
vagrant destroy -f  # tout supprimer
```

## Avertissement

Infra volontairement vulnérable (compte faible, services exposés), à usage pédagogique sur
un réseau isolé uniquement. Ne pas exposer sur un vrai réseau.
