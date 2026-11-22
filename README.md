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
203.0.113.66       WAN 203.0.113.1                        ├─ pc1     192.168.10.11  (SSH + web exposés)
                   LAN 192.168.10.1                        └─ pc2     192.168.10.12
```

Le « switch » est un réseau interne VirtualBox (`lan`). Le réseau `wan` est un Internet simulé.
Tout le trafic des postes vers Internet passe par le routeur, donc Suricata le voit.

| VM | Rôle | RAM |
|----|------|-----|
| router | Routeur/pare-feu nftables + NAT + Suricata + agent Wazuh | 1 Go |
| wazuh | Wazuh all-in-one (indexer + manager + dashboard) | 6 Go |
| pc1 | Poste avec SSH et site web exposés, agent Wazuh | 1 Go |
| pc2 | Poste, agent Wazuh | 1 Go |
| attacker | Attaquant externe (nmap, hydra, nikto) | 1 Go |

Total ≈ 10 Go de RAM. Prévois une machine avec au moins 16 Go.

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

| # | Attaque | Commande | Où regarder dans le dashboard (Threat Hunting → filtre) |
|---|---------|----------|---------------------------------------------------------|
| 1 | Scan de ports | `sudo nmap -sS -sV -sC -p 22,80,443,1433,3306,3389 203.0.113.1` | `data.src_ip:203.0.113.66` |
| 2 | Brute force SSH | `hydra -l admin -P ~/wordlist.txt -t 4 ssh://203.0.113.1` | `agent.name:pc1 and rule.groups:authentication_failures` |
| 3 | Scan web | `nikto -h http://203.0.113.1 -maxtime 60s` | `agent.name:pc1 and rule.groups:web` |

Le brute force (#2) **réussit** : le compte `admin` / `admin123` de pc1 est une **faille
volontaire** pour la démo. Après plusieurs échecs tu verras une alerte de connexion réussie.

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
