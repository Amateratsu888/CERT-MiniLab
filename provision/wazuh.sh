#!/usr/bin/env bash
# Serveur Wazuh all-in-one (indexer + manager + dashboard) via le script officiel 4.14.
set -euo pipefail

LOG=/var/log/wazuh-lab-install.log
SENTINEL=/root/.wazuh-lab-done            # écrit par CE script quand l'install est confirmée terminée
TAR=/root/wazuh-install-files.tar         # certs + mots de passe (créé tôt par l'installeur, PAS un marqueur de fin)
ADMIN_PW="Passer123-"                      # mot de passe fixe du dashboard admin.
# Wazuh impose : 8-64 caractères, au moins une majuscule, une minuscule, un chiffre et un
# symbole parmi . * + ? -  (donc « passer123 » seul est refusé).

# lab-count '<requête lucene>' [minutes] + rappel du mot de passe admin. Idempotent.
# Heredoc NON quoté : $ADMIN_PW est injecté (source unique), les \$ restent littéraux dans le script.
finalize() {
  install -m 700 /dev/stdin /usr/local/bin/lab-count <<SCRIPT
#!/usr/bin/env bash
set -euo pipefail
q=\${1:?requête lucene}; mins=\${2:-10}
body=\$(printf '{"query":{"bool":{"must":[{"query_string":{"query":"%s"}},{"range":{"timestamp":{"gte":"now-%dm"}}}]}}}' "\$q" "\$mins")
curl -sk -u 'admin:$ADMIN_PW' "https://localhost:9200/wazuh-alerts-*/_count" \\
     -H 'Content-Type: application/json' -d "\$body" | sed -E 's/.*"count":([0-9]+).*/\\1/'
SCRIPT
  echo "=================================================="
  echo "Dashboard : https://localhost:8443   (utilisateur admin)"
  echo "Mot de passe admin : $ADMIN_PW"
  echo "=================================================="
}

# Attendre que l'indexer réponde (nécessaire avant de changer un mot de passe).
wait_indexer() {
  local _; for _ in $(seq 1 30); do
    curl -sk -o /dev/null https://localhost:9200 && return 0
    sleep 2
  done
}

# Fixer le mot de passe du dashboard admin à $ADMIN_PW (sinon l'installeur en génère un aléatoire).
# Idempotent : relancer le remet simplement à la même valeur.
set_admin_password() {
  local tool=/root/wazuh-passwords-tool.sh tmp
  if [ ! -x "$tool" ]; then
    # Téléchargement atomique : on écrit dans un fichier temporaire et on ne l'installe au
    # chemin de confiance (root, 700) QUE si curl réussit entièrement — jamais un fichier
    # partiel exécuté plus tard. -f : échoue sur erreur HTTP ; HTTPS/TLS imposés ; même source
    # officielle que wazuh-install.sh (pas de pin SHA : l'installeur et les paquets viennent du
    # même dépôt HTTPS de la même façon).
    tmp=$(mktemp)
    if curl -fsSL --proto '=https' --tlsv1.2 --retry 3 \
         -o "$tmp" https://packages.wazuh.com/4.14/wazuh-passwords-tool.sh; then
      install -m 700 "$tmp" "$tool"
    else
      echo "ATTENTION : téléchargement du password-tool échoué, mot de passe admin inchangé"
    fi
    rm -f "$tmp"
    [ -x "$tool" ] || return 0
  fi
  bash "$tool" -u admin -p "$ADMIN_PW" >/dev/null 2>&1 \
    || echo "ATTENTION : changement du mot de passe admin échoué (relancer : vagrant provision wazuh)"
}

# Règles locales : hisser les événements Suricata « normaux » (http/dns/tls/flow/ssh) au niveau 3
# pour qu'ils soient indexés et visibles dans le dashboard. Par défaut ils sont au niveau 0 et
# seules les alertes (86601) remontent. IDs parents vérifiés sur 4.14 : dns 86603, tls 86604,
# http 86602, base (flow/ssh) 86600. Idempotent.
local_rules() {
  install -m 660 -o wazuh -g wazuh /dev/stdin /var/ossec/etc/rules/lab_suricata.xml <<'XML'
<group name="local,suricata,">
  <rule id="100100" level="3">
    <if_sid>86602,86603,86604</if_sid>
    <description>Suricata $(event_type): $(src_ip) -> $(dest_ip)</description>
  </rule>
  <rule id="100101" level="3">
    <if_sid>86600</if_sid>
    <field name="event_type">^flow$|^ssh$</field>
    <description>Suricata $(event_type): $(src_ip) -> $(dest_ip)</description>
  </rule>
</group>
XML
}

# Adapter Wazuh à une petite VM de lab (disque 30 Go). Idempotent.
harden() {
  # La détection de vulnérabilités télécharge un feed CVE de ~9 Go qui remplit le disque :
  # disque plein => wazuh-db ne peut plus écrire => agents "Unknown" et API qui ne démarre pas.
  # Inutile pour une démo de détection d'attaques, on la désactive et on vide le feed.
  sed -i '/<vulnerability-detection>/,/<\/vulnerability-detection>/ s|<enabled>yes</enabled>|<enabled>no</enabled>|' \
    /var/ossec/etc/ossec.conf
  find /var/ossec/queue/vd/feed -mindepth 1 -delete 2>/dev/null || true
  apt-get clean
  # Le manager est lent à démarrer sur une VM modeste : éviter le timeout systemd (défaut trop court).
  mkdir -p /etc/systemd/system/wazuh-manager.service.d
  printf '[Service]\nTimeoutStartSec=600\n' > /etc/systemd/system/wazuh-manager.service.d/override.conf
  systemctl daemon-reload
}

if [ -f "$SENTINEL" ]; then
  echo "Wazuh déjà installé — on s'assure que les services tournent."
  harden
  local_rules
  systemctl start wazuh-indexer wazuh-dashboard 2>/dev/null || true
  wait_indexer
  set_admin_password
  systemctl restart wazuh-manager 2>/dev/null || true
  finalize
  exit 0
fi

# Le paquet wazuh-indexer fait 874 Mo et transite par le NAT du routeur : le téléchargement
# peut expirer. On rend apt résilient (reprise sur coupure, plusieurs essais) avant l'install.
cat > /etc/apt/apt.conf.d/99lab <<'EOF'
Acquire::Retries "6";
Acquire::http::Timeout "180";
Acquire::https::Timeout "180";
EOF

# Pré-télécharger le gros .deb de l'indexer (874 Mo) avec reprise, dans le cache apt :
# l'installeur l'y trouvera et ne le retéléchargera pas. curl -C - reprend un fichier partiel.
arch=$(dpkg --print-architecture)
deb="wazuh-indexer_4.14.10-1_${arch}.deb"
if [ ! -s "/var/cache/apt/archives/$deb" ]; then
  echo "Pré-téléchargement de l'indexer Wazuh ($deb, ~874 Mo)…"
  curl -fsS --retry 6 --retry-delay 5 -C - \
    -o "/var/cache/apt/archives/$deb" \
    "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-indexer/$deb"
fi

# Garde-disque : dès que le manager démarre pendant l'install, son module de détection de
# vulnérabilités télécharge un feed CVE de ~10 Go qui sature le disque de 30 Go AVANT la fin
# (le dashboard échoue alors sur « No space left on device »). On coupe VD dès que la conf
# existe et on empêche le feed de s'accumuler tant que l'installeur tourne. harden() le
# désactivera définitivement après. S'arrête quand l'installeur se termine.
# S'arrête sur le même marqueur de fin que la boucle principale (pas de détection par nom de
# process), avec un plafond absolu de 1200 itérations (~40 min) pour ne jamais tourner sans fin.
diskguard() {
  local i
  for i in $(seq 1 1200); do
    grep -qE "Installation finished|ERROR:" "$LOG" 2>/dev/null && break
    [ -f /var/ossec/etc/ossec.conf ] && \
      sed -i '/<vulnerability-detection>/,/<\/vulnerability-detection>/ s|<enabled>yes</enabled>|<enabled>no</enabled>|' \
        /var/ossec/etc/ossec.conf 2>/dev/null || true
    find /var/ossec/queue/vd/feed -mindepth 1 -delete 2>/dev/null || true
    sleep 2
  done
}

# Install fraîche. Pas de -o (destructif). setsid : l'installeur tourne dans sa propre
# session, donc une coupure SSH (SIGHUP) ne l'interrompt pas — il finit même si ce script meurt.
cd /root
[ -f wazuh-install.sh ] || curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
if ! pgrep -f 'bash wazuh-install.sh' >/dev/null; then
  : > "$LOG"
  setsid bash wazuh-install.sh -a -i > "$LOG" 2>&1 < /dev/null &
fi
diskguard &

# Attendre le VRAI message de fin de l'installeur (le .tar, lui, est créé bien avant la fin).
echo "Installation de Wazuh en cours (10-20 min)…"
for _ in $(seq 1 240); do
  grep -q "Installation finished" "$LOG" 2>/dev/null && break
  if grep -q "ERROR:" "$LOG" 2>/dev/null; then
    tail -20 "$LOG"; echo "Install Wazuh en erreur (voir $LOG)"; exit 1
  fi
  sleep 10
done
grep -q "Installation finished" "$LOG" 2>/dev/null \
  || { echo "Install Wazuh non terminée (timeout). Relancer : vagrant provision wazuh"; exit 1; }

# Désactiver VD + libérer le disque AVANT que le feed CVE ne grossisse, fixer le mot de passe
# admin, puis redémarrer le manager.
harden
local_rules
wait_indexer
set_admin_password
systemctl restart wazuh-manager 2>/dev/null || true

touch "$SENTINEL"
finalize
