#!/usr/bin/env bash
# Surveillance d'intégrité de fichiers (FIM) en temps réel sur pc1.
# Détecte en quelques secondes tout fichier déposé dans les dossiers sensibles
# (webshell, malware EICAR) — base des scénarios post-exploitation et dépôt de malware.
set -euo pipefail

OSSEC=/var/ossec/etc/ossec.conf
changed=0
for d in /var/www/html /root; do
  grep -qF ">$d</directories>" "$OSSEC" && continue
  line="    <directories realtime=\"yes\" check_all=\"yes\" report_changes=\"yes\">$d</directories>"
  # Insère la ligne juste avant la fin du bloc <syscheck>.
  awk -v l="$line" '/<\/syscheck>/ && !done {print l; done=1} {print}' "$OSSEC" > "$OSSEC.tmp"
  mv "$OSSEC.tmp" "$OSSEC"
  changed=1
done

[ "$changed" = 1 ] && systemctl restart wazuh-agent
echo "FIM temps réel actif sur /var/www/html et /root"
