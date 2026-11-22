#!/usr/bin/env bash
# Agent Wazuh. Arguments : <chemin>:<log_format> à ajouter à la surveillance (ex. /var/log/x:json).
set -euo pipefail

MANAGER=192.168.10.10
OSSEC=/var/ossec/etc/ossec.conf

if ! dpkg -s wazuh-agent >/dev/null 2>&1; then
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
  chmod 644 /usr/share/keyrings/wazuh.gpg
  echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -q
  WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$(hostname)" apt-get install -yq wazuh-agent=4.14.10-1
fi

# Surveiller chaque log demandé, sans doublon si on relance.
changed=0
for spec in "$@"; do
  path=${spec%:*}; fmt=${spec##*:}
  grep -qF "<location>$path</location>" "$OSSEC" && continue
  # Insère le bloc juste avant </ossec_config> (le dernier).
  block="  <localfile>\n    <log_format>$fmt</log_format>\n    <location>$path</location>\n  </localfile>"
  awk -v b="$block" '/<\/ossec_config>/ && !done {print b; done=1} {print}' "$OSSEC" > "$OSSEC.tmp"
  mv "$OSSEC.tmp" "$OSSEC"
  changed=1
done

systemctl enable -q wazuh-agent
if [ "$changed" = 1 ] || ! systemctl is-active -q wazuh-agent; then
  systemctl restart wazuh-agent
fi
echo "Agent $(hostname) prêt (manager $MANAGER)"
