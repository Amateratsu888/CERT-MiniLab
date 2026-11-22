#!/usr/bin/env bash
# pc1 : poste exposé sur Internet via le routeur (SSH + petit site web).
# FAILLE VOLONTAIRE pour la démo : compte admin/admin123 avec connexion SSH par mot de passe.
set -euo pipefail

apt-get update -q
apt-get install -yq nginx
echo '<h1>LAB-PC1 — intranet de l entreprise</h1>' > /var/www/html/index.html
# Page piège : la réponse contient "uid=0(root)", qui déclenche de façon déterministe la règle
# Suricata GPL ATTACK_RESPONSE (sid 2100498) quand l'attaquant la récupère. Sert aux démos/tests.
echo 'uid=0(root) gid=0(root) groups=0(root)' > /var/www/html/uid

id admin >/dev/null 2>&1 || useradd -m -s /bin/bash admin
echo 'admin:admin123' | chpasswd
# 00- : sshd garde la première valeur lue, donc ce fichier l'emporte sur 50-cloud-init.conf.
echo 'PasswordAuthentication yes' > /etc/ssh/sshd_config.d/00-lab.conf
systemctl reload ssh
echo "pc1 prêt : nginx + SSH par mot de passe (admin/admin123)"
