# Lab réseau d'entreprise + Wazuh — voir docs/2026-11-21-lab-wazuh-design.md
#
#  [attacker] ── (wan 203.0.113.0/24) ── [router] ── (lan 192.168.10.0/24 = le switch) ── wazuh, pc1, pc2
#
# Ordre de démarrage = ordre de définition : le routeur d'abord (Internet des autres VMs),
# puis le manager Wazuh (avant ses agents).

# Contournement macOS uniquement : sur macOS, le test de port de Vagrant 2.4.9
# (Socket.tcp avec connect_timeout) voit tous les ports locaux comme occupés et
# refuse le port 8443 du dashboard. On le remplace par une connexion simple.
# Inutile et neutre sur Linux/Windows, donc on ne l'applique que sur Darwin.
if RUBY_PLATFORM.include?("darwin")
  require "vagrant/util/is_port_open"
  module Vagrant::Util::IsPortOpen
    def is_port_open?(host, port)
      Socket.tcp(host, port).close
      true
    rescue SystemCallError
      false
    end
  end
end

# Règle RAM (Mo) et CPU pour les DEUX providers supportés, VirtualBox et VMware.
# VMware nécessite le plugin vagrant-vmware-desktop : vagrant up --provider vmware_desktop
def set_resources(m, mem, cpus)
  m.vm.provider("virtualbox") { |v| v.memory = mem; v.cpus = cpus }
  m.vm.provider("vmware_desktop") { |v| v.vmx["memsize"] = mem.to_s; v.vmx["numvcpus"] = cpus.to_s }
end

Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-24.04"
  # Architecture auto-détectée : arm64 sur Apple Silicon, amd64 sur un hôte x86 (Windows/Linux).
  config.vm.synced_folder ".", "/vagrant", disabled: true

  # Ressources par défaut, pour les deux providers.
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 1024
    vb.cpus = 1
  end
  config.vm.provider "vmware_desktop" do |vw|
    vw.vmx["memsize"] = "1024"
    vw.vmx["numvcpus"] = "1"
  end

  config.vm.define "router" do |m|
    m.vm.hostname = "router"
    m.vm.network "private_network", ip: "203.0.113.1", virtualbox__intnet: "wan"
    m.vm.network "private_network", ip: "192.168.10.1", virtualbox__intnet: "lan"
    m.vm.provision "router", type: "shell", path: "provision/router.sh"
    m.vm.provision "agent", type: "shell", path: "provision/agent.sh",
      args: ["/var/log/suricata/eve.json:json", "/var/log/kern.log:syslog"]
  end

  config.vm.define "wazuh" do |m|
    m.vm.hostname = "wazuh"
    m.vm.network "private_network", ip: "192.168.10.10", virtualbox__intnet: "lan"
    m.vm.network "forwarded_port", guest: 443, host: 8443
    set_resources(m, 6144, 2)
    m.vm.provision "client", type: "shell", path: "provision/client.sh"
    m.vm.provision "wazuh", type: "shell", path: "provision/wazuh.sh"
  end

  { "pc1" => "192.168.10.11", "pc2" => "192.168.10.12" }.each do |name, ip|
    config.vm.define name do |m|
      m.vm.hostname = name
      m.vm.network "private_network", ip: ip, virtualbox__intnet: "lan"
      m.vm.provision "client", type: "shell", path: "provision/client.sh"
      m.vm.provision "pc1", type: "shell", path: "provision/pc1.sh" if name == "pc1"
      if name == "pc1"
        m.vm.provision "agent", type: "shell", path: "provision/agent.sh",
          args: ["/var/log/nginx/access.log:apache", "/var/log/nginx/error.log:apache"]
        # FIM temps réel (web root + /root) : détecte webshell/malware déposés en post-exploitation.
        m.vm.provision "fim", type: "shell", path: "provision/fim-pc1.sh"
      else
        m.vm.provision "agent", type: "shell", path: "provision/agent.sh"
      end
    end
  end

  config.vm.define "attacker" do |m|
    m.vm.hostname = "attacker"
    m.vm.network "private_network", ip: "203.0.113.66", virtualbox__intnet: "wan"
    m.vm.provision "attacker", type: "shell", path: "provision/attacker.sh"
  end
end
