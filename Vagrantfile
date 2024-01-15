# -*- mode: ruby -*-
# vi: set ft=ruby :

# Common for all rhel-like distros
$bootstrap_rhel_common = <<SCRIPT
set -euxo pipefail
dnf install -y \
    rust \
    cargo \
    clang \
    llvm \
    rustfmt \
    elfutils-libelf-devel \
    zlib-devel \
    libpcap-devel \
    git \
    python3-pip \
    socat \
    nftables

    python3 -m pip install pytest pyroute2
SCRIPT

Vagrant.configure("2") do |config|
  config.vm.box_check_update = false

  config.vm.define "f39" do |fedora|
    fedora.vm.box = "fedora/39-cloud-base"

    fedora.vm.provision "common", type: "shell", inline: $bootstrap_rhel_common
    fedora.vm.provision "shell", inline: <<-SHELL
       dnf install -y openvswitch
    SHELL

    fedora.vm.synced_folder ".", "/vagrant", type: "rsync"
  end

  config.vm.define "rawhide" do |rawhide|
    def get_box(pattern)
      require 'open-uri'
      require 'nokogiri'

      url = "https://dl.fedoraproject.org/pub/fedora/linux/development/rawhide/Cloud/x86_64/images/"
      doc = Nokogiri::HTML(URI.open(url))
      box = doc.css('a').map { |link| link['href'] }.select { |alink| alink.include?(pattern) }.last
      url + box
    end

    rawhide.vm.box = "fedora-rawhide-cloud"
    rawhide.vm.box_url = get_box("vagrant-libvirt.box")

    rawhide.vm.provision "common", type: "shell", inline: $bootstrap_rhel_common
    rawhide.vm.provision "shell", inline: <<-SHELL
       dnf install -y openvswitch
    SHELL

    rawhide.vm.synced_folder ".", "/vagrant", type: "rsync"
  end

  config.vm.define "c8s" do |centos|
    centos.vm.box = "generic/centos8s"

    centos.vm.provision "shell", inline: <<-SHELL
       dnf config-manager --set-enabled powertools
    SHELL
    centos.vm.provision "common", type: "shell", inline: $bootstrap_rhel_common
    centos.vm.provision "shell", inline: <<-SHELL
       dnf install -y centos-release-nfv-openvswitch
       dnf install -y openvswitch3.1
    SHELL

    centos.vm.synced_folder ".", "/vagrant", type: "rsync"
  end

  config.vm.define "c9s" do |centos|
    centos.vm.box = "generic/centos9s"

    centos.vm.provision "common", type: "shell", inline: $bootstrap_rhel_common
    centos.vm.provision "shell", inline: <<-SHELL
       dnf install -y centos-release-nfv-openvswitch
       dnf install -y openvswitch3.1
    SHELL

    centos.vm.synced_folder ".", "/vagrant", type: "rsync"
  end

  config.vm.define "jammy" do |jammy|
    jammy.vm.box = "generic/ubuntu2204"

    jammy.vm.provision "shell", inline: <<-SHELL
      set -euxo pipefail
      apt-get update -y && apt-get install -y \
          clang \
          curl \
          llvm \
          libelf-dev \
          zlib1g-dev \
          libpcap-dev \
          git \
          pkg-config \
          python3-pip \
          openvswitch-switch \
          socat \
          nftables

      su vagrant -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -qy"
      python3 -m pip install pytest pyroute2
    SHELL

    jammy.vm.synced_folder ".", "/vagrant", type: "rsync"
  end

  config.vm.provider "libvirt" do |libvirt|
    libvirt.cpus = 4
    libvirt.memory = 4096
  end
end
