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
    python3-pip

    python3 -m pip install pytest pyroute2
SCRIPT

Vagrant.configure("2") do |config|
  # Define Fedora36 VM
  config.vm.define "f36" do |fedora|
    fedora.vm.box = "fedora/36-cloud-base"

    fedora.vm.provision "common", type: "shell", inline: $bootstrap_rhel_common
    fedora.vm.provision "shell", inline: <<-SHELL
       dnf install -y openvswitch
    SHELL

    fedora.vm.synced_folder ".", "/vagrant", type: "rsync"
  end

  config.vm.define "centos9s" do |centos|
    centos.vm.box = "generic/centos9s"

    centos.vm.provision "common", type: "shell", inline: $bootstrap_rhel_common
    centos.vm.provision "shell", inline: <<-SHELL
       dnf install -y centos-release-nfv-openvswitch
       dnf install -y openvswitch3.1
    SHELL

    centos.vm.synced_folder ".", "/vagrant", type: "rsync"
  end

  config.vm.define "centos9s" do |centos|
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
          rustc \
          cargo \
          clang \
          llvm \
          rustfmt \
          libelf-dev \
          zlib1g-dev \
          libpcap-dev \
          git \
          pkg-config \
          python3-pip \
          openvswitch-switch
      
          python3 -m pip install pytest pyroute2
    SHELL

    jammy.vm.synced_folder ".", "/vagrant", type: "rsync"
  end

  config.vm.provider "libvirt" do |libvirt|
    libvirt.cpus = 4
    libvirt.memory = 4096
  end
end
