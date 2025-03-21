# -*- mode: ruby -*-
# vi: set ft=ruby :

# Common for all rhel-like distros
# Installation of scapy 2.6.1 and above will fail on RHEL 8.
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
    python3-devel \
    socat \
    nftables \
    make \
    jq \
    ethtool

    python3 -m pip install pytest pyroute2
    python3 -m pip install "scapy>=2.6.1"
SCRIPT

# CentOS mirror URL changed but the c8s image is no longer being built. We
# have to fix them manually in order to install packages later.
$fix_centos_repositories = <<SCRIPT
sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo
sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo
sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo
SCRIPT

def get_box(url, pattern)
  require 'open-uri'
  require 'nokogiri'

  doc = Nokogiri::HTML(URI.open(url))
  box = doc.css('a').map { |link| link['href'] }.select { |alink| pattern.match?(alink) }.last
  url + box
end

Vagrant.configure("2") do |config|
  config.vm.box_check_update = false

  config.vm.define "x86_64-f41" do |fedora|
    fedora.vm.box = "fedora-41-cloud"
    fedora.vm.box_url = get_box("https://dl.fedoraproject.org/pub/fedora/linux/releases/41/Cloud/x86_64/images/", /.*vagrant\.libvirt\.box$/)

    fedora.vm.provision "common", type: "shell", inline: $bootstrap_rhel_common
    fedora.vm.provision "shell", inline: <<-SHELL
       dnf install -y openvswitch
    SHELL

    fedora.vm.synced_folder ".", "/vagrant", type: "rsync"
  end

  config.vm.define "x86_64-rawhide" do |rawhide|
    rawhide.vm.box = "fedora-rawhide-cloud"
    rawhide.vm.box_url = get_box("https://dl.fedoraproject.org/pub/fedora/linux/development/rawhide/Cloud/x86_64/images/", /.*vagrant\.libvirt\.box$/)

    rawhide.vm.provision "common", type: "shell", inline: $bootstrap_rhel_common
    rawhide.vm.provision "shell", inline: <<-SHELL
       dnf install -y openvswitch
    SHELL

    rawhide.vm.synced_folder ".", "/vagrant", type: "rsync"
  end

  config.vm.define "x86_64-c8s" do |centos|
    centos.vm.box = "centos-8-stream"
    centos.vm.box_url = get_box("https://cloud.centos.org/centos/8-stream/x86_64/images/", /.*latest\.x86_64\.vagrant-libvirt\.box$/)

    centos.vm.provision "shell", inline: <<-SHELL
       #{$fix_centos_repositories}!
       dnf config-manager --set-enabled powertools
    SHELL
    centos.vm.provision "common", type: "shell", inline: $bootstrap_rhel_common
    centos.vm.provision "shell", inline: <<-SHELL
       dnf install -y centos-release-nfv-openvswitch
       #{$fix_centos_repositories}!
       dnf install -y openvswitch3.1
    SHELL

    centos.vm.synced_folder ".", "/vagrant", type: "rsync"
  end

  config.vm.define "x86_64-c9s" do |centos|
    centos.vm.box = "centos-9-stream"
    centos.vm.box_url = get_box("https://cloud.centos.org/centos/9-stream/x86_64/images/", /.*latest\.x86_64\.vagrant-libvirt\.box$/)

    centos.vm.provision "common", type: "shell", inline: $bootstrap_rhel_common
    centos.vm.provision "shell", inline: <<-SHELL
       dnf install -y centos-release-nfv-openvswitch
       dnf install -y openvswitch3.1
    SHELL

    centos.vm.synced_folder ".", "/vagrant", type: "rsync"
  end

  config.vm.define "x86_64-c10s" do |centos|
    centos.vm.box = "centos-10-stream"
    centos.vm.box_url = get_box("https://cloud.centos.org/centos/10-stream/x86_64/images/", /.*latest\.x86_64\.vagrant-libvirt\.box$/)

    # The CRB repository is needed for libpcap-devel.
    centos.vm.provision "shell", inline: <<-SHELL
       dnf config-manager --set-enabled crb
    SHELL
    centos.vm.provision "common", type: "shell", inline: $bootstrap_rhel_common
    # Repo https://mirror.stream.centos.org/SIGs/10-stream/nfv/x86_64/openvswitch-2/
    # exists but at the moment does not provide the selinux dependency that's
    # required to install openvswitch. Use a COPR repo instead.
    # Issue tracker: https://issues.redhat.com/browse/RHEL-83794
    centos.vm.provision "shell", inline: <<-SHELL
       rpm --import https://download.copr.fedorainfracloud.org/results/nmstate/ovs-el10/pubkey.gpg
       dnf copr enable -y nmstate/ovs-el10
       dnf install -y openvswitch3.5
    SHELL

    centos.vm.synced_folder ".", "/vagrant", type: "rsync"
  end

  config.vm.define "x86_64-jammy" do |jammy|
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
          python3-dev \
          openvswitch-switch \
          socat \
          nftables \
          make \
          jq

      su vagrant -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -qy"
      python3 -m pip install pytest pyroute2 "scapy>=2.6.1"
    SHELL

    jammy.vm.synced_folder ".", "/vagrant", type: "rsync"
  end

  config.vm.provider "libvirt" do |libvirt|
    libvirt.cpus = 4
    libvirt.memory = 4096
  end
end
