# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # Define Fedora36 VM
  config.vm.define "f36" do |fedora|
    fedora.vm.box = "fedora/36-cloud-base"

    fedora.vm.provision "shell", inline: <<-SHELL
       dnf install -y \
           rust \
           cargo \
           clang \
           llvm \
           rustfmt \
           elfutils-libelf-devel \
           zlib-devel \
           libpcap-devel \
           git
    SHELL
  end

  config.vm.provider "libvirt" do |libvirt|
    libvirt.cpus = 4
    libvirt.memory = 4096
  end
end
