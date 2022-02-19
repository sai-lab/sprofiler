# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "generic/ubuntu2110"

  config.vm.define :sprofiler_dev do |node|

    node.vm.synced_folder ".", "/vagrant", type: "rsync"
    node.vm.synced_folder "./integration_test/sprofiler-bpf/hooks", "/usr/share/containers/oci/hooks.d", type: "rsync"

    node.vm.provider :libvirt do |domain|
      domain.memory = 8192
      domain.cpus = 4
    end

    # Provisionning requirements
    # - Install sprofiler-bpf build depends
    # - Cgroup v2 enable (Require reboot after provisioning)
    # node.vm.provision "shell", inline: <<-SHELL
    #   curl https://sh.rustup.rs -sSf | sh -s -- -y
    #   source $HOME/.cargo/env
    #   cargo install libbpf-cargo
    #   cd /vagrant
    #   bpftool btf dump file /sys/kernel/btf/vmlinux format c > /vagrant/sprofiler-bpf/src/bpf/vmlinux.h
    #   cargo libbpf make
    #   cargo install --path ./sprofiler
    # SHELL
    node.vm.provision "shell", inline: <<-SHELL
      curl -O https://github.com/sai-lab/sprofiler/releases/download/latest/sprofiler_0.1.0_amd64.deb
      apt update
      apt intall -y sprofiler_0.1.0_amd64.deb
    SHELL
  end
end
