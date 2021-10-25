# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "fedora/34-cloud-base"

  config.vm.define :sprofiler_dev do |node|

    node.vm.synced_folder ".", "/vagrant", type: "rsync"
    node.vm.synced_folder "./integration_test/sprofiler-bpf/hooks", "/usr/share/containers/oci/hooks.d", type: "rsync"

    node.vm.provider :libvirt do |domain|
      domain.memory = 8192
      domain.cpus = 6
    end

    # Provisionning requirements
    # - Install sprofiler-bpf build depends
    # - Cgroup v2 enable (Require reboot after provisioning)
    node.vm.provision "shell", inline: <<-SHELL
      dnf install -y clang curl make podman libbpf elfutils-libelf-devel zlib bpftool
      curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly -y
      source $HOME/.cargo/env
      cargo install libbpf-cargo
      cd /vagrant
      bpftool btf dump file /sys/kernel/btf/vmlinux format c > /vagrant/sprofiler-bpf/src/bpf/vmlinux.h
      cargo libbpf make
      cargo install --path ./sprofiler
      cargo install --path ./sprofiler-bpf
    SHELL
  end
end
