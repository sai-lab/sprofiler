# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "generic/ubuntu2010"

  config.vm.define :iiguni_sprofiler do |node|


    node.vm.synced_folder ".", "/vagrant", type: "rsync"

    node.vm.provider :libvirt do |domain|
      domain.memory = 8192
      domain.cpus = 6
    end

    # Provisionning requirements
    # - Install sprofiler-bpf build depends
    # - Cgroup v2 enable (Require reboot after provisioning)
    node.vm.provision "shell", inline: <<-SHELL
      apt-get update
      apt-get install -y libelf-dev libgcc-s1 libbpf-dev clang curl linux-tools-generic linux-tools-common make podman
      sed -i 's/GRUB_CMDLINE_LINUX=\"\(.*\)\"/GRUB_CMDLINE_LINUX=\"\1 systemd.unified_cgroup_hierarchy=1\"/' /etc/default/grub
      update-grub
    SHELL

    # Install rust and build tools
    node.vm.provision "shell", privileged: false, inline: <<-SHELL
      curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly -y
      source $HOME/.cargo/env
      cargo install cargo-deb libbpf-cargo
    SHELL

  end
end
