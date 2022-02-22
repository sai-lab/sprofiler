# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "generic/ubuntu2110"

  config.vm.define :sprofiler_dev do |node|

    node.vm.synced_folder ".", "/vagrant", type: "rsync"

    node.vm.provider :libvirt do |domain|
      domain.memory = 8192
      domain.cpus = 4
    end

    # Provisionning requirements
    # - Install sprofiler-bpf build depends
    # - Cgroup v2 enable (Require reboot after provisioning)
    node.vm.provision "shell", inline: <<-SHELL
      curl -Lo sprofiler.deb https://github.com/sai-lab/sprofiler/releases/download/latest/sprofiler_0.1.0_amd64.deb
      apt-get update
      apt-get install -y ./sprofiler.deb podman
    SHELL
  end
end
