# Vagrant VM matching the paper's testbed exactly:
#   Ubuntu 22.04 LTS, Linux kernel 5.15, Mininet 2.3.0, OVS 2.17.0, Python 3.10.
#
#   vagrant up
#   vagrant ssh
#   cd /vagrant && ./scripts/run_testbed.sh          # real Mininet/Ryu run
#   cd /vagrant && python3.10 run_experiment.py       # pure-Python reproduction
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"        # Ubuntu 22.04 LTS, kernel 5.15
  config.vm.hostname = "sdn-microseg-repro"

  config.vm.provider "virtualbox" do |vb|
    vb.name = "sdn-microseg-repro"
    vb.memory = 4096
    vb.cpus = 4
  end

  config.vm.provision "shell", inline: <<-SHELL
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y python3.10 python3.10-venv python3-pip \
        mininet openvswitch-switch openvswitch-common \
        iperf3 hping3 git build-essential
    uname -r
    ovs-vsctl --version | head -1
    mn --version
    python3.10 -m pip install --upgrade pip
    cd /vagrant
    python3.10 -m pip install -r requirements.txt
    python3.10 -m pip install -r requirements-testbed.txt || \
        echo "Ryu pin optional; pure-Python pipeline unaffected."
    echo "Provisioned. Kernel: $(uname -r)  (paper: 5.15)"
  SHELL
end
