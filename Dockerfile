# =============================================================================
# Dockerfile -- reproducible environment matching the paper's testbed
#   Ubuntu 22.04 LTS, Python 3.10, Mininet 2.3.0, OVS 2.17.0, Ryu, OF 1.3
# =============================================================================
# Build:  docker build -t sdn-microseg-repro .
#
# Pure-Python reproduction (works in any container/host):
#   docker run --rm -v "$PWD/results:/app/results" -v "$PWD/figures:/app/figures" \
#              sdn-microseg-repro python run_experiment.py
#
# Real Mininet/Ryu testbed (needs kernel access):
#   docker run --rm -it --privileged --network host \
#              -v /lib/modules:/lib/modules sdn-microseg-repro bash
#   # then inside:  ./scripts/run_testbed.sh
# -----------------------------------------------------------------------------
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# --- system: python 3.10 (default on 22.04) + testbed tooling -----------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3.10 python3.10-venv python3-pip \
        mininet openvswitch-switch openvswitch-common openvswitch-testcontroller \
        iperf3 hping3 iproute2 net-tools tcpdump \
        git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt requirements-testbed.txt ./

# --- pure-Python reproduction stack (paper pins) -----------------------------
RUN python3.10 -m pip install --no-cache-dir --upgrade pip \
    && python3.10 -m pip install --no-cache-dir -r requirements.txt

# --- testbed extras (Ryu 4.34 / eventlet 0.30.2 / Scapy 2.5.0) --------------
RUN python3.10 -m pip install --no-cache-dir -r requirements-testbed.txt || \
    echo "WARNING: Ryu/eventlet pin failed to build; pure-Python pipeline still works."

COPY . .

# record the built environment for the metadata step
RUN python3.10 -c "import sys,platform,sklearn,numpy,pandas; \
    print('py', sys.version.split()[0], platform.platform()); \
    print('sklearn', sklearn.__version__, 'numpy', numpy.__version__, 'pandas', pandas.__version__)"

CMD ["python3.10", "run_experiment.py"]
