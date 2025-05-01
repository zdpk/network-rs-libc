FROM ubuntu:22.04

# Install base packages and update
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    libpcap-dev \
    pkg-config \
    # Network tools
    arping \
    tcpdump \
    iputils-ping \
    net-tools \
    iproute2 \
    ncat \
    netcat \
    gh \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    && rustup default stable \
    && rustup component add rustfmt clippy \
    && cargo install cargo-edit cargo-watch

# Set working directory
WORKDIR /workspace

# Set environment variables
ENV USER=root
ENV HOME=/root

# Set default shell
CMD ["bash"]

# Grant network capabilities to tcpdump
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump

# Change to root user
USER root