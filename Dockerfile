FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies for MariaDB
RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    libncurses5-dev \
    libssl-dev \
    libgnutls28-dev \
    bison \
    libpam0g-dev \
    libboost-dev \
    zlib1g-dev \
    libreadline-dev \
    libcurl4-openssl-dev \
    libxml2-dev \
    libaio-dev \
    libsystemd-dev \
    libevent-dev \
    libcrack2-dev \
    libsnappy-dev \
    liblz4-dev \
    libbz2-dev \
    liblzma-dev \
    libzstd-dev \
    libjemalloc-dev \
    libpcre2-dev \
    liburing-dev \
    gnutls-dev \
    pkg-config \
    perl \
    python3 \
    python3-pip \
    git \
    gdb \
    ccache \
    && rm -rf /var/lib/apt/lists/*

# Install Python mysql connector for the reproducer script
RUN pip3 install --break-system-packages mysql-connector-python

# Set up ccache
ENV CCACHE_DIR=/ccache
ENV PATH="/usr/lib/ccache:${PATH}"

WORKDIR /src

# Default command keeps container running
CMD ["sleep", "infinity"]
