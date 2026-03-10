FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 基础依赖
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    build-essential \
    git \
    pkg-config \
    llvm \
    lld \
    clang \
    && rm -rf /var/lib/apt/lists/*

# 创建非 root 用户 lxy
ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} lxy && \
    useradd -m -u ${UID} -g ${GID} -s /bin/bash lxy

# 切换用户
USER lxy
WORKDIR /home/lxy

# rustup / cargo 用户级目录
ENV CARGO_HOME=/home/lxy/.cargo
ENV RUSTUP_HOME=/home/lxy/.rustup
ENV PATH=/home/lxy/.cargo/bin:$PATH

# 安装 rustup（minimal profile）
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal

# 安装并锁定 nightly
RUN rustup toolchain install nightly-2025-11-22 && \
    rustup default nightly-2025-11-22

# 安装组件
RUN rustup component add \
    llvm-tools-preview \
    rustfmt \
    clippy \
    --toolchain nightly-2025-11-22

# 安装 cargo-fuzz（真正的非 root）
RUN cargo install cargo-fuzz

CMD ["bash"]
