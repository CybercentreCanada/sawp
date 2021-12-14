# SAWP Dockerfile
# ===============
#
# This file is for testing the `make install` command and shouldn't be
# used in production.
#
# Example build command:
# ```
# docker build -f docker/Dockerfile -t sawp:latest .
# ```
FROM centos:7

# Package dependencies to install rust, cbindgen and to build an rpm
RUN (yum makecache \
    && yum install -y \
        gcc \
        make \
        rpm-build \
        wget \
    && yum clean all)

# Install Rust Toolchain
# Steps taken from https://github.com/rust-lang/docker-rust/blob/master/Dockerfile-debian.template
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
ENV RUST_VERSION=1.52.1
ENV RUSTUP_VERSION=1.24.2
ENV RUSTUP_ARCH=x86_64-unknown-linux-gnu
ENV RUSTUP_URL="https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${RUSTUP_ARCH}/rustup-init"

RUN (set -ex && wget -qO rustup-init "${RUSTUP_URL}" \
    && chmod +x rustup-init \
    && ./rustup-init -y \
        --no-modify-path \
        --profile minimal \
        --default-toolchain ${RUST_VERSION} \
        --default-host ${RUSTUP_ARCH} \
    && rm rustup-init \
    && chmod -R a+w ${RUSTUP_HOME} ${CARGO_HOME} \
    && rustup --version \
    && cargo --version \
    && rustc --version)

# Cargo dependencies
RUN cargo install cbindgen

# Install SAWP
RUN mkdir /scratch
COPY . /scratch

# Install SAWP
RUN (cd /scratch \
    && make \
    && make install)

# Alternatively, build and install the rpms
#RUN (cd /scratch \
#    && make \
#    && make rpm \
#    && rpm -ivh /scratch/target/rpmbuild/RPMS/x86_64/*.rpm)

# Post install
RUN ldconfig
