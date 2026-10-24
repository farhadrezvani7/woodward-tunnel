# Build and test environment for the Linux desktop bundle (Tauri 2 needs WebKitGTK 4.1 dev files).
# Base image pinned by digest (ubuntu:24.04 index digest, resolved from registry-1.docker.io 2026-10-24).
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config curl wget file ca-certificates git xz-utils \
    libssl-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev \
    libdbus-1-dev libsoup-3.0-dev patchelf nodejs npm dpkg-dev fakeroot \
    xvfb xauth x11-utils x11-apps imagemagick xdotool dbus dbus-x11 gnome-keyring libcap2-bin \
    fonts-dejavu-core libfuse2t64 \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
# rustup-init is pinned to an exact release and verified against the SHA-256 that
# static.rust-lang.org publishes for it (no "curl | sh"); rustup itself verifies the toolchain
# manifests and component hashes. A mismatch fails the image build.
ARG RUSTUP_VERSION=1.29.2
ARG RUSTUP_SHA256_X86_64=5be191e8c70a5007074254cb74d78dbfdd25cd5a61c27de7b8e5410122ec24f4
ARG RUSTUP_SHA256_AARCH64=a9c168dbea81a84671c6b7a5c1795cb0eb699020110d107ddfca427bd797e697
RUN set -eu; \
    case "$(uname -m)" in \
      x86_64) triple=x86_64-unknown-linux-gnu; want="$RUSTUP_SHA256_X86_64" ;; \
      aarch64) triple=aarch64-unknown-linux-gnu; want="$RUSTUP_SHA256_AARCH64" ;; \
      *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${triple}/rustup-init"; \
    echo "${want}  /tmp/rustup-init" | sha256sum -c -; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --profile minimal --default-toolchain stable; \
    rm -f /tmp/rustup-init; \
    chmod -R a+rX /opt/rustup /opt/cargo && rustc --version
# Jobs run as the calling user with their own CARGO_HOME (set by build-desktop.sh).
ENV HOME=/tmp/home
RUN mkdir -p /tmp/home && chmod 1777 /tmp/home
WORKDIR /work
