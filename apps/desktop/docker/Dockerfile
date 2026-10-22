# Build and test environment for the Linux desktop bundle (Tauri 2 needs WebKitGTK 4.1 dev files).
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config curl wget file ca-certificates git xz-utils \
    libssl-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev \
    libdbus-1-dev libsoup-3.0-dev patchelf nodejs npm dpkg-dev fakeroot \
    xvfb xauth x11-utils x11-apps imagemagick xdotool dbus dbus-x11 gnome-keyring libcap2-bin \
    fonts-dejavu-core libfuse2t64 \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && chmod -R a+rX /opt/rustup /opt/cargo && rustc --version
# Jobs run as the calling user with their own CARGO_HOME (set by build-desktop.sh).
ENV HOME=/tmp/home
RUN mkdir -p /tmp/home && chmod 1777 /tmp/home
WORKDIR /work
