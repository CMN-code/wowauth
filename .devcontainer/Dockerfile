# Multi-arch image: resolves to linux/arm64 on your M2 — no QEMU emulation.
# Do NOT add --platform=linux/amd64 anywhere; that's what makes Macs slow.
FROM mcr.microsoft.com/devcontainers/base:debian

# just — single static binary, no runtime deps. Installed system-wide.
# Pin a version for reproducibility; bump as you like.
ARG JUST_VERSION=1.51.0
RUN curl --proto '=https' --tlsv1.2 -fsSL https://just.systems/install.sh \
      | bash -s -- --tag "${JUST_VERSION}" --to /usr/local/bin \
    && just --version
