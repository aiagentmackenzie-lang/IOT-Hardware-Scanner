# syntax=docker/dockerfile:1
#
# Pinned extraction worker for IoT Hardware Scanner.
#
# A scan runs this image read-only, with no network, no capabilities, a
# size-limited tmpfs and memory/pid/CPU limits, and streams the extracted tree
# to the host over a pipe. The runtime image therefore carries exactly one
# helper a scan calls: upstream `unsquashfs` from `squashfs-tools`.
#
# Reproducibility (milestone D, §2.1)
# -----------------------------------
# The package set is pinned twice over: to a Debian snapshot date, so the
# repository that served the archive still exists, and to exact versions in
# `packages.txt`, so nothing resolves at build time. `binutils` (readelf),
# `device-tree-compiler` (fdtdump/fdtget) and `u-boot-tools` (mkimage -l) are
# used only by release verification to cross-check the scanner's ELF and
# FDT/FIT facts, never by a scan, so they live in the `verification` stage.
#
# The Docker image *id* is deliberately not claimed reproducible: the image
# configuration records a build timestamp, so two builds of identical content
# can still hash differently. The reproducible facts are this file's digest,
# the package list and `unsquashfs -version`; the CI job prints all three and
# records the id it observed.
#
# Stages:
#   base          snapshot-pinned, package-pinned Debian with squashfs-tools
#   verification  base + binutils, device-tree-compiler and u-boot-tools.
#                 Built as `ihs-squashfs-worker:4.5.1-verify`; never the
#                 default target.
#   runtime       the default (last) stage; no binutils.

ARG DEBIAN_BASE=debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
ARG DEBIAN_SNAPSHOT=20251101T000000Z

FROM ${DEBIAN_BASE} AS base
ARG DEBIAN_SNAPSHOT

# APT reads the archive over HTTP: the slim base carries no CA bundle, and
# snapshot.debian.org redirects to a content-addressed file URL that does not
# expire. `check-valid-until` is off because a snapshot's Release file is old by
# definition; the pinning is the protection, not the expiry date.
RUN rm -f /etc/apt/sources.list.d/* \
 && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s bookworm main\n' \
      "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list \
 && rm -rf /var/lib/apt/lists/*

COPY packages.txt /tmp/packages.txt

# Install the exact set, with no recommends and no upgrade of the base: the
# shell expansion is the whole list, so every installed version is named.
RUN apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends $(grep -v '^#' /tmp/packages.txt) \
 && rm -rf /var/lib/apt/lists/* /tmp/packages.txt

# Verification stage: readelf for the ELF cross-check, fdtdump/fdtget and
# mkimage for the FDT/FIT cross-check. The scanner never invokes anything from
# this stage, and the runtime image below does not contain these tools.
FROM base AS verification
COPY packages-verify.txt /tmp/packages-verify.txt
RUN apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends $(grep -v '^#' /tmp/packages-verify.txt) \
 && rm -rf /var/lib/apt/lists/* /tmp/packages-verify.txt

# Runtime stage (default target). `unsquashfs -version` prints its banner and
# exits 1 by design; callers read it through a pipe.
FROM base AS runtime
ENTRYPOINT ["/usr/bin/unsquashfs"]
