# Pinned extraction worker for IoT Hardware Scanner.
#
# Contains upstream unsquashfs (squashfs-tools) and nothing else the scanner
# calls at scan time. The scanner runs this image read-only, with no network,
# no capabilities, a size-limited tmpfs and memory/pid/CPU limits, and streams
# the extracted tree to the host over a pipe.
#
# mksquashfs is included so the test suite can build controlled fixtures, and
# binutils so release verification can compare the scanner's ELF facts with
# readelf. Neither is used during a scan.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update \
 && apt-get install -y --no-install-recommends squashfs-tools=1:4.5.1-1 binutils \
 && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/usr/bin/unsquashfs"]
