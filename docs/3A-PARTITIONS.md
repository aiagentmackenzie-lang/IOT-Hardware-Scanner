# Slice 3A, part 2 — partitioned disk images (release 2.9.0)

Slice 3A built the image map for a single container: a gzip wrapper, its validated
SquashFS extent, and the child file locators. The plan's next row was:

> Extend the same representation to partitioned images and CPIO after the first
> Linux qualification. […] **Accept when** a generated partitioned image with two
> distinct root filesystems maps both into the report, all physical ranges stay in
> bounds, and identical paths in different partitions remain distinguishable.

This is the partitioned-image half. **CPIO is still open** and is not claimed.

---

## 1. Why a disk image used to be an opaque blob

The scanner asked one question of offset zero: is this a SquashFS superblock or a
gzip wrapper? A flash dump or an SD-card image answers neither — offset zero is a
boot sector — so the file was classified as opaque, extraction failed, and every
stage after ingest was unobserved. The artifact was perfectly readable; the
scanner was asking the wrong question.

`squashfs-tools` itself calls such an image a *disk*. So does every flashing tool.
The map now has the same idea: a node whose format is `disk`, children whose
format is `partition`, and each child decoded by its own magic bytes.

## 2. What is decoded

| Table | Fields read | Refused when |
| --- | --- | --- |
| MBR | four 16-byte entries, bootable flag, type id, LBA start/count | signature absent; no non-empty entry; a GPT-protective entry with no GPT behind it |
| Extended MBR | EBR chain, one logical partition per link | the chain loops; a link leaves the image; more than 8 links |
| GPT | header CRC32, entry-array CRC32, entry size/count, first/last LBA, type GUID, unique GUID, UTF-16 label, attributes | signature, CRC, entry size, entry count, an entry that ends before it starts, an entry array past the end of the file |
| Any | `offset + length ≤ file size` | a declared range outside the file (a truncated image) |

Type names are a **stated subset** (`linux`, `linux-swap`, `fat32-lba`, …,
`efi-system`, `linux-filesystem`, `linux-root-arm64`). An id outside it is
reported as `raw-0xNN` or as its GUID. A name that says exactly how much is known
beats one that guesses.

A byte range is validated before it is read, so a truncated image is incomplete
work — `FAILED`, exit 4 — rather than a partition full of holes.

## 3. Coordinates, and why the map did not need a new schema

A partition node carries what every other node carries:

```json
{"artifact_id": "p2", "parent_id": "a0", "format": "partition",
 "coordinate_system": "container-bytes",
 "offset": 34816, "length": 4096,
 "decoder": "ihs-partitions", "decoder_version": "1",
 "details": {"scheme": "gpt", "partition_index": 2, "label": "rootfs-b",
             "type_id": "0fc63daf-8483-4772-8e79-3d69d8477de4",
             "type_name": "linux-filesystem", "start_hex": "0x00008800",
             "end_hex": "0x00009800", "content": "squashfs", "file_count": 3,
             "extraction_state": "OK"}}
```

`offset`/`length` are bytes in the **container**, and `coordinate_system` says so;
the extracted root's file locators are a different coordinate system and are not
mixed with it. Because `image_map.nodes[]`, `details` and `inventory.roots[]`
(`root_id`, `artifact_id`) already existed, **report schema 8 is unchanged** and
there is no migration. The evidence for that is mechanical: `SCHEMA_VERSION` is
still 8 and the schema-compatibility fixtures still pass untouched.

## 4. Two roots, and the bug the second one exposed

Each partition is sliced into private scratch (streamed, hashed, budgeted), decoded
by its own magic, and extracted by the same pinned worker a single-image scan uses.
Roots are numbered `rootfs1`, `rootfs2`, … and each `RootIdentity` names the
partition node it came from.

The first run with two roots produced **one** location, `rootfs/etc/shadow:1` for
both partitions. Two defects, both real, both older than this slice:

1. the account join derived a location's qualifier from the extracted directory's
   **basename** — and both partitions extract into a directory called `rootfs`;
2. the qualifier was then used as the *path* to compute the relative location, so
   once it became an identity (`rootfs2`) the relative path could not be computed
   and the fallback emitted an absolute scratch path — unstable across hosts and
   useless in a report.

The fix separates the two: `_rel_label(path, root_id, root_dir=…)` takes the
**identity** for the label and the **directory** for the relative calculation, and
the identity comes from `inventory.roots[]`, not from `Path(...).name`. A finding
now reads `rootfs2/etc/shadow:1`, which is what the acceptance row asks for.

## 5. What a partitioned scan reports

* one `disk` node with the scheme and partition count;
* one `partition` node per table entry, with its declared range and type;
* per-partition `details.content`: `squashfs`, `gzip`, `unrecognised`, or
  `undecodable`, plus `file_count` and `extraction_state` — a bootloader partition
  and a `uboot-env` blob are recorded, not failed over;
* one root per extracted filesystem, each with its `artifact_id`;
* `extraction` stage `PARTIAL` when some partitions yielded no filesystem, and
  `eligible` = partitions, `inspected` = filesystem partitions.

A disk image with **no** filesystem partition exits 4 (incomplete) or 5 (worker
unavailable); it never exits 0 as "clean".

## 6. Bounds

| Bound | Value |
| --- | --- |
| sectors read for a table | 1 boot sector, plus 1 per EBR link |
| GPT entries | ≤ 4096, entry size a multiple of 128, array ≤ 512 KiB |
| EBR chain | ≤ 8 links, cycle-checked |
| partition slice | exactly its declared length, streamed in ≤ 1 MiB windows |
| LBA size | 512 bytes; a 4Kn disk is not claimed |

## 7. Gates

| Gate | Command | Result |
| --- | --- | --- |
| Lint / format | `ruff check src/ tests/ benchmarks/`, `ruff format --check` | clean |
| Types | `mypy src/` | clean, 42 source files |
| Tests | `pytest` (local, macOS arm64, CPython 3.12.14, colima worker) | **1094 collected, 1078 passed, 0 failed, 16 skipped** — with the worker present the container rows run here; the reference-image rows still need the corpus |
| Partitions, unit | `pytest tests/test_partitions.py` | 21 passed — MBR, EBR chain, GPT + both CRCs, bounds, truncation, map nodes, slicing |
| Partitions, end to end | `pytest tests/test_installed_image_cli.py::TestPartitionedImage` | **1 passed** — two generated SquashFS roots in one GPT image, through the installed CLI |

The end-to-end case builds its own disk image with the worker's `mksquashfs`, so
it runs wherever the pinned image is present (the `linux-extractor` job) and skips
with a stated reason where it is not.

## 8. Still not claimed

* **CPIO** — the other half of the plan's sentence. Not started.
* **JFFS2 / UBIFS** — flash filesystems, not containers; each needs its own gate.
* **RAUC bundles** (3E) — slot mapping and signature verification, next.
* **Raw NAND** — page/spare/eraseblock geometry, with the two-fixture rule.
* **Comparison** — `compare` does not yet diff two disk images. The partitions are
  recorded in each document; a release-to-release identity for a disk layout is a
  separate contract this release does not claim.
