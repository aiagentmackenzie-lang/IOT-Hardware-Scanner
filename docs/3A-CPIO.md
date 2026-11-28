# Slice 3A, part 3 — CPIO initramfs archives (release 2.10.0)

Slice 3A built the image map for one container; part 2 extended it to a disk with
partitions. The plan's sentence had a third half:

> Extend the same representation to partitioned images and CPIO after the first
> Linux qualification.

This is the CPIO half, and it is the first container this scanner decodes
**without a worker**. An initramfs is a sequence of headers, not a compressed
filesystem that needs a kernel-side tool, so a whole class of firmware that
previously required Docker can now be read on any host, offline.

---

## 1. Why this is not a small change

The obvious reading of "add CPIO" is a loop over headers. Three details make it a
slice worth its own record, and each has a case in `tests/test_cpio.py`:

| Trap | What it does to a naive reader | What this release does |
| --- | --- | --- |
| A hard link's zero-length member | `newc` stores the bytes once per group of names; every other member declares `filesize = 0`. Reading that literally materialises a 0-byte `/etc/shadow` and reports **a weaker finding than the artifact supports** | the group is resolved by `(dev, ino)`; every name shares the carrier's digest and size, and the link is created as a real hard link so the scanner's inode reconciliation still sees one file |
| `odc` has no padding at all | every field is octal and the name/data are **not** aligned; a `newc`-shaped reader walks off the record and produces a plausible tree of nonsense | layout is chosen per archive magic, and a record whose magic disagrees with the archive's stops the walk |
| `crc`'s check field | the format calls it a CRC; it is the sum of the data bytes. "Read it" is not "check it" | the sum is accumulated while the bytes are written and compared; a mismatch is a named failure, not a number copied into the report |

Two more, smaller ones: the `TRAILER!!!` record is the only end marker, so its
absence is truncation and not "the last member was the last file"; and a member
name is data that becomes a path, so it is validated at **decode**, before the map
has a locator for it and before any caller could write it.

## 2. What is decoded

| Layout | Magic | Header | Padding | Check |
| --- | --- | --- | --- | --- |
| `newc` | `070701` | 110 bytes, thirteen 8-digit hex fields | name and data to 4 bytes | none (`0`) |
| `crc` | `070702` | same | same | sum of data bytes, verified |
| `odc` | `070707` | 76 bytes, six-digit octal fields (11 for mtime/filesize) | **none** | none |
| binary | `C7 71` | — | — | refused by name |

Binary CPIO is the trap that has no fixture: its magic is decimal `070707` stored
as a 16-bit word, so a reader that matches the *text* `070707` will refuse it — and
a reader that matches the *integer* will happily misparse the older format as
`odc`. It is detected and refused with its own message.

Every member becomes a node with `coordinate_system: "container-bytes"`, its data
offset and length, its archive mode, uid, gid, nlink and mtime, and its decoder
(`ihs-cpio/1`). A hard link's node points at the carrier's byte range and records
`declared_data_length: 0` and `hardlink_of`, because "0 is what the archive says"
and "25 is what the name resolves to" are two different true statements.

## 3. Extraction, and why there is no worker

| Kind | Materialised | Recorded |
| --- | --- | --- |
| `dir` | yes | mode, uid, gid |
| `file` | yes, streamed in ≤ 1 MiB windows, hashed, mode applied | mode, uid, gid, nlink, mtime, sha256 |
| `hardlink` | as a real link to the carrier | carrier path, carrier digest, declared length |
| `symlink` | **no** | target, mode |
| `char` / `block` | **no** | mode, `rdev` major:minor |
| `fifo` / `socket` | **no** | mode |

The manifest the extractor writes (`extract-manifest.json`) is the same shape the
SquashFS worker writes, so the enumeration stage reads archive-derived metadata
with `metadata_source: "image"` and no code changed: a permission conclusion rests
on the artifact, not on this host. Ownership is recorded from the headers and the
permission bits are applied with `chmod`; `uid`/`gid` are **not** applied, because a
non-root process cannot, and pretending otherwise would put a host fact where an
image fact belongs.

A `crc` member that fails its own checksum fails the **stage** (`FAILED`, exit 4).
A partition full of plausible bytes whose check field disagrees with them is not
evidence.

## 4. Where it plugs in

* `scan image.cpio` — the root node is `cpio`.
* `scan image.cpio.gz` — the gzip child is settled by **its own header** (2.4's
  rule), so the wrapper's name does not decide the format. The child node is
  `cpio`, the wrapper stays `gzip`.
* A partition whose bytes are an archive — `details.content: "cpio"`, decoded
  in-process while the other partitions in the same image still go through the
  worker. One image can legitimately need both.
* Ingest labels the artifact `CPIO archive (initramfs, newc)` with
  `file_type_source: "magic-bytes"`, because the header proves it and a `.cpio`
  suffix would have claimed less.

## 5. The one report change: schema 9

`extraction.backend` names the decoder that produced the tree. Before it, an
in-process decode and a worker whose provenance was lost looked identical — both
had `state: ok` and no worker fields. A v8 document upgrades with
`backend: null` ("not recorded"), never `"none"`; see
[docs/MIGRATION-v9.md](MIGRATION-v9.md). No profile, detector or control changed:
schema 9, profile 6.0.

## 6. Bounds

| Bound | Value |
| --- | --- |
| records | `max_extracted_entries` (200,000) |
| declared data | `max_decoded_bytes_mb` (1 GiB) |
| a symlink target | 4,096 bytes (a sanity bound, not a budget) |
| a member's data read | streamed, ≤ 1 MiB windows, exactly its declared length |
| a name | no absolute path, no `..` component, no NUL, NUL-terminated inside its field |
| the archive | must end in `TRAILER!!!`; bytes after it are reported, and a second archive makes the stage `PARTIAL` |
| the address space | never materialised; the map costs one node per record |

## 7. Gates

| Gate | Command | Result |
| --- | --- | --- |
| Lint / format | `ruff check src/ tests/ benchmarks/`, `ruff format --check` | clean |
| Types | `mypy src/` | clean, 43 source files |
| Tests | `pytest` (local, macOS arm64, CPython 3.12.14, colima worker, no reference corpus) | **1125 passed, 0 failed, 16 skipped**, 86 % — the sixteen are the reference-image and container-oracle rows |
| CPIO unit | `pytest tests/test_cpio.py` | **40 rows** — layout, padding, `odc` widths, hard links, symlinks, specials, `crc`, truncation, unsafe names, budgets, map coordinates |
| CPIO end to end | `pytest tests/test_installed_image_cli.py::TestCpioInitramfs` | **5 rows** through the installed CLI: newc, gzip-wrapped, odc, a zero-length hard-link member, and a truncated archive (exit 4, no traceback) |
| CPIO, hostile | `pytest tests/test_hostile_inputs.py` | **4 of the 19 scan cases** — a declared size past the end, a traversal name, a missing trailer, and the binary magic: each exit 4 with a named stage and no traceback |

Every CPIO row runs on any host: no container runtime, no reference corpus, no
network.

## 8. Still not claimed

* **A concatenated initramfs.** A second archive after the trailer is recorded and
  makes extraction `PARTIAL`; only the first is inventoried.
* **Symlinks are not materialised.** They are evidence, not structure; a scanner
  that followed them would index files that do not exist in the tree.
* **Archive ownership is not applied.** Mode bits are; uid/gid are recorded.
* **`compare` does not diff two initramfs trees.** Findings and packages compare as
  they already did; a tree-level identity contract is not this slice.
* **JFFS2 / UBIFS** are flash filesystems, not containers, and each needs its own
  gate. **RAUC bundles** (3E) and **raw NAND** remain the open capability rows.
