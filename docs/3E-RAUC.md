# Slice 3E — a RAUC bundle is a proposed device state (release 2.11.0)

Slice 3A taught the scanner to see containers; parts 2 and 3 added a disk and an
initramfs. Slice 3E is the first input that describes **a device that does not
exist yet**: an update bundle, whose whole purpose is to become the running
system after the next reboot.

The plan's row:

> Interpret an update bundle as a proposed device state. […] Start with RAUC. Read
> its manifest, board compatibility and mapping of payloads to slot classes. Verify
> declared payload digests, label the release image and recovery image separately,
> and report signature verification against the supplied trust store. Carry slot
> references into file and component findings. […] **Accept when** a generated
> bundle containing distinct system and recovery payloads lists each exactly once,
> reports which payload contains a seeded finding, and marks the running slot
> unknown. A manifest mismatch invalidates the affected association. Supplying a
> partial update alone cannot make a previously reported component appear removed.

---

## 1. What a bundle is

A RAUC bundle (`.raucb`) is a **SquashFS image** whose root holds:

* `manifest.raucm` — an INI document naming the board (`[update] compatible`), the
  release version, and one `[image.<slot-class>]` section per payload, each with
  `filename`, `sha256` and `size`;
* the payload images themselves (`rootfs.squashfs`, `recovery.squashfs`, an ext4
  `appfs`, …);
* optionally a custom handler script, and a detached CMS signature appended after
  the filesystem.

Nothing in that description says which slot is running. That is a fact about the
device at boot time, so `running_slot` is `"unknown"` in every document this release
writes, and no code path infers it from slot order or version numbers.

## 2. The decision that makes this honest

**A payload is associated with its slot only if its bytes are the bytes the
manifest declared.** Four states, and only one of them may carry evidence:

| State | Meaning | Slot association |
| --- | --- | --- |
| `VERIFIED` | declared size **and** declared SHA-256 both match the file in the bundle | yes — the payload is decoded and becomes a root |
| `MISMATCH` | size or digest disagrees | **no** — listed, hashed, and never decoded |
| `MISSING` | the manifest names a file the bundle does not carry | no |
| `UNCHECKED` | no digest was declared (older `format=plain` bundles), or none was computed | no |

`UNCHECKED` is not a soft pass. A bundle whose manifest says nothing about a
payload is a bundle whose payload cannot be trusted, and it is reported that way
rather than decoded to look complete.

The invalidation is per payload, not per bundle: a tampered `rootfs` does not stop
the `recovery` image from being verified and decoded. That is what the plan's
"invalidates the affected association" means.

## 3. Slots become roots

Each verified payload is decoded by exactly the machinery a single image uses
(`_decode_partition`: bare SquashFS, gzip-wrapped SquashFS, or CPIO), and the resulting
root is named by its **slot class** through the existing `root_sources` mechanism:

```
inventory.roots[]        root_id      artifact_id
                         bundle       a1            the bundle's own tree: manifest, hooks, payloads
                         rootfs       rauc-rootfs   the decoded system payload
                         recovery     rauc-recovery the decoded recovery payload
```

Because locators are already root-qualified (2.9.0), a finding reads
`rootfs/etc/shadow:1` and a reader can name the payload without a lookup table.
`rauc.images[].root_id` is the same name, so the section and the inventory cannot
drift apart.

A payload that is not a container this release decodes — an ext4 `appfs`, a raw
kernel — is `VERIFIED` and *not* decoded, with the reason in `diagnostics`. It is
not silently dropped and it is not guessed at.

## 4. The signature

RAUC appends a detached CMS block after the SquashFS filesystem, which this scanner
already measures: the superblock's `bytes_used` is `extent_bytes` on the map node,
and everything after it is the signature.

```json
"signature": {"present": true, "bytes": 3452, "verified": null,
              "reason": "a detached signature is present; verifying it needs a trust store and a CMS verifier, and this release supplies neither for RAUC bundles"}
```

`verified` is `null`, not `false`. A signature nobody checked is not an invalid
signature, and the difference is exactly the one 3D drew between "no key supplied"
and "signature does not match". Supplying a trust store without a verifier would be
worse than useless, so the field says what is missing.

## 5. Hooks are artifacts, never code

A custom handler named by `[handler]` (or by `hooks=` on an image) lives inside the
bundle's own root, so the ordinary enumeration scans it as a file, with its digest
and mode, and the rule set gets its chance. Nothing executes it. The manifest's
handler section is recorded in `rauc.handler` so a reader can see which script the
bundle intends to run on the device.

## 6. Bounds

| Bound | Value |
| --- | --- |
| manifest | read whole (it is a manifest, not payload data) and parsed with `configparser`, duplicate sections refused |
| a payload's digest | streamed in ≤ 1 MiB windows under `max_decoded_bytes_mb`; a payload over budget is `UNCHECKED`, never assumed |
| a payload path | resolved and required to stay inside the bundle root, or it is not read |
| a payload's decode | the same budgets, worker and refusal path as any other image |
| the section | one entry per `[image.*]` section; a duplicate section is a parse error, because merging it would silently drop a payload |

## 7. Gates

| Gate | Command | Result |
| --- | --- | --- |
| RAUC unit | `pytest tests/test_rauc.py` | **26 rows** — manifest parse, duplicate sections refused, slot naming, every payload state, the invalidation rule, signature presence |
| RAUC end to end | `pytest tests/test_installed_image_cli.py::TestRaucBundle` | **2 rows** through the installed CLI: a generated two-payload bundle (each listed once, the finding attributed to `rootfs/`, running slot unknown, signature present and unverified) and a manifest digest that disagrees (that slot invalidated, the other still verified, its findings absent) |
| Schema | `pytest tests/test_schema_compat.py` | 1 → 10 with the exact upgrade result per version |

The end-to-end rows build their own bundle with the pinned worker's `mksquashfs` and
therefore run wherever the worker image is present (the `linux-extractor` job).

## 8. Still not claimed

* **Signature verification.** Presence and byte count only; `verified` is `null`
  with the reason. A CMS verifier and a supplied trust store are the next increment.
* **Delta / partial updates.** A bundle that needs a base image is recorded as a
  bundle; the "this partial update alone cannot remove a component" row belongs to
  `compare`, which does not yet diff two bundles.
* **A bundle inside a partition.** The phase runs for a top-level image. A bundle in
  a disk partition would need the partition's extraction result to be re-entered.
* **ext4 payloads.** Verified, not decoded; there is no ext4 reader in this release.
* **FIT-signed bundles, UBI, SWUpdate, Mender.** One format is qualified, as the
  plan requires.
