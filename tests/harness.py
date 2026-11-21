"""The installed-CLI harness: run the scanner the way a user does.

Two execution modes, chosen automatically:

``IHS_INSTALLED_CLI`` set
    The path to a console script installed from the built wheel in a clean
    environment. This is what CI uses, and it is the only mode that proves the
    wheel contains its rules, data and ELF reader.

otherwise
    The package is copied out of the checkout into a temporary site directory
    and run with ``python -m iot_hardware_scanner`` and ``PYTHONPATH`` pointing
    there. That still proves the import path and resource loading do not depend
    on the source tree, but it does not prove wheel packaging.

Neither mode reaches the network: every scan passes ``--offline`` and the
fixtures are generated locally.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SRC = REPO_ROOT / "src" / "iot_hardware_scanner"


class Runner:
    """Invoke the scanner the way a user would, from an unrelated directory."""

    def __init__(self, argv_prefix: list[str], env_extra: dict[str, str], mode: str) -> None:
        self.argv_prefix = argv_prefix
        self.env_extra = env_extra
        self.mode = mode

    def __call__(
        self, args: list[str], cwd: Path, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        """Run one command with a minimal, explicit environment."""
        # The interpreter comes first; the caller's PATH is kept so a container
        # runtime (docker/podman) is found where the operator installed it.
        environment = {
            "PATH": os.pathsep.join(
                [os.path.dirname(sys.executable), os.environ.get("PATH", "/usr/bin:/bin")]
            ),
            "HOME": str(cwd),
            **self.env_extra,
            **(env or {}),
        }
        return subprocess.run(
            [*self.argv_prefix, *args],
            cwd=str(cwd),
            env=environment,
            capture_output=True,
            text=True,
            timeout=900,
        )


def build_runner(site_dir: Path) -> Runner:
    """The runner for this session: the installed wheel if one was named."""
    installed = os.environ.get("IHS_INSTALLED_CLI")
    if installed:
        return Runner([installed], {}, "wheel")
    return Runner(
        [sys.executable, "-m", "iot_hardware_scanner"],
        {"PYTHONPATH": str(site_dir), "PYTHONNOUSERSITE": "1"},
        "relocated-copy",
    )


def make_tree(root: Path, shadow: str) -> Path:
    """A minimal staged tree with an account database."""
    (root / "etc").mkdir(parents=True, exist_ok=True)
    (root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/ash\nuser:x:1000:1000:user:/home/user:/bin/ash\n"
    )
    (root / "etc" / "shadow").write_text(shadow)
    return root
