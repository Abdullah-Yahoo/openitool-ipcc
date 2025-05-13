import asyncio
import glob
import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, List, Literal, Optional, Tuple, TypeVar

from models import Error, Firmware, Ok, Result

# for json writing callbacks
J = TypeVar("J")


def check_file_existence_in_branch(branch: str, file_path: str) -> bool:
    command = f"git ls-tree -r --name-only {branch} -- {file_path}"
    result = subprocess.run(command.split(), stdout=subprocess.PIPE, check=True)

    return str(result.stdout).strip() != ""


def copy_previous_metadata(ident: str) -> None:
    ignored_firms_file_name = "ignored_firmwares.json"
    ignored_firms_exists = check_file_existence_in_branch("files", f"{ident}/{ignored_firms_file_name}")

    metadata_file_name = "metadata.json"
    metadata_exists = check_file_existence_in_branch("files", f"{ident}/{metadata_file_name}")

    command = lambda file, ident=ident: f"git show files:{ident}/{file}"

    Path(ident).mkdir(exist_ok=True)

    if ignored_firms_exists:

        with open(ignored_firms_file_name, "w") as f:
            subprocess.run(command(ignored_firms_file_name).split(), stdout=f, check=True)

    if metadata_exists:

        with open(metadata_file_name, "w") as f:
            subprocess.run(command(metadata_file_name).split(), stdout=f, check=True)

async def calculate_hash(file_path: Path) -> Tuple[str, str]:
    def hash(algo: Literal["sha1", "md5"]):
        hash_func = getattr(hashlib, algo)()
        with file_path.open("rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                hash_func.update(chunk)

        return hash_func.hexdigest()

    return (hash("sha1"), hash("md5"))


async def compare_either_hash(file_path: Path, firmware: Firmware) -> bool:
    sha1, md5 = await calculate_hash(file_path)

    return sha1.strip() == firmware.sha1sum.strip() or md5.strip() == firmware.md5sum.strip()


async def put_metadata(
    metadata_path: Path, key: str, callback: Callable[[Optional[J]], J]
) -> Result[None, str]:
    """Read & update JSON metadata using a callback."""
    try:
        metadata = json.loads(metadata_path.read_text() or "{}")
        metadata[key] = callback(metadata.get(key))
        metadata["updated_at"] = datetime.now(UTC).isoformat()
        metadata_path.write_text(json.dumps(metadata, indent=4))
    except json.JSONDecodeError as e:
        return Error(f"Invalid JSON: {e}")
    return Ok(None)


async def bundles_glob(path: Path, has_parent: bool = False) -> List[Path]:
    return list(
        map(
            lambda s: Path(s).resolve(),
            glob.glob(
                f"{path}/{'*/' if has_parent else ''}System/Library/Carrier Bundles/**/*.bundle"
            ),
        )
    )


async def delete_non_bundles(
    base_path: Path, bundles: List[Path], has_parent: bool = False
) -> Result[List[Path], str]:
    try:
        for bundle in bundles:
            shutil.move(bundle, base_path / bundle.name)

        if has_parent:
            system_dirs = list(base_path.glob("*/System"))
            if not system_dirs:
                return Error("No nested 'System' folder found")
            path = system_dirs[0].parent
        else:
            path = base_path / "System"

        if path.exists():
            shutil.rmtree(path, ignore_errors=True)

        return Ok([base_path / bundle.name for bundle in bundles])

    except Exception as e:
        return Error(f"Failed to clean up: {e}")


async def system_has_parent(dmg_file: Path) -> Result[bool, str]:
    proc = await asyncio.create_subprocess_exec(
        "7z",
        "l",
        dmg_file,
        "*/System",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    if proc.stdout is None or proc.stderr is None:
        return Error("Failed to capture stdout/stderr from 7z")

    lines = set()

    start_collecting = False

    while True:
        # TODO: sometimes it freezes

        # stderr_data = await proc.stderr.read()
        #
        # if stderr_data:
        #     return Error(stderr_data.decode(errors="ignore"))

        line = await proc.stdout.readline()

        if line == b"":
            break

        if b"Date" in line and b"Time" in line:
            start_collecting = True

        if start_collecting:
            lines.add(line)

            if len(lines) > 10:
                break

    try:
        proc.kill()
    except ProcessLookupError:
        pass

    return Ok(len(lines) > 10)
