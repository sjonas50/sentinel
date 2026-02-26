"""Service for invoking the Rust sentinel-pathfind binary."""

from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any


class PathfindError(Exception):
    """Raised when the pathfind subprocess fails."""


async def run_pathfind(
    command: str,
    request: dict[str, Any] | None = None,
    *,
    extra_args: list[str] | None = None,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Invoke the Rust sentinel-pathfind binary with a JSON request.

    Args:
        command: Subcommand to run (compute, blast-radius, shortest).
        request: JSON-serializable request body (passed via stdin).
        extra_args: Additional CLI arguments.
        timeout: Maximum seconds to wait.

    Returns:
        Parsed JSON response from stdout.

    Raises:
        PathfindError: If the binary is not found, exits non-zero, or times out.
    """
    binary = shutil.which("sentinel-pathfind")
    if binary is None:
        raise PathfindError(
            "sentinel-pathfind binary not found in PATH. "
            "Build with: cargo build -p sentinel-pathfind --release"
        )

    args = [binary, command]
    if extra_args:
        args.extend(extra_args)

    stdin_data = json.dumps(request).encode() if request else None

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE if stdin_data else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_data),
            timeout=timeout,
        )
    except asyncio.TimeoutError as exc:
        raise PathfindError(
            f"sentinel-pathfind timed out after {timeout}s"
        ) from exc
    except OSError as exc:
        raise PathfindError(f"Failed to spawn sentinel-pathfind: {exc}") from exc

    if proc.returncode != 0:
        err_msg = stderr.decode().strip() if stderr else "unknown error"
        raise PathfindError(
            f"sentinel-pathfind exited with code {proc.returncode}: {err_msg}"
        )

    try:
        return json.loads(stdout)  # type: ignore[no-any-return]
    except json.JSONDecodeError as exc:
        raise PathfindError(
            f"Failed to parse sentinel-pathfind output: {exc}"
        ) from exc
