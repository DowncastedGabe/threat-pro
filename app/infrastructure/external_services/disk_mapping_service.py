from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import psutil

from app.core.config.settings import settings


class DiskMappingValidationError(ValueError):
    pass


def get_allowed_roots() -> list[Path]:
    roots: list[Path] = []
    for raw_root in settings.disk_mapping_allowed_roots.split(os.pathsep):
        raw_root = raw_root.strip()
        if not raw_root:
            continue
        root = Path(raw_root).expanduser().resolve()
        if root.exists():
            roots.append(root)
    return roots or [Path.cwd().resolve()]


def collect_disk_mapping(root_path: str | None = None, max_depth: int = 2, max_nodes: int = 250) -> dict:
    warnings: list[str] = []
    allowed_roots = get_allowed_roots()
    tree = None

    if root_path is not None:
        root = _validate_allowed_path(root_path, allowed_roots)
        budget = {"remaining": max_nodes}
        tree = _build_tree(root, current_depth=0, max_depth=max_depth, budget=budget, warnings=warnings)

    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "allowed_roots": [str(root) for root in allowed_roots],
        "partitions": _collect_partitions(warnings),
        "tree": tree,
        "warnings": warnings,
    }


def _collect_partitions(warnings: list[str]) -> list[dict]:
    partitions: list[dict] = []
    seen_mountpoints: set[str] = set()

    for partition in psutil.disk_partitions(all=False):
        if partition.mountpoint in seen_mountpoints:
            continue
        seen_mountpoints.add(partition.mountpoint)

        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except (OSError, PermissionError) as exc:
            warnings.append(f"Nao foi possivel ler uso de disco em {partition.mountpoint}: {exc}")
            continue

        partitions.append(
            {
                "device": partition.device,
                "mountpoint": partition.mountpoint,
                "filesystem": partition.fstype or "unknown",
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "percent_used": usage.percent,
                "status": _usage_status(usage.percent),
            }
        )

    return partitions


def _validate_allowed_path(path: str, allowed_roots: list[Path]) -> Path:
    candidate = Path(path).expanduser().resolve()
    if not candidate.exists():
        raise DiskMappingValidationError("Caminho informado nao existe.")
    if not candidate.is_dir():
        raise DiskMappingValidationError("Mapeamento de arvore aceita apenas diretorios.")

    for root in allowed_roots:
        try:
            candidate.relative_to(root)
            return candidate
        except ValueError:
            continue

    raise DiskMappingValidationError("Caminho fora da allowlist de mapeamento de disco.")


def _build_tree(
    path: Path,
    current_depth: int,
    max_depth: int,
    budget: dict[str, int],
    warnings: list[str],
) -> dict:
    budget["remaining"] -= 1
    node = {
        "name": path.name or str(path),
        "path": str(path),
        "type": "directory",
        "size_bytes": None,
        "children_count": None,
        "is_truncated": False,
        "children": [],
    }

    if budget["remaining"] <= 0:
        node["is_truncated"] = True
        return node

    try:
        entries = sorted(path.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower()))
    except (OSError, PermissionError) as exc:
        warnings.append(f"Sem permissao para ler {path}: {exc}")
        node["is_truncated"] = True
        return node

    node["children_count"] = len(entries)

    if current_depth >= max_depth:
        node["is_truncated"] = len(entries) > 0
        return node

    for entry in entries:
        if budget["remaining"] <= 0:
            node["is_truncated"] = True
            break

        if entry.is_dir():
            node["children"].append(_build_tree(entry, current_depth + 1, max_depth, budget, warnings))
            continue

        budget["remaining"] -= 1
        node["children"].append(
            {
                "name": entry.name,
                "path": str(entry),
                "type": "file",
                "size_bytes": _safe_file_size(entry),
                "children_count": None,
                "is_truncated": False,
                "children": [],
            }
        )

    return node


def _safe_file_size(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except (OSError, PermissionError):
        return None


def _usage_status(percent_used: float) -> str:
    if percent_used >= 90:
        return "critical"
    if percent_used >= 75:
        return "warning"
    return "healthy"
