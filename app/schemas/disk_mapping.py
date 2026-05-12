from __future__ import annotations

from pydantic import BaseModel, Field


class DiskTreeRequest(BaseModel):
    root_path: str | None = Field(default=None, max_length=1024)
    max_depth: int = Field(default=2, ge=0, le=5)
    max_nodes: int = Field(default=250, ge=1, le=1000)


class DiskTreeNode(BaseModel):
    name: str
    path: str
    type: str
    size_bytes: int | None = None
    children_count: int | None = None
    is_truncated: bool = False
    children: list[DiskTreeNode] = Field(default_factory=list)


class DiskPartitionInfo(BaseModel):
    device: str
    mountpoint: str
    filesystem: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    percent_used: float
    status: str


class DiskMappingResponse(BaseModel):
    generated_at: str
    allowed_roots: list[str]
    partitions: list[DiskPartitionInfo]
    tree: DiskTreeNode | None = None
    warnings: list[str] = []
